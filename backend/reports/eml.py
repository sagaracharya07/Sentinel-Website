"""
`.eml` upload handling: validate, store safely, and run the same analysis
pipeline as connected Gmail mail.

Security (Phase 11 / Phase 14):
  - extension + size validation, empty-file rejection
  - filename sanitised (werkzeug secure_filename) -> no path traversal
  - files stored OUTSIDE the public static tree (instance/uploads) and never
    served back to any client
  - the raw message is parsed with the safe MIME parser; attachments are never
    executed and HTML is never rendered
"""

import os
import random
import string
import json
from datetime import datetime, timezone

from werkzeug.utils import secure_filename

from extensions import db
from models import Scan, EmailReport
from ml import infer
from integrations.gmail import parser, analysis

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def max_bytes() -> int:
    try:
        return int(os.environ.get("EML_MAX_BYTES", str(5 * 1024 * 1024)))
    except ValueError:
        return 5 * 1024 * 1024


def upload_dir() -> str:
    return os.environ.get("UPLOAD_DIR") or os.path.join(
        _BACKEND_DIR, "instance", "uploads"
    )


class EmlValidationError(Exception):
    """Raised for any upload that fails validation -- surfaced to the user as
    a 400 with a safe message."""


def _new_scan_id():
    return "SCN-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


def _status_for(label):
    if label == "Phishing":
        return "Quarantined"
    if label == "Needs Review":
        return "Flagged"
    return "Delivered"


def validate_and_read(file_storage) -> tuple[bytes, str]:
    """Validate an uploaded file and return (raw_bytes, safe_filename).
    Reads at most max_bytes+1 to detect oversize without loading unbounded
    data into memory."""
    filename = (file_storage.filename or "").strip()
    if not filename:
        raise EmlValidationError("No file provided")
    if not filename.lower().endswith(".eml"):
        raise EmlValidationError("Only .eml files are accepted")

    safe = secure_filename(filename) or "upload.eml"
    if not safe.lower().endswith(".eml"):
        safe += ".eml"

    cap = max_bytes()
    raw = file_storage.read(cap + 1)
    if not raw:
        raise EmlValidationError("The uploaded file is empty")
    if len(raw) > cap:
        raise EmlValidationError(f"File too large (max {cap // (1024 * 1024)} MB)")

    # Light content sanity: a real RFC822 message has header-ish bytes near the
    # top. We don't hard-require a specific MIME type (browsers report .eml
    # inconsistently), but reject obvious binary junk with no ':' header.
    head = raw[:2048]
    if b":" not in head:
        raise EmlValidationError("File does not look like a valid email message")

    return raw, safe


def store_file(raw: bytes, safe_filename: str) -> str:
    """Persist the raw upload under UPLOAD_DIR with a timestamped unique name.
    Guards against traversal by confirming the resolved path stays inside
    UPLOAD_DIR even though secure_filename already stripped separators."""
    directory = upload_dir()
    os.makedirs(directory, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    unique = f"{stamp}_{safe_filename}"
    path = os.path.join(directory, unique)
    if not os.path.abspath(path).startswith(os.path.abspath(directory) + os.sep):
        raise EmlValidationError("Invalid storage path")
    with open(path, "wb") as fh:
        fh.write(raw)
    return path


def analyze_and_store(user, raw: bytes, safe_filename: str, persist_file: bool = True):
    """Full pipeline: parse -> analyse -> classify -> store Scan + EmailReport.
    Returns (report, scan). The Scan uses source='upload' so uploaded reports
    are cleanly distinguishable from Gmail/manual/IMAP detections."""
    parsed = parser.parse(raw)
    sender = (
        f"{parsed.from_display} <{parsed.from_address}>"
        if parsed.from_display
        else parsed.from_address
    )
    body = parsed.body_for_classifier()

    result = infer.classify(parsed.subject, body, sender)
    security = analysis.analyze_to_dicts(parsed)
    combined = result["findings"] + security

    scan = Scan(
        scan_id=_new_scan_id(),
        sender=sender or "(unknown sender)",
        subject=parsed.subject or "(no subject)",
        body=body,
        classification=result["label"],
        confidence_score=result["phishing_probability"],
        prediction_confidence=result["prediction_confidence"],
        score=result["score"],
        risk_level=result["risk_level"],
        findings_json=json.dumps(combined),
        highlights_json=json.dumps(result["highlights"]),
        status=_status_for(result["label"]),
        model_version=result["model_version"],
        created_by=user.username,
        source="upload",
        mailbox_message_id=parsed.message_id,
        mailbox_action="none",
    )
    db.session.add(scan)

    stored_path = store_file(raw, safe_filename) if persist_file else None
    report = EmailReport(
        reporter_user_id=user.id,
        reporter_username=user.username,
        filename=safe_filename,
        stored_path=stored_path,
        scan_id=scan.scan_id,
        status="pending",
    )
    db.session.add(report)
    db.session.commit()
    return report, scan
