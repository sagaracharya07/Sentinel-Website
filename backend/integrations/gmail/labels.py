"""
Gmail label management: discover or create Sentinel's labels once per
connection, and cache their ids on the GmailConnection so message actions
(quarantine/release) reference ids, not names.

Sentinel's labels (nested under a single "Sentinel" parent so they group
tidily in the Gmail sidebar):
    Sentinel/Processed      -- optional marker on classified-legitimate mail
    Sentinel/Needs Review   -- medium-risk, left in inbox for an analyst
    Sentinel/Quarantine     -- high-risk, INBOX removed (never deleted)
    Sentinel/Scan Failed    -- processing error, left in inbox

Duplicate-label prevention: labels are matched by name before creating, and
a create that races another (409) falls back to re-reading the list, so we
never create two labels with the same name.
"""

import logging

from . import client

logger = logging.getLogger(__name__)

PARENT_LABEL = "Sentinel"
PROCESSED_LABEL = "Sentinel/Processed"
NEEDS_REVIEW_LABEL = "Sentinel/Needs Review"
QUARANTINE_LABEL = "Sentinel/Quarantine"
SCAN_FAILED_LABEL = "Sentinel/Scan Failed"

# Order matters: create the parent first so the children nest under it.
_REQUIRED_LABELS = [
    PARENT_LABEL,
    PROCESSED_LABEL,
    NEEDS_REVIEW_LABEL,
    QUARANTINE_LABEL,
    SCAN_FAILED_LABEL,
]


def list_labels(service) -> list[dict]:
    """All labels in the mailbox as [{id, name, ...}]."""
    resp = client.execute(service.users().labels().list(userId="me"))
    return resp.get("labels", [])


def _name_to_id(service) -> dict:
    return {lbl["name"]: lbl["id"] for lbl in list_labels(service)}


def find_label_id(service, name: str):
    return _name_to_id(service).get(name)


def create_label(service, name: str) -> str:
    """Create one label, returning its id. Idempotent against a concurrent
    create: if the API rejects it as already-existing, we re-read and return
    the existing id rather than failing."""
    body = {
        "name": name,
        "labelListVisibility": "labelShow",
        "messageListVisibility": "show",
    }
    try:
        created = client.execute(
            service.users().labels().create(userId="me", body=body)
        )
        return created["id"]
    except client.GmailPermanentError:
        # Most likely a 409 "label exists" race -- re-read and use it.
        existing = find_label_id(service, name)
        if existing:
            return existing
        raise


def ensure_sentinel_labels(service, conn) -> dict:
    """Ensure all Sentinel labels exist, caching their ids on the connection.
    Safe to call repeatedly -- existing labels are reused, never duplicated.
    Returns {name: id} for the four action labels."""
    existing = _name_to_id(service)
    ids = {}
    for name in _REQUIRED_LABELS:
        ids[name] = existing.get(name) or create_label(service, name)

    conn.processed_label_id = ids[PROCESSED_LABEL]
    conn.needs_review_label_id = ids[NEEDS_REVIEW_LABEL]
    conn.quarantine_label_id = ids[QUARANTINE_LABEL]
    conn.scan_failed_label_id = ids[SCAN_FAILED_LABEL]

    from extensions import db

    db.session.commit()
    return {
        "processed": conn.processed_label_id,
        "needs_review": conn.needs_review_label_id,
        "quarantine": conn.quarantine_label_id,
        "scan_failed": conn.scan_failed_label_id,
    }
