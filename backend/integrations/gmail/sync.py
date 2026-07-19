"""
Incremental Gmail sync: the one code path both Celery Beat (automatic) and
the admin "Scan now" button use, so there's exactly one place that decides
what happens to a real incoming Gmail message.

Flow per pass:
    acquire per-connection DB lock  (stops overlapping syncs)
        build service (refresh token if needed)
        ensure Sentinel labels exist
        find new message ids:
            history id present -> Gmail History API (incremental)
            none / expired     -> bounded recent list, then baseline
        dedup against already-stored Gmail message ids
        for each new message (isolated):
            retrieve -> extract -> classify -> store -> label action
        advance last_history_id, update sync timestamps
    release lock

Design guarantees carried over from the IMAP sync:
  - never raises: every failure is captured onto the connection/summary
  - one message's failure never aborts the batch (per-message try/except)
  - idempotent: already-stored messages are skipped, and the partial unique
    index (source='gmail') is the DB-level backstop against duplicates
  - concurrency-safe: DB compare-and-set lock, stale-lock takeover
  - tokens / message bodies are never logged
"""

import os
import json
import base64
import random
import string
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

from extensions import db
from models import Scan, GmailConnection, GMAIL_STATUS_CONNECTED
from ml import infer
from . import client, labels, messages, parser, analysis
from .exceptions import (
    GmailError,
    GmailAuthError,
    GmailConfigError,
    GmailHistoryExpiredError,
)

logger = logging.getLogger(__name__)

SYNC_LOCK_STALE_AFTER = timedelta(minutes=10)


def _max_messages() -> int:
    try:
        return int(os.environ.get("GMAIL_MAX_MESSAGES_PER_SYNC", "100"))
    except ValueError:
        return 100


def _initial_lookback_days() -> int:
    try:
        return int(os.environ.get("GMAIL_INITIAL_LOOKBACK_DAYS", "1"))
    except ValueError:
        return 1


def _new_scan_id():
    return "SCN-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


def _decode_raw(raw_b64url: str) -> bytes:
    """Decode Gmail's base64url 'raw' field into RFC822 bytes. Tolerant of
    missing padding (Gmail strips it)."""
    if not raw_b64url:
        return b""
    padding = "=" * (-len(raw_b64url) % 4)
    return base64.urlsafe_b64decode(raw_b64url + padding)


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def action_for(label: str) -> str:
    """Operational mailbox action for a classification label (Gmail label ops).
    Legitimate -> Processed marker; Needs Review -> Needs Review label (stays
    in inbox); Phishing -> Quarantine (INBOX removed)."""
    if label == "Phishing":
        return "quarantined"
    if label == "Needs Review":
        return "needs_review"
    return "processed"


# ---------------------------------------------------------------------------
# per-connection DB lock (compare-and-set on the GmailConnection row)
# ---------------------------------------------------------------------------
def _try_acquire_lock(conn) -> bool:
    now = _now()
    stale_cutoff = now - SYNC_LOCK_STALE_AFTER
    result = db.session.execute(
        db.update(GmailConnection)
        .where(GmailConnection.id == conn.id)
        .where(
            or_(
                GmailConnection.sync_in_progress.is_(False),
                GmailConnection.sync_lock_acquired_at < stale_cutoff,
            )
        )
        .values(sync_in_progress=True, sync_lock_acquired_at=now)
    )
    db.session.commit()
    return result.rowcount > 0


def _release_lock(conn):
    db.session.execute(
        db.update(GmailConnection)
        .where(GmailConnection.id == conn.id)
        .values(sync_in_progress=False)
    )
    db.session.commit()


# ---------------------------------------------------------------------------
# public entry points
# ---------------------------------------------------------------------------
def run_active_sync(log_action=None) -> dict:
    """Sync the single active connection if it exists and protection is on.
    This is what the Celery task and 'Scan now' call."""
    conn = GmailConnection.active()
    if not conn:
        return {"ran": False, "reason": "no_active_connection"}
    if not conn.protection_enabled or conn.connection_status != GMAIL_STATUS_CONNECTED:
        return {"ran": False, "reason": "protection_paused_or_not_connected"}
    return sync_connection(conn, log_action=log_action)


def sync_connection(conn, log_action=None) -> dict:
    """Run one sync pass against a specific connection. Never raises."""
    if not _try_acquire_lock(conn):
        return {"ran": False, "reason": "sync_already_in_progress"}
    try:
        return _do_sync(conn, log_action)
    finally:
        _release_lock(conn)


def _do_sync(conn, log_action) -> dict:
    conn.last_attempted_sync_at = _now()
    db.session.commit()

    summary = {
        "ran": True,
        "new_messages": 0,
        "scanned": 0,
        "skipped_duplicates": 0,
        "failed_retrieve": 0,
        "failed_classification": 0,
        "failed_action": 0,
        "error": None,
    }

    try:
        service = client.build_service(conn)
        labels.ensure_sentinel_labels(service, conn)
        profile = messages.get_profile(service)
    except (GmailAuthError, GmailConfigError) as e:
        conn.last_error_code = type(e).__name__
        conn.last_error_message = str(e)
        db.session.commit()
        if log_action:
            log_action("system", "gmail_sync_failed", details=type(e).__name__)
        summary["error"] = type(e).__name__
        return summary
    except GmailError as e:
        conn.last_error_code = type(e).__name__
        conn.last_error_message = str(e)
        db.session.commit()
        if log_action:
            log_action("system", "gmail_sync_failed", details=type(e).__name__)
        summary["error"] = type(e).__name__
        return summary

    # Determine the set of new message ids.
    new_ids, latest_history_id = _discover_new_messages(service, conn, profile)

    # Dedup against what's already stored for this connection.
    known = {
        row.gmail_message_id
        for row in Scan.query.filter_by(
            gmail_connection_id=conn.id, source="gmail"
        ).all()
        if row.gmail_message_id
    }
    to_process = [mid for mid in new_ids if mid not in known]
    summary["new_messages"] = len(to_process)
    summary["skipped_duplicates"] += len(new_ids) - len(to_process)

    for mid in to_process:
        _process_one(service, conn, mid, summary, log_action)

    conn.last_history_id = latest_history_id or conn.last_history_id
    conn.last_successful_sync_at = _now()
    conn.last_error_code = None
    conn.last_error_message = None
    db.session.commit()

    if log_action and summary["scanned"]:
        log_action(
            "system",
            "gmail_sync",
            target=conn.mailbox_email,
            details=f"{summary['scanned']} new message(s) scanned",
        )
    return summary


def _discover_new_messages(service, conn, profile):
    """Return (message_ids, latest_history_id). Uses the History API when a
    baseline exists, falling back to a bounded recent list on first sync or
    when the stored history id has expired."""
    profile_history_id = profile.get("historyId")

    if conn.last_history_id:
        try:
            added, latest = messages.list_history(
                service, conn.last_history_id, max_results=_max_messages()
            )
            return added[: _max_messages()], latest
        except GmailHistoryExpiredError:
            logger.info(
                "Gmail history id expired for connection %s; falling back to list",
                conn.id,
            )
            # fall through to bounded list, re-baseline below

    # First sync or expired history: scan a bounded recent window, then
    # baseline to the current history id so subsequent syncs are incremental.
    query = f"in:inbox newer_than:{_initial_lookback_days()}d"
    listed = messages.list_message_ids(
        service, max_results=_max_messages(), query=query
    )
    ids = [m["id"] for m in listed]
    return ids, profile_history_id


def _process_one(service, conn, message_id, summary, log_action):
    """Handle exactly one message. Every step is isolated so a single bad
    message can't abort the batch. Only ids are ever logged -- never bodies."""
    # Retrieve the raw RFC822 and parse the full MIME structure.
    try:
        raw_msg = messages.get_raw(service, message_id)
        raw_bytes = _decode_raw(raw_msg.get("raw", ""))
        parsed = parser.parse(raw_bytes)
    except GmailError as e:
        summary["failed_retrieve"] += 1
        if log_action:
            log_action(
                "system",
                "gmail_retrieve_failed",
                details=f"id={message_id}: {type(e).__name__}",
            )
        return

    sender = (
        f"{parsed.from_display} <{parsed.from_address}>"
        if parsed.from_display
        else parsed.from_address
    )
    body = parsed.body_for_classifier()

    # Classify (falls back to Scan Failed label on classifier error).
    try:
        result = infer.classify(parsed.subject, body, sender)
    except Exception as e:
        summary["failed_classification"] += 1
        _safe_label(service, conn, message_id, "scan_failed")
        if log_action:
            log_action(
                "system", "gmail_classify_failed", details=f"id={message_id}: {e}"
            )
        return

    # Structured email-security findings, merged with the ML explainability
    # findings. Analysis never changes the ML probability -- it only adds
    # explainable signals alongside it (see analysis.py / Phase 7).
    security_findings = analysis.analyze_to_dicts(parsed)
    combined_findings = result["findings"] + security_findings

    action = action_for(result["label"])
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
        findings_json=json.dumps(combined_findings),
        highlights_json=json.dumps(result["highlights"]),
        status=_status_for(result["label"]),
        model_version=result["model_version"],
        created_by="gmail-sync",
        source="gmail",
        gmail_connection_id=conn.id,
        gmail_message_id=raw_msg.get("id"),
        gmail_thread_id=raw_msg.get("threadId"),
        gmail_history_id=raw_msg.get("historyId"),
        mailbox_message_id=parsed.message_id,
        mailbox_action="none",
    )

    # Real Gmail label action.
    try:
        if action == "quarantined":
            messages.quarantine(service, message_id, conn)
        elif action == "needs_review":
            messages.mark_needs_review(service, message_id, conn)
        else:
            messages.mark_processed(service, message_id, conn)
        scan.mailbox_action = action
    except GmailError as e:
        scan.mailbox_action_error = f"{type(e).__name__}: {e}"
        summary["failed_action"] += 1
        if log_action:
            log_action(
                "system",
                "gmail_action_failed",
                details=f"id={message_id}: {type(e).__name__}",
            )

    # Commit per-message so one duplicate IntegrityError (the unique-index
    # backstop catching a race the lock should prevent) only loses that one.
    db.session.add(scan)
    try:
        db.session.commit()
        summary["scanned"] += 1
    except IntegrityError:
        db.session.rollback()
        summary["skipped_duplicates"] += 1


def _status_for(label):
    if label == "Phishing":
        return "Quarantined"
    if label == "Needs Review":
        return "Flagged"
    return "Delivered"


def _safe_label(service, conn, message_id, which):
    """Best-effort labelling that never raises (used on the failure path)."""
    try:
        if which == "scan_failed":
            messages.mark_scan_failed(service, message_id, conn)
    except GmailError:
        pass
