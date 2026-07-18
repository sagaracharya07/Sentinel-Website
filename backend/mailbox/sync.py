"""
Bridges the real IMAP mailbox (mailbox/imap_client.py) with Sentinel's
scanning pipeline and database. This is the function both the background
poller (automatic, continuous) and the admin's manual "Sync now" button
call -- same code path either way, so there's exactly one place that
decides what happens to a real incoming email.
"""

import json
import random
import string
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

from extensions import db
from models import Scan, MailboxStatus
from ml import infer
from mailbox.imap_client import (
    MailboxConfig,
    fetch_new_messages,
    quarantine_message,
    flag_message,
    MailboxError,
)

# A lock held longer than this is assumed abandoned (the process that
# acquired it crashed or was killed without releasing it) and can be
# taken over by the next sync attempt, rather than deadlocking sync
# forever. Real syncs take seconds, not minutes -- 10 minutes is a very
# generous ceiling.
SYNC_LOCK_STALE_AFTER = timedelta(minutes=10)


def new_scan_id():
    return "SCN-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


def status_for(label):
    """Phishing (High risk) -> quarantine. Needs Review (Medium risk) ->
    flag for analyst review, but never silently quarantine or drop it.
    Legitimate -> no action. Mirrors app.py's status_for."""
    if label == "Phishing":
        return "Quarantined"
    if label == "Needs Review":
        return "Flagged"
    return "Delivered"


def get_or_create_status_row():
    row = db.session.get(MailboxStatus, 1)
    if not row:
        row = MailboxStatus(id=1)
        db.session.add(row)
        db.session.commit()
    return row


def _try_acquire_sync_lock():
    """
    Atomic compare-and-set on the MailboxStatus singleton row: only
    succeeds if no sync currently holds the lock (or the lock is stale).
    A DB-backed lock rather than Redis so it works the same whether or
    not Redis is configured (e.g. local dev without it running) -- the
    single UPDATE...WHERE is what makes this race-free even if the
    Celery-Beat-scheduled sync and a manual admin "Sync now" click hit it
    at the same instant: only one UPDATE can match the WHERE clause and
    flip the row, the other gets rowcount 0.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    stale_cutoff = now - SYNC_LOCK_STALE_AFTER
    result = db.session.execute(
        db.update(MailboxStatus)
        .where(MailboxStatus.id == 1)
        .where(
            or_(
                MailboxStatus.sync_in_progress.is_(False),
                MailboxStatus.sync_lock_acquired_at < stale_cutoff,
            )
        )
        .values(sync_in_progress=True, sync_lock_acquired_at=now)
    )
    db.session.commit()
    return result.rowcount > 0


def _release_sync_lock():
    db.session.execute(
        db.update(MailboxStatus)
        .where(MailboxStatus.id == 1)
        .values(sync_in_progress=False)
    )
    db.session.commit()


def sync_mailbox(log_action=None):
    """
    Runs one sync pass against the real mailbox: connect, fetch messages
    not already recorded as scanned (by IMAP UID), classify each with the
    real trained model, persist as Scan rows, and take the corresponding
    real mailbox action (quarantine/flag) for risky mail.

    Idempotent / safe to call repeatedly -- already-scanned UIDs are
    skipped. Concurrency-safe on two levels: _try_acquire_sync_lock()
    stops the background poller and a manual "Sync now" click from
    running at the same time in the first place, and the DB-level unique
    partial index on Scan.mailbox_uid (see models.py) is the backstop
    that guarantees no duplicate Scan row can exist for one UID even if
    that lock is ever bypassed.

    Never raises -- every failure mode is captured into MailboxStatus so
    the admin UI shows real connection health instead of assuming success.
    """
    status_row = get_or_create_status_row()

    if not _try_acquire_sync_lock():
        return {
            "configured": status_row.configured,
            "new_messages": 0,
            "error": None,
            "skipped": "a sync is already in progress",
        }

    try:
        return _do_sync(status_row, log_action)
    finally:
        _release_sync_lock()


def _do_sync(status_row, log_action):
    cfg = MailboxConfig.from_env()

    if not cfg:
        status_row.configured = False
        status_row.connected = False
        status_row.last_error = "Mailbox not configured — set MAILBOX_HOST / MAILBOX_USERNAME / MAILBOX_PASSWORD in backend/.env"
        db.session.commit()
        return {"configured": False, "new_messages": 0, "error": status_row.last_error}

    status_row.configured = True
    status_row.host = cfg.host
    status_row.username = cfg.username
    status_row.inbox_folder = cfg.inbox_folder
    status_row.quarantine_folder = cfg.quarantine_folder
    db.session.commit()

    known_uids = {
        row.mailbox_uid
        for row in Scan.query.filter_by(source="mailbox").all()
        if row.mailbox_uid
    }

    try:
        new_messages, fetch_stats = fetch_new_messages(cfg, known_uids, limit=25)
    except MailboxError as e:
        status_row.connected = False
        status_row.last_error = str(e)
        db.session.commit()
        if log_action:
            log_action("system", "mailbox_sync_failed", details=str(e))
        return {"configured": True, "new_messages": 0, "error": str(e)}

    # Per-batch summary counts (Phase 5) -- fetched/skipped_duplicates/
    # failed_parse come straight from fetch_new_messages(); the rest are
    # built up below as each message is classified/stored/actioned.
    summary = {
        "fetched": fetch_stats["fetched"],
        "scanned": 0,
        "skipped_duplicates": fetch_stats["skipped_duplicates"],
        "failed_parse": fetch_stats["failed_parse"],
        "failed_classification": 0,
        "failed_action": 0,
    }

    for msg in new_messages:
        _process_one_message(msg, cfg, summary, log_action)

    processed = summary["scanned"]
    status_row.connected = True
    status_row.last_error = None
    status_row.last_sync_at = datetime.now(timezone.utc).replace(tzinfo=None)
    status_row.last_new_messages = processed
    status_row.total_synced = (status_row.total_synced or 0) + processed
    db.session.commit()

    if log_action and processed:
        log_action(
            "system",
            "mailbox_sync",
            details=f"{processed} new message(s) scanned from live mailbox",
        )

    return {"configured": True, "new_messages": processed, "error": None, **summary}


def _process_one_message(msg, cfg, summary, log_action):
    """
    Handles exactly one already-fetched message: classify, store, apply
    the mailbox action. Never lets one message's failure stop the batch
    -- every step below is its own try/except that increments a summary
    counter and moves on, rather than letting an exception propagate out
    to sync_mailbox's caller. Only the message UID/Message-ID are ever
    logged, never the body or mailbox credentials.
    """
    uid = msg.get("uid")

    try:
        result = infer.classify(msg["subject"], msg["body"], msg["sender"])
    except Exception as e:
        summary["failed_classification"] += 1
        if log_action:
            log_action(
                "system",
                "mailbox_sync_classification_failed",
                details=f"uid={uid}: {e}",
            )
        return

    status = status_for(result["label"])
    scan = Scan(
        scan_id=new_scan_id(),
        sender=msg["sender"] or "(unknown sender)",
        subject=msg["subject"] or "(no subject)",
        body=msg["body"],
        classification=result["label"],
        confidence_score=result["phishing_probability"],
        prediction_confidence=result["prediction_confidence"],
        score=result["score"],
        risk_level=result["risk_level"],
        findings_json=json.dumps(result["findings"]),
        highlights_json=json.dumps(result["highlights"]),
        status=status,
        model_version=result["model_version"],
        created_by="mailbox-sync",
        source="mailbox",
        mailbox_uid=msg["uid"],
        mailbox_message_id=msg["message_id"],
        mailbox_action="none",
    )

    # Take the real action in the real mailbox -- this is the part that
    # makes "quarantine" mean something more than a UI label.
    try:
        if status == "Quarantined":
            quarantine_message(cfg, msg["uid"])
            scan.mailbox_action = "quarantined"
        elif status == "Flagged":
            flag_message(cfg, msg["uid"])
            scan.mailbox_action = "flagged"
    except MailboxError as e:
        # Classification still gets recorded even if the mailbox action
        # failed (e.g. transient network issue) -- we never lose the
        # detection, we just surface that the action didn't apply so an
        # admin can retry it manually.
        scan.mailbox_action_error = str(e)
        summary["failed_action"] += 1
        if log_action:
            log_action(
                "system",
                "mailbox_sync_action_failed",
                details=f"uid={uid} message_id={msg.get('message_id')}: {e}",
            )

    # Committed per-message (not batched into one commit at the end) so
    # that one duplicate-UID IntegrityError -- the backstop unique index
    # catching a race the lock should already prevent -- only loses that
    # one message instead of rolling back the whole batch.
    db.session.add(scan)
    try:
        db.session.commit()
        summary["scanned"] += 1
    except IntegrityError:
        db.session.rollback()
        summary["skipped_duplicates"] += 1
