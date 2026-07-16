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
from datetime import datetime, timezone

from extensions import db
from models import Scan, MailboxStatus
from ml import infer
from mailbox.imap_client import MailboxConfig, fetch_new_messages, quarantine_message, flag_message, MailboxError


def new_scan_id():
    return "SCN-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


def status_for(label, risk_level):
    if label == "Phishing":
        return "Quarantined" if risk_level == "High" else "Flagged"
    return "Delivered"


def get_or_create_status_row():
    row = db.session.get(MailboxStatus, 1)
    if not row:
        row = MailboxStatus(id=1)
        db.session.add(row)
        db.session.commit()
    return row


def sync_mailbox(log_action=None):
    """
    Runs one sync pass against the real mailbox: connect, fetch messages
    not already recorded as scanned (by IMAP UID), classify each with the
    real trained model, persist as Scan rows, and take the corresponding
    real mailbox action (quarantine/flag) for risky mail.

    Idempotent / safe to call repeatedly -- already-scanned UIDs are
    skipped, so the background poller and a manual "Sync now" click can
    never double-process the same message.

    Never raises -- every failure mode is captured into MailboxStatus so
    the admin UI shows real connection health instead of assuming success.
    """
    status_row = get_or_create_status_row()
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

    known_uids = {
        row.mailbox_uid for row in Scan.query.filter_by(source="mailbox").all() if row.mailbox_uid
    }

    try:
        new_messages = fetch_new_messages(cfg, known_uids, limit=25)
    except MailboxError as e:
        status_row.connected = False
        status_row.last_error = str(e)
        db.session.commit()
        if log_action:
            log_action("system", "mailbox_sync_failed", details=str(e))
        return {"configured": True, "new_messages": 0, "error": str(e)}

    processed = 0
    for msg in new_messages:
        result = infer.classify(msg["subject"], msg["body"], msg["sender"])
        status = status_for(result["label"], result["risk_level"])

        scan = Scan(
            scan_id=new_scan_id(),
            sender=msg["sender"] or "(unknown sender)",
            subject=msg["subject"] or "(no subject)",
            body=msg["body"],
            classification=result["label"],
            confidence_score=result["confidence"],
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

        # Take the real action in the real mailbox -- this is the part
        # that makes "quarantine" mean something more than a UI label.
        try:
            if status == "Quarantined":
                quarantine_message(cfg, msg["uid"])
                scan.mailbox_action = "quarantined"
            elif status == "Flagged":
                flag_message(cfg, msg["uid"])
                scan.mailbox_action = "flagged"
        except MailboxError as e:
            # Classification still gets recorded even if the mailbox
            # action failed (e.g. transient network issue) -- we never
            # lose the detection, we just surface that the action didn't
            # apply so an admin can retry it manually.
            scan.mailbox_action_error = str(e)

        db.session.add(scan)
        processed += 1

    status_row.connected = True
    status_row.last_error = None
    status_row.last_sync_at = datetime.now(timezone.utc).replace(tzinfo=None)
    status_row.last_new_messages = processed
    status_row.total_synced = (status_row.total_synced or 0) + processed
    db.session.commit()

    if log_action and processed:
        log_action("system", "mailbox_sync", details=f"{processed} new message(s) scanned from live mailbox")

    return {"configured": True, "new_messages": processed, "error": None}
