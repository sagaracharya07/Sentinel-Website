"""
Optional Gmail push notifications (users.watch + Google Pub/Sub).

Push is strictly optional: polling (integrations/gmail/sync.py) is the
default and works with zero external infrastructure. Push only activates when
GOOGLE_PUBSUB_TOPIC is configured AND an administrator enables it. A Gmail
watch expires after 7 days, so it must be renewed; renew_active_watch() (run
from a Celery Beat task) re-arms it before expiry.

This module never processes messages itself -- a Pub/Sub notification only
triggers the same incremental sync the poller runs, so the two monitoring
modes converge on identical behaviour.
"""

import os
import logging
from datetime import datetime, timedelta, timezone

from extensions import db
from models import GmailConnection
from . import client
from .exceptions import GmailError

logger = logging.getLogger(__name__)

WATCH_RENEW_WITHIN = timedelta(days=1)


def is_push_configured() -> bool:
    return bool(os.environ.get("GOOGLE_PUBSUB_TOPIC"))


def _epoch_ms_to_naive_utc(ms):
    if not ms:
        return None
    return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).replace(tzinfo=None)


def start_watch(service, conn) -> dict:
    """Arm a Gmail watch on INBOX targeting the configured Pub/Sub topic.
    Records the returned historyId (baseline for incremental sync) and the
    watch expiration on the connection."""
    topic = os.environ.get("GOOGLE_PUBSUB_TOPIC")
    if not topic:
        raise GmailError("GOOGLE_PUBSUB_TOPIC is not configured")
    body = {
        "topicName": topic,
        "labelIds": ["INBOX"],
        "labelFilterBehavior": "include",
    }
    resp = client.execute(service.users().watch(userId="me", body=body))
    if resp.get("historyId"):
        conn.last_history_id = str(resp["historyId"])
    conn.last_watch_expiration = _epoch_ms_to_naive_utc(resp.get("expiration"))
    conn.monitoring_mode = "push"
    db.session.commit()
    return resp


def stop_watch(service, conn) -> None:
    """Stop Gmail push for this mailbox and revert to polling."""
    try:
        client.execute(service.users().stop(userId="me"))
    finally:
        conn.last_watch_expiration = None
        conn.monitoring_mode = "polling"
        db.session.commit()


def needs_renewal(conn, within: timedelta = WATCH_RENEW_WITHIN) -> bool:
    if conn.monitoring_mode != "push":
        return False
    if not conn.last_watch_expiration:
        return True
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return conn.last_watch_expiration - now <= within


def renew_active_watch() -> dict:
    """Re-arm the active connection's watch if it's in push mode and near
    expiry. Called from the Celery Beat renewal task. No-op (safe) when push
    isn't configured or no mailbox uses it."""
    if not is_push_configured():
        return {"renewed": False, "reason": "push_not_configured"}
    conn = GmailConnection.active()
    if not conn or conn.monitoring_mode != "push":
        return {"renewed": False, "reason": "no_push_connection"}
    if not needs_renewal(conn):
        return {"renewed": False, "reason": "not_due"}
    try:
        service = client.build_service(conn)
        resp = start_watch(service, conn)
    except GmailError as e:
        conn.last_error_code = type(e).__name__
        conn.last_error_message = str(e)[:300]
        db.session.commit()
        return {"renewed": False, "reason": type(e).__name__}
    return {"renewed": True, "expiration": resp.get("expiration")}
