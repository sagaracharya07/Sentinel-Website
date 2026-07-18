"""
Google Pub/Sub push webhook for Gmail notifications (optional push mode).

Security & robustness:
  - authenticated by a shared verification token in the query string
    (?token=...), matched against GOOGLE_PUBSUB_VERIFICATION_TOKEN; if that
    env var is unset the endpoint refuses all requests (fail closed)
  - CSRF-exempt (Google, not a browser, calls it) -- exemption is applied in
    app.py via csrf.exempt(pubsub_bp)
  - does NOT process messages inline: it only enqueues the same idempotent
    incremental sync the poller runs, then acks immediately, so a burst of
    notifications can't block or duplicate work
  - unrecognised/duplicate notifications are safe: the sync is idempotent
    and self-locking
"""

import os
import logging

from flask import Blueprint, request

logger = logging.getLogger(__name__)

pubsub_bp = Blueprint("pubsub", __name__)


@pubsub_bp.post("/api/gmail/pubsub")
def pubsub_push():
    expected = os.environ.get("GOOGLE_PUBSUB_VERIFICATION_TOKEN")
    # Fail closed: without a configured token we can't authenticate Google's
    # push, so we refuse rather than accept unauthenticated triggers.
    if not expected or request.args.get("token") != expected:
        return "", 403

    # We deliberately don't trust or require the message body -- a
    # notification just means "something changed", and the incremental sync
    # re-derives exactly what from the stored history id. Ack fast, work async.
    try:
        from tasks import gmail_sync_task

        gmail_sync_task.delay()
    except Exception:
        # Never make Pub/Sub retry forever because our queue is down; log and
        # ack. The next poll (or the next notification) will catch up.
        logger.warning("pubsub_push: could not enqueue gmail sync", exc_info=False)

    return "", 204
