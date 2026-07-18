"""
Google Pub/Sub push webhook for Gmail notifications (optional push mode).

Authentication (two modes, both fail-closed):
  1. PRODUCTION -- OIDC bearer token. When GOOGLE_PUBSUB_AUDIENCE is set, the
     push subscription is configured to send an `Authorization: Bearer <JWT>`
     signed by Google. We verify the JWT's signature, expiry and audience
     (and optionally the service-account email). This is the recommended
     production setup -- no shared secret travels in the URL.
  2. SIMPLE -- shared token in the query string (?token=...), matched against
     GOOGLE_PUBSUB_VERIFICATION_TOKEN. Fine for a demo; weaker (token can
     appear in access logs).
  If neither is configured the endpoint refuses everything.

Robustness:
  - CSRF-exempt (Google, not a browser, calls it) -- applied in app.py
  - never processes messages inline: enqueues the same idempotent, self-locking
    incremental sync the poller runs, then acks immediately
  - duplicate/unordered notifications are safe (the sync re-derives state from
    the stored history id)
"""

import os
import logging

from flask import Blueprint, request

logger = logging.getLogger(__name__)

pubsub_bp = Blueprint("pubsub", __name__)


def _verify_oidc(token: str, audience: str) -> dict:
    """Verify a Google-signed OIDC token. Isolated for testability. Raises on
    any validation failure (bad signature/expiry/audience)."""
    from google.oauth2 import id_token
    from google.auth.transport import requests as ga_requests

    return id_token.verify_oauth2_token(token, ga_requests.Request(), audience=audience)


def _authenticated() -> bool:
    audience = os.environ.get("GOOGLE_PUBSUB_AUDIENCE")
    shared = os.environ.get("GOOGLE_PUBSUB_VERIFICATION_TOKEN")

    if audience:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        token = auth.split(" ", 1)[1].strip()
        try:
            claims = _verify_oidc(token, audience)
        except Exception:
            logger.warning("pubsub_push: OIDC verification failed")
            return False
        expected_sa = os.environ.get("GOOGLE_PUBSUB_SERVICE_ACCOUNT")
        if expected_sa and claims.get("email") != expected_sa:
            return False
        return True

    if shared:
        return request.args.get("token") == shared

    # Neither mode configured -> fail closed.
    return False


@pubsub_bp.post("/api/gmail/pubsub")
def pubsub_push():
    if not _authenticated():
        return "", 403

    # We deliberately don't require or trust the message body -- a notification
    # just means "something changed", and the incremental sync re-derives what
    # from the stored history id. Ack fast, work async.
    try:
        from tasks import gmail_sync_task

        gmail_sync_task.delay()
    except Exception:
        # Never make Pub/Sub retry-storm us because our queue is down; log and
        # ack. The next poll (or notification) catches up.
        logger.warning("pubsub_push: could not enqueue gmail sync", exc_info=False)

    return "", 204
