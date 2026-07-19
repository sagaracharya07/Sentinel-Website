"""
Authenticated Gmail API client construction, token refresh, and error
classification.

Everything that touches the network funnels through here so the rest of the
integration (labels.py, messages.py, sync.py) can stay declarative and be
tested against a fake service object. Two responsibilities:

1. Turn a stored GmailConnection (encrypted refresh token) into a live,
   auto-refreshing Gmail service -- persisting a refreshed access token back
   to the DB (re-encrypted) so the next sync doesn't refresh again needlessly.
2. Classify Gmail/HTTP errors into retryable vs permanent vs auth-lost, so
   Celery tasks decide retry-vs-give-up from the exception type, never from
   string matching.
"""

import os
import logging
from datetime import timezone

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from extensions import db
from models import GMAIL_STATUS_REVOKED
from .oauth import SCOPES, _TOKEN_URI
from .exceptions import (
    GmailAuthError,
    GmailConfigError,
    GmailRetryableError,
    GmailPermanentError,
    GmailNotFoundError,
    GmailHistoryExpiredError,
)

logger = logging.getLogger(__name__)


def _naive_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def build_credentials(conn) -> Credentials:
    """Reconstruct google credentials from a stored connection. Decrypting the
    refresh token happens here (conn.get_refresh_token); a decryption failure
    surfaces as the crypto module's TokenDecryptionError, which the caller
    treats as 'reconnect required'."""
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    if not (client_id and client_secret):
        raise GmailConfigError(
            "GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are required to refresh "
            "Gmail credentials."
        )
    refresh_token = conn.get_refresh_token()
    if not refresh_token:
        raise GmailAuthError("No refresh token stored -- reconnect the mailbox.")
    scopes = conn.granted_scopes.split() if conn.granted_scopes else SCOPES
    return Credentials(
        token=conn.get_access_token(),
        refresh_token=refresh_token,
        token_uri=_TOKEN_URI,
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes,
        expiry=conn.token_expiry,  # naive UTC, matches how it's stored
    )


def _persist_refreshed(conn, credentials):
    """Save a freshly-refreshed access token back to the connection so the
    next call reuses it instead of refreshing again. Refresh tokens don't
    change here, so only the access token + expiry are updated."""
    conn.set_access_token(credentials.token)
    conn.token_expiry = _naive_utc(credentials.expiry)
    db.session.commit()


def ensure_valid(conn, credentials):
    """Refresh the access token if it's missing/expired, and persist it.
    Raises GmailAuthError (and marks the connection revoked) if Google
    rejects the refresh -- e.g. the user revoked access, or invalid_grant."""
    if credentials.valid:
        return credentials
    try:
        credentials.refresh(Request())
    except RefreshError as e:
        conn.connection_status = GMAIL_STATUS_REVOKED
        conn.protection_enabled = False
        conn.last_error_code = "invalid_grant"
        conn.last_error_message = "Gmail access was revoked or the grant is no longer valid -- reconnect the mailbox."
        db.session.commit()
        raise GmailAuthError(str(e)) from e
    _persist_refreshed(conn, credentials)
    return credentials


def build_service(conn):
    """A ready-to-use Gmail API service for this connection, with a valid
    (refreshed if needed) access token. static_discovery=True builds from the
    library's bundled discovery document -- no network fetch, which keeps this
    testable and avoids a startup dependency on the discovery endpoint."""
    credentials = build_credentials(conn)
    ensure_valid(conn, credentials)
    return build("gmail", "v1", credentials=credentials, static_discovery=True)


# ---------------------------------------------------------------------------
# error classification
# ---------------------------------------------------------------------------
def _status_of(error: HttpError):
    resp = getattr(error, "resp", None)
    if resp is not None and getattr(resp, "status", None) is not None:
        return int(resp.status)
    return getattr(error, "status_code", None)


def _reason_of(error: HttpError) -> str:
    # HttpError stores the raw JSON body in error.content (bytes).
    try:
        import json

        body = json.loads(error.content.decode("utf-8"))
        errors = body.get("error", {}).get("errors", [])
        if errors:
            return errors[0].get("reason", "")
    except Exception:
        pass
    return ""


def classify_http_error(error: HttpError) -> Exception:
    """Map a googleapiclient HttpError to one of our typed exceptions."""
    status = _status_of(error)
    reason = _reason_of(error)

    if status == 401:
        return GmailAuthError("Gmail rejected the access token (401).")
    if status == 403 and reason in ("rateLimitExceeded", "userRateLimitExceeded"):
        return GmailRetryableError("Gmail rate limit hit (403).")
    if status == 429:
        return GmailRetryableError("Gmail rate limit hit (429).")
    if status == 409 and reason == "aborted":
        # Distinct from a 409 "alreadyExists" conflict (a genuine permanent
        # state, handled by callers re-reading and reusing what's there --
        # see labels.py's create_label). "aborted" is Gmail's own signal
        # that a concurrent/rapid modification should be retried; nothing
        # was actually created, so treating it as permanent would make the
        # caller give up on a label that was never made. Seen in practice
        # creating several Sentinel labels in quick succession right after
        # a brand-new OAuth grant.
        return GmailRetryableError("Gmail request aborted, safe to retry (409).")
    if status is not None and 500 <= status < 600:
        return GmailRetryableError(f"Gmail transient server error ({status}).")
    if status == 404:
        return GmailNotFoundError("Gmail resource not found (404).")
    return GmailPermanentError(f"Gmail API error ({status}): {reason or 'unknown'}")


def execute(request, *, history: bool = False):
    """Run a googleapiclient request, translating failures into typed errors.
    `history=True` upgrades a 404 into GmailHistoryExpiredError so the sync
    can fall back to a bounded list instead of treating it as a hard failure.
    """
    try:
        return request.execute()
    except HttpError as e:
        classified = classify_http_error(e)
        if history and isinstance(classified, GmailNotFoundError):
            raise GmailHistoryExpiredError(str(classified)) from e
        raise classified from e
    except (GmailRetryableError, GmailPermanentError, GmailAuthError):
        raise
    except Exception as e:  # transport/DNS/socket -- worth a retry
        raise GmailRetryableError(f"Gmail request failed: {e}") from e
