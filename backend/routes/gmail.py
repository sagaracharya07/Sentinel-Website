"""
Gmail connection routes (admin-only).

Thin HTTP layer over integrations/gmail: it owns OAuth *state* (stored in
the Flask session, validated on callback to stop connection-CSRF), the
GmailConnection database row, and the audit trail. All Google-protocol
work is delegated to integrations.gmail.oauth.

Security posture:
  - every route is @admin_required (mailbox management is admin-only)
  - the callback validates the OAuth state against the session value, so a
    forged callback from an attacker's browser can't attach a mailbox to
    the victim's account
  - tokens are never returned to the browser, put in a redirect URL, or logged
"""

import os
import secrets
import logging
from datetime import timezone

from flask import Blueprint, request, jsonify, session, redirect

from extensions import db, limiter
from auth import admin_required, current_actor, log_action
from models import (
    User,
    GmailConnection,
    GMAIL_STATUS_CONNECTED,
    GMAIL_STATUS_PAUSED,
)
from integrations.gmail import oauth, client, labels, messages, sync, watch
from integrations.gmail.exceptions import GmailConfigError, GmailOAuthError, GmailError

logger = logging.getLogger(__name__)

gmail_bp = Blueprint("gmail", __name__)

_STATE_SESSION_KEY = "gmail_oauth_state"
# Where the OAuth callback sends the browser once it's done (a real page,
# never a JSON blob). Query params tell the page what happened.
_RESULT_PAGE = "/mailboxes.html"


def _default_monitoring_mode() -> str:
    mode = (os.environ.get("GMAIL_MONITORING_MODE") or "polling").strip().lower()
    return mode if mode in ("polling", "push") else "polling"


def _naive_utc(dt):
    """Store datetimes naive-UTC to match the rest of the schema (models.py
    stores naive UTC everywhere)."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


@gmail_bp.get("/api/admin/gmail/authorize-url")
@admin_required
@limiter.limit("20 per hour")
def authorize_url():
    """Start the connect flow: mint a fresh OAuth state, stash it in the
    session, and hand back the Google consent URL for the browser to
    navigate to. GET (not POST) because it's read-only and the browser
    navigates to the returned URL -- CSRF isn't a concern for producing a
    URL, and the state generated here is what protects the callback."""
    if not oauth.is_configured():
        return jsonify(
            {
                "configured": False,
                "error": "Google OAuth is not configured on the server "
                "(GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / "
                "GOOGLE_OAUTH_REDIRECT_URI). See backend/.env.example.",
            }
        ), 400
    state = secrets.token_urlsafe(32)
    session[_STATE_SESSION_KEY] = state
    try:
        url = oauth.authorization_url(state)
    except GmailConfigError as e:
        return jsonify({"configured": False, "error": str(e)}), 400
    return jsonify({"configured": True, "authorization_url": url})


# Reconnect is, for a fresh consent, identical to starting a connection:
# force Google's consent screen again (oauth.authorization_url already sets
# prompt=consent) so a new refresh token is issued.
@gmail_bp.post("/api/admin/gmail/reconnect")
@admin_required
@limiter.limit("20 per hour")
def reconnect():
    if not oauth.is_configured():
        return jsonify(
            {"configured": False, "error": "Google OAuth is not configured."}
        ), 400
    state = secrets.token_urlsafe(32)
    session[_STATE_SESSION_KEY] = state
    log_action(current_actor(), "gmail_reconnect_started")
    return jsonify(
        {"configured": True, "authorization_url": oauth.authorization_url(state)}
    )


@gmail_bp.get("/api/admin/gmail/callback")
@admin_required
def callback():
    """Google redirects the browser here after consent. Validate state,
    exchange the code, identify the account, and persist the connection.
    Always ends in a redirect to a real page with a status query param --
    never leaks tokens or renders raw errors."""
    expected_state = session.pop(_STATE_SESSION_KEY, None)

    # User cancelled or Google returned an error.
    error = request.args.get("error")
    if error:
        log_action(current_actor(), "gmail_connect_denied", details=error)
        return redirect(f"{_RESULT_PAGE}?error={error}")

    state = request.args.get("state")
    code = request.args.get("code")
    if not expected_state or not state or state != expected_state:
        log_action(current_actor(), "gmail_connect_state_mismatch")
        return redirect(f"{_RESULT_PAGE}?error=state_mismatch")
    if not code:
        return redirect(f"{_RESULT_PAGE}?error=missing_code")

    try:
        credentials = oauth.exchange_code(code, state)
        info = oauth.fetch_userinfo(credentials)
    except GmailOAuthError as e:
        # str(e) is a library-level message, safe (no tokens); keep it out
        # of the redirect URL regardless and only log it.
        logger.warning("Gmail OAuth callback failed: %s", e)
        log_action(current_actor(), "gmail_connect_failed", details=str(e)[:200])
        return redirect(f"{_RESULT_PAGE}?error=oauth_failed")

    storage = oauth.credentials_to_storage(credentials)
    email = info["email"]

    # Enforce one active connection per deployment: retire any other active
    # mailbox before attaching this one.
    active = GmailConnection.active()
    if active and active.mailbox_email != email:
        active.mark_disconnected()
        log_action(
            current_actor(),
            "gmail_disconnect",
            target=active.mailbox_email,
            details="auto-disconnected: replaced by a newly connected mailbox",
        )

    # Reuse a prior row for the same mailbox (keeps its history) or create one.
    conn = (
        GmailConnection.query.filter_by(mailbox_email=email)
        .order_by(GmailConnection.id.desc())
        .first()
    )
    if conn is None:
        conn = GmailConnection(provider="gmail", mailbox_email=email)
        db.session.add(conn)

    owner = User.query.filter_by(username=session.get("username")).first()
    conn.owner_user_id = owner.id if owner else None
    conn.provider_account_id = info.get("sub")

    # prompt=consent should always yield a refresh token; if for some reason
    # it didn't and we have no prior one, we can't maintain access -- fail
    # loudly rather than store a connection that silently can't refresh.
    if storage["refresh_token"]:
        conn.set_refresh_token(storage["refresh_token"])
    elif not conn.encrypted_refresh_token:
        log_action(current_actor(), "gmail_connect_no_refresh_token", target=email)
        return redirect(f"{_RESULT_PAGE}?error=no_refresh_token")

    conn.set_access_token(storage["access_token"])
    conn.token_expiry = _naive_utc(storage["token_expiry"])
    conn.granted_scopes = storage["scopes"]
    conn.connection_status = GMAIL_STATUS_CONNECTED
    conn.protection_enabled = True
    conn.monitoring_mode = conn.monitoring_mode or _default_monitoring_mode()
    conn.disconnected_at = None
    conn.last_error_code = None
    conn.last_error_message = None
    db.session.commit()

    log_action(current_actor(), "gmail_connect", target=email)
    return redirect(f"{_RESULT_PAGE}?connected=1")


@gmail_bp.get("/api/admin/gmail/status")
@admin_required
def status():
    conn = GmailConnection.active()
    return jsonify(
        {
            "oauth_configured": oauth.is_configured(),
            "connection": conn.to_dict() if conn else None,
        }
    )


@gmail_bp.post("/api/admin/gmail/disconnect")
@admin_required
def disconnect():
    conn = GmailConnection.active()
    if not conn:
        return jsonify({"error": "No connected mailbox"}), 404
    email = conn.mailbox_email
    conn.mark_disconnected()
    db.session.commit()
    log_action(current_actor(), "gmail_disconnect", target=email)
    return jsonify({"ok": True, "connection": conn.to_dict()})


@gmail_bp.post("/api/admin/gmail/pause")
@admin_required
def pause():
    conn = GmailConnection.active()
    if not conn:
        return jsonify({"error": "No connected mailbox"}), 404
    conn.protection_enabled = False
    conn.connection_status = GMAIL_STATUS_PAUSED
    db.session.commit()
    log_action(current_actor(), "gmail_pause", target=conn.mailbox_email)
    return jsonify({"ok": True, "connection": conn.to_dict()})


@gmail_bp.post("/api/admin/gmail/resume")
@admin_required
def resume():
    # active() never returns a disconnected connection, so "resume after
    # disconnect" surfaces here as "no active mailbox" (404) -- reconnect,
    # don't resume.
    conn = GmailConnection.active()
    if not conn:
        return jsonify({"error": "No connected mailbox"}), 404
    conn.protection_enabled = True
    conn.connection_status = GMAIL_STATUS_CONNECTED
    db.session.commit()
    log_action(current_actor(), "gmail_resume", target=conn.mailbox_email)
    return jsonify({"ok": True, "connection": conn.to_dict()})


@gmail_bp.post("/api/admin/gmail/test")
@admin_required
@limiter.limit("30 per hour")
def test_connection():
    """Verify the stored credentials still work: refresh the token, fetch the
    Gmail profile, and ensure Sentinel's labels exist. Returns a safe summary
    -- never a token or a raw stack trace."""
    conn = GmailConnection.active()
    if not conn:
        return jsonify({"ok": False, "error": "No connected mailbox"}), 404
    try:
        service = client.build_service(conn)
        profile = messages.get_profile(service)
        labels.ensure_sentinel_labels(service, conn)
    except GmailError as e:
        conn.last_error_code = type(e).__name__
        conn.last_error_message = str(e)[:300]
        db.session.commit()
        log_action(
            current_actor(),
            "gmail_test_failed",
            target=conn.mailbox_email,
            details=type(e).__name__,
        )
        return jsonify({"ok": False, "error": _safe_error(e)}), 200
    log_action(current_actor(), "gmail_test", target=conn.mailbox_email)
    return jsonify(
        {
            "ok": True,
            "email": profile.get("emailAddress"),
            "messages_total": profile.get("messagesTotal"),
            "labels_ready": conn.to_dict()["labels_ready"],
        }
    )


@gmail_bp.post("/api/admin/gmail/scan-now")
@admin_required
@limiter.limit("30 per hour")
def scan_now():
    """Run one sync pass immediately (same code path as the Celery poller)."""
    conn = GmailConnection.active()
    if not conn:
        return jsonify({"error": "No connected mailbox"}), 404
    result = sync.sync_connection(conn, log_action=log_action)
    return jsonify(result)


@gmail_bp.post("/api/admin/gmail/watch/start")
@admin_required
def watch_start():
    """Enable Gmail push mode (requires GOOGLE_PUBSUB_TOPIC + a configured
    Pub/Sub topic granting Gmail publish rights). Polling remains the fallback
    if the watch lapses."""
    if not watch.is_push_configured():
        return jsonify(
            {"error": "Push mode is not configured (set GOOGLE_PUBSUB_TOPIC)."}
        ), 400
    conn = GmailConnection.active()
    if not conn:
        return jsonify({"error": "No connected mailbox"}), 404
    try:
        service = client.build_service(conn)
        resp = watch.start_watch(service, conn)
    except GmailError as e:
        return jsonify({"ok": False, "error": _safe_error(e)}), 200
    log_action(current_actor(), "gmail_watch_start", target=conn.mailbox_email)
    return jsonify(
        {"ok": True, "monitoring_mode": "push", "expiration": resp.get("expiration")}
    )


@gmail_bp.post("/api/admin/gmail/watch/stop")
@admin_required
def watch_stop():
    """Disable push mode and fall back to polling."""
    conn = GmailConnection.active()
    if not conn:
        return jsonify({"error": "No connected mailbox"}), 404
    try:
        service = client.build_service(conn)
        watch.stop_watch(service, conn)
    except GmailError as e:
        return jsonify({"ok": False, "error": _safe_error(e)}), 200
    log_action(current_actor(), "gmail_watch_stop", target=conn.mailbox_email)
    return jsonify({"ok": True, "monitoring_mode": "polling"})


def _safe_error(e: GmailError) -> str:
    """A short, admin-safe message per error class -- no tokens, no internals."""
    from integrations.gmail.exceptions import GmailAuthError, GmailConfigError

    if isinstance(e, GmailAuthError):
        return "Gmail access is no longer valid. Reconnect the mailbox."
    if isinstance(e, GmailConfigError):
        return "Google OAuth is not configured on the server."
    return "Could not reach Gmail. Please try again."
