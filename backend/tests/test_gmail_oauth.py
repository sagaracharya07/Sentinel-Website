"""
Gmail OAuth route tests -- admin-only access, state validation, token
non-exposure, connection lifecycle, single-active-connection rule, audit.

No network and no real Google account: integrations.gmail.oauth functions
are monkeypatched. routes/gmail.py references them via the shared
`integrations.gmail.oauth` module object, so patching that module's
attributes patches what the route calls.
"""

from types import SimpleNamespace
from datetime import datetime


from models import GmailConnection, AuditLog, GMAIL_STATUS_DISCONNECTED
from integrations.gmail import oauth as oauth_mod
from integrations.gmail.exceptions import GmailOAuthError


def _fake_creds(refresh="refresh-token-xyz", token="access-token-xyz"):
    return SimpleNamespace(
        refresh_token=refresh,
        token=token,
        expiry=datetime(2030, 1, 1, 0, 0, 0),
        scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/gmail.modify",
        ],
    )


def _set_state(client, state):
    with client.session_transaction() as sess:
        sess["gmail_oauth_state"] = state


def _patch_success(monkeypatch, email="ops@corp.example", refresh="refresh-token-xyz"):
    monkeypatch.setattr(
        oauth_mod, "exchange_code", lambda code, state: _fake_creds(refresh)
    )
    monkeypatch.setattr(
        oauth_mod,
        "fetch_userinfo",
        lambda creds: {"email": email, "sub": "google-sub-1", "email_verified": True},
    )


# ---------------------------------------------------------------------------
# authorize-url (start)
# ---------------------------------------------------------------------------
def test_authorize_url_requires_login(client):
    assert client.get("/api/admin/gmail/authorize-url").status_code == 401


def test_authorize_url_requires_admin(user_client):
    assert user_client.get("/api/admin/gmail/authorize-url").status_code == 403


def test_authorize_url_returns_url_and_stores_state(admin_client, monkeypatch):
    monkeypatch.setattr(oauth_mod, "is_configured", lambda: True)
    monkeypatch.setattr(
        oauth_mod,
        "authorization_url",
        lambda state: f"https://accounts.google.com/o/oauth2/auth?state={state}",
    )
    resp = admin_client.get("/api/admin/gmail/authorize-url")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["configured"] is True
    assert body["authorization_url"].startswith("https://accounts.google.com/")
    with admin_client.session_transaction() as sess:
        assert sess.get("gmail_oauth_state")  # a state was stored


def test_authorize_url_when_oauth_not_configured(admin_client, monkeypatch):
    monkeypatch.setattr(oauth_mod, "is_configured", lambda: False)
    resp = admin_client.get("/api/admin/gmail/authorize-url")
    assert resp.status_code == 400
    assert resp.get_json()["configured"] is False


# ---------------------------------------------------------------------------
# callback
# ---------------------------------------------------------------------------
def test_callback_valid_state_creates_connection(admin_client, app, monkeypatch):
    _patch_success(monkeypatch, email="inbox@corp.example")
    _set_state(admin_client, "STATE-OK")

    resp = admin_client.get("/api/admin/gmail/callback?state=STATE-OK&code=authcode")
    assert resp.status_code == 302
    assert "connected=1" in resp.headers["Location"]
    # No token ever appears in the redirect URL.
    assert "refresh-token-xyz" not in resp.headers["Location"]

    with app.app_context():
        conn = GmailConnection.active()
        assert conn is not None
        assert conn.mailbox_email == "inbox@corp.example"
        assert conn.provider_account_id == "google-sub-1"
        assert conn.get_refresh_token() == "refresh-token-xyz"  # stored + decryptable
        assert conn.protection_enabled is True


def test_callback_creates_audit_entry(admin_client, app, monkeypatch):
    _patch_success(monkeypatch, email="audit@corp.example")
    _set_state(admin_client, "S1")
    admin_client.get("/api/admin/gmail/callback?state=S1&code=c")
    with app.app_context():
        assert (
            AuditLog.query.filter_by(
                action="gmail_connect", target="audit@corp.example"
            ).count()
            == 1
        )


def test_callback_rejects_state_mismatch(admin_client, app, monkeypatch):
    _patch_success(monkeypatch)
    _set_state(admin_client, "EXPECTED")
    resp = admin_client.get("/api/admin/gmail/callback?state=FORGED&code=c")
    assert resp.status_code == 302
    assert "error=state_mismatch" in resp.headers["Location"]
    with app.app_context():
        assert GmailConnection.query.count() == 0


def test_callback_rejects_missing_state(admin_client, app, monkeypatch):
    _patch_success(monkeypatch)
    # No state placed in session.
    resp = admin_client.get("/api/admin/gmail/callback?state=whatever&code=c")
    assert resp.status_code == 302
    assert "error=state_mismatch" in resp.headers["Location"]
    with app.app_context():
        assert GmailConnection.query.count() == 0


def test_callback_handles_consent_denied(admin_client, app):
    resp = admin_client.get("/api/admin/gmail/callback?error=access_denied")
    assert resp.status_code == 302
    assert "error=access_denied" in resp.headers["Location"]
    with app.app_context():
        assert GmailConnection.query.count() == 0


def test_callback_handles_exchange_failure(admin_client, app, monkeypatch):
    def boom(code, state):
        raise GmailOAuthError("bad code")

    monkeypatch.setattr(oauth_mod, "exchange_code", boom)
    _set_state(admin_client, "S")
    resp = admin_client.get("/api/admin/gmail/callback?state=S&code=c")
    assert resp.status_code == 302
    assert "error=oauth_failed" in resp.headers["Location"]
    # The library error message must not leak into the redirect URL.
    assert "bad code" not in resp.headers["Location"]
    with app.app_context():
        assert GmailConnection.query.count() == 0


def test_callback_no_refresh_token_is_rejected(admin_client, app, monkeypatch):
    _patch_success(monkeypatch, refresh=None)
    _set_state(admin_client, "S")
    resp = admin_client.get("/api/admin/gmail/callback?state=S&code=c")
    assert resp.status_code == 302
    assert "error=no_refresh_token" in resp.headers["Location"]


def test_callback_requires_admin(user_client):
    # A logged-in non-admin can't complete a callback either.
    assert (
        user_client.get("/api/admin/gmail/callback?error=access_denied").status_code
        == 403
    )


# ---------------------------------------------------------------------------
# status / token non-exposure
# ---------------------------------------------------------------------------
def test_status_requires_admin(user_client):
    assert user_client.get("/api/admin/gmail/status").status_code == 403


def test_status_never_exposes_tokens(admin_client, app, monkeypatch):
    _patch_success(monkeypatch, email="secret@corp.example")
    _set_state(admin_client, "S")
    admin_client.get("/api/admin/gmail/callback?state=S&code=c")

    resp = admin_client.get("/api/admin/gmail/status")
    assert resp.status_code == 200
    raw = resp.get_data(as_text=True)
    assert "refresh-token-xyz" not in raw
    assert "access-token-xyz" not in raw
    assert "encrypted" not in raw.lower()
    conn = resp.get_json()["connection"]
    assert conn["mailbox_email"] == "secret@corp.example"
    assert "refresh_token" not in conn and "encrypted_refresh_token" not in conn


# ---------------------------------------------------------------------------
# lifecycle: pause / resume / disconnect / reconnect
# ---------------------------------------------------------------------------
def _connect(admin_client, monkeypatch, email="lifecycle@corp.example"):
    _patch_success(monkeypatch, email=email)
    _set_state(admin_client, "S")
    admin_client.get("/api/admin/gmail/callback?state=S&code=c")


def test_pause_and_resume(admin_client, app, monkeypatch):
    _connect(admin_client, monkeypatch)

    r = admin_client.post("/api/admin/gmail/pause")
    assert r.status_code == 200
    assert r.get_json()["connection"]["protection_enabled"] is False
    assert r.get_json()["connection"]["connection_status"] == "paused"

    r = admin_client.post("/api/admin/gmail/resume")
    assert r.status_code == 200
    assert r.get_json()["connection"]["protection_enabled"] is True
    assert r.get_json()["connection"]["connection_status"] == "connected"


def test_disconnect_clears_credentials(admin_client, app, monkeypatch):
    _connect(admin_client, monkeypatch)
    r = admin_client.post("/api/admin/gmail/disconnect")
    assert r.status_code == 200
    with app.app_context():
        conn = GmailConnection.query.first()
        assert conn.connection_status == GMAIL_STATUS_DISCONNECTED
        assert conn.encrypted_refresh_token is None
        assert GmailConnection.active() is None


def test_disconnect_requires_admin(user_client):
    assert user_client.post("/api/admin/gmail/disconnect").status_code == 403


def test_resume_after_disconnect_has_no_active_mailbox(admin_client, app, monkeypatch):
    # Once disconnected there's no active connection, so resume can't act on
    # it -- the correct answer is "no connected mailbox" (reconnect instead).
    _connect(admin_client, monkeypatch)
    admin_client.post("/api/admin/gmail/disconnect")
    r = admin_client.post("/api/admin/gmail/resume")
    assert r.status_code == 404


def test_reconnect_returns_authorization_url(admin_client, monkeypatch):
    monkeypatch.setattr(oauth_mod, "is_configured", lambda: True)
    monkeypatch.setattr(
        oauth_mod, "authorization_url", lambda state: "https://accounts.google.com/x"
    )
    r = admin_client.post("/api/admin/gmail/reconnect")
    assert r.status_code == 200
    assert r.get_json()["authorization_url"].startswith("https://accounts.google.com/")


def test_scan_now_requires_admin(user_client):
    assert user_client.post("/api/admin/gmail/scan-now").status_code == 403


def test_scan_now_without_connection_is_404(admin_client):
    assert admin_client.post("/api/admin/gmail/scan-now").status_code == 404


def test_test_connection_requires_admin(user_client):
    assert user_client.post("/api/admin/gmail/test").status_code == 403


def test_test_connection_success(admin_client, app, monkeypatch):
    from tests.gmail_fakes import FakeGmailService
    from integrations.gmail import client as client_mod

    _connect(admin_client, monkeypatch, email="tester@corp.example")
    svc = FakeGmailService(
        profile={
            "emailAddress": "tester@corp.example",
            "messagesTotal": 7,
            "historyId": "9",
        }
    )
    monkeypatch.setattr(client_mod, "build_service", lambda conn: svc)

    r = admin_client.post("/api/admin/gmail/test")
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True
    assert body["email"] == "tester@corp.example"
    assert body["messages_total"] == 7
    assert body["labels_ready"] is True
    # A test must never leak a token in its response.
    assert "refresh-token-xyz" not in r.get_data(as_text=True)


def test_test_connection_auth_failure_is_safe(admin_client, app, monkeypatch):
    from integrations.gmail import client as client_mod
    from integrations.gmail.exceptions import GmailAuthError

    _connect(admin_client, monkeypatch, email="tester@corp.example")

    def boom(conn):
        raise GmailAuthError("invalid_grant details")

    monkeypatch.setattr(client_mod, "build_service", boom)
    r = admin_client.post("/api/admin/gmail/test")
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is False
    assert "Reconnect" in body["error"]
    assert "invalid_grant details" not in r.get_data(
        as_text=True
    )  # internals not leaked


def test_only_one_active_connection(admin_client, app, monkeypatch):
    # Connect account A, then account B: A must be auto-disconnected.
    _connect(admin_client, monkeypatch, email="first@corp.example")
    _connect(admin_client, monkeypatch, email="second@corp.example")
    with app.app_context():
        active = GmailConnection.active()
        assert active.mailbox_email == "second@corp.example"
        first = GmailConnection.query.filter_by(
            mailbox_email="first@corp.example"
        ).first()
        assert first.connection_status == GMAIL_STATUS_DISCONNECTED
