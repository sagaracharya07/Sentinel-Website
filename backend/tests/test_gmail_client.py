"""Gmail client: token refresh + persistence, revoked handling, error mapping."""

from datetime import datetime

import pytest

from extensions import db
from models import GmailConnection, GMAIL_STATUS_CONNECTED, GMAIL_STATUS_REVOKED
from integrations.gmail import client
from integrations.gmail.exceptions import (
    GmailAuthError,
    GmailConfigError,
    GmailRetryableError,
    GmailPermanentError,
    GmailNotFoundError,
    GmailHistoryExpiredError,
)
from tests.gmail_fakes import make_http_error


class FakeCreds:
    def __init__(self, valid=False, token="old-token", raise_refresh=False):
        self._valid = valid
        self.token = token
        self.expiry = None
        self.refresh_token = "rt"
        self._raise = raise_refresh

    @property
    def valid(self):
        return self._valid

    def refresh(self, request):
        if self._raise:
            from google.auth.exceptions import RefreshError

            raise RefreshError("invalid_grant")
        self.token = "new-token"
        self.expiry = datetime(2030, 1, 1)
        self._valid = True


class DummyReq:
    def __init__(self, exc):
        self._exc = exc

    def execute(self):
        raise self._exc


def _conn(app, refresh="rt-value"):
    with app.app_context():
        c = GmailConnection(
            provider="gmail",
            mailbox_email="ops@corp.example",
            connection_status=GMAIL_STATUS_CONNECTED,
        )
        if refresh:
            c.set_refresh_token(refresh)
        c.set_access_token("old-access")
        db.session.add(c)
        db.session.commit()
        return c.id


# --- token refresh -----------------------------------------------------------
def test_ensure_valid_refreshes_and_persists(app):
    cid = _conn(app)
    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        creds = FakeCreds(valid=False)
        client.ensure_valid(conn, creds)
        conn = db.session.get(GmailConnection, cid)
        assert conn.get_access_token() == "new-token"  # persisted, re-encrypted
        assert conn.token_expiry is not None


def test_ensure_valid_noop_when_already_valid(app):
    cid = _conn(app)
    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        creds = FakeCreds(valid=True, token="still-good")
        client.ensure_valid(conn, creds)
        # No refresh happened, so nothing was re-persisted from the creds.
        assert creds.token == "still-good"


def test_ensure_valid_marks_revoked_on_refresh_error(app):
    cid = _conn(app)
    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        creds = FakeCreds(valid=False, raise_refresh=True)
        with pytest.raises(GmailAuthError):
            client.ensure_valid(conn, creds)
        conn = db.session.get(GmailConnection, cid)
        assert conn.connection_status == GMAIL_STATUS_REVOKED
        assert conn.protection_enabled is False
        assert conn.last_error_code == "invalid_grant"


def test_build_credentials_requires_refresh_token(app, monkeypatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "cid")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "secret")
    cid = _conn(app, refresh=None)
    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        with pytest.raises(GmailAuthError):
            client.build_credentials(conn)


def test_build_credentials_requires_client_config(app, monkeypatch):
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_CLIENT_SECRET", raising=False)
    cid = _conn(app)
    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        with pytest.raises(GmailConfigError):
            client.build_credentials(conn)


# --- error classification ----------------------------------------------------
@pytest.mark.parametrize(
    "status,reason,expected",
    [
        (401, "", GmailAuthError),
        (403, "rateLimitExceeded", GmailRetryableError),
        (403, "userRateLimitExceeded", GmailRetryableError),
        (403, "insufficientPermissions", GmailPermanentError),
        (429, "", GmailRetryableError),
        (409, "aborted", GmailRetryableError),
        (409, "alreadyExists", GmailPermanentError),
        (500, "", GmailRetryableError),
        (503, "", GmailRetryableError),
        (404, "notFound", GmailNotFoundError),
        (400, "badRequest", GmailPermanentError),
    ],
)
def test_classify_http_error(status, reason, expected):
    err = make_http_error(status, reason)
    assert isinstance(client.classify_http_error(err), expected)


def test_execute_wraps_http_error():
    with pytest.raises(GmailPermanentError):
        client.execute(DummyReq(make_http_error(400, "badRequest")))


def test_execute_history_404_becomes_history_expired():
    with pytest.raises(GmailHistoryExpiredError):
        client.execute(DummyReq(make_http_error(404, "notFound")), history=True)


def test_execute_transport_error_is_retryable():
    with pytest.raises(GmailRetryableError):
        client.execute(DummyReq(ConnectionError("socket died")))
