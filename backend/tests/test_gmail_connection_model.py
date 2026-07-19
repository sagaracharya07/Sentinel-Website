"""GmailConnection model: token storage, state transitions, single-active rule."""

from datetime import datetime, timezone

from extensions import db
from models import (
    GmailConnection,
    GMAIL_STATUS_CONNECTED,
    GMAIL_STATUS_PAUSED,
    GMAIL_STATUS_DISCONNECTED,
)


def _make(app, email="ops@example.com", status=GMAIL_STATUS_CONNECTED):
    with app.app_context():
        c = GmailConnection(
            provider="gmail", mailbox_email=email, connection_status=status
        )
        c.set_refresh_token("refresh-token-123")
        c.set_access_token("access-token-abc")
        c.token_expiry = datetime.now(timezone.utc).replace(tzinfo=None)
        db.session.add(c)
        db.session.commit()
        return c.id


def test_tokens_stored_encrypted_not_plaintext(app):
    cid = _make(app)
    with app.app_context():
        c = db.session.get(GmailConnection, cid)
        assert c.encrypted_refresh_token
        assert "refresh-token-123" not in c.encrypted_refresh_token
        assert c.get_refresh_token() == "refresh-token-123"
        assert c.get_access_token() == "access-token-abc"


def test_to_dict_never_exposes_tokens(app):
    cid = _make(app)
    with app.app_context():
        c = db.session.get(GmailConnection, cid)
        d = c.to_dict()
        blob = str(d).lower()
        assert "token" not in blob
        assert "refresh-token-123" not in str(d)
        assert "access-token-abc" not in str(d)
        assert d["mailbox_email"] == "ops@example.com"


def test_to_dict_exposes_sync_lock_state(app):
    # Not a secret, and needed so a stuck Test Connection/Scan Now can
    # actually be diagnosed from the admin console instead of guessed at.
    cid = _make(app)
    with app.app_context():
        c = db.session.get(GmailConnection, cid)
        d = c.to_dict()
        assert d["sync_in_progress"] is False
        assert d["sync_lock_acquired_at"] is None

        c.sync_in_progress = True
        c.sync_lock_acquired_at = datetime(2026, 1, 1, tzinfo=timezone.utc).replace(
            tzinfo=None
        )
        db.session.commit()
        d2 = c.to_dict()
        assert d2["sync_in_progress"] is True
        assert d2["sync_lock_acquired_at"] is not None


def test_active_returns_only_non_disconnected(app):
    _make(app, email="a@example.com", status=GMAIL_STATUS_CONNECTED)
    with app.app_context():
        assert GmailConnection.active() is not None
        assert GmailConnection.active().mailbox_email == "a@example.com"


def test_disconnected_connection_is_not_active(app):
    cid = _make(app, status=GMAIL_STATUS_CONNECTED)
    with app.app_context():
        c = db.session.get(GmailConnection, cid)
        c.mark_disconnected()
        db.session.commit()
        assert GmailConnection.active() is None


def test_mark_disconnected_clears_credentials(app):
    cid = _make(app)
    with app.app_context():
        c = db.session.get(GmailConnection, cid)
        c.mark_disconnected()
        db.session.commit()
        c = db.session.get(GmailConnection, cid)
        assert c.connection_status == GMAIL_STATUS_DISCONNECTED
        assert c.protection_enabled is False
        assert c.encrypted_refresh_token is None
        assert c.encrypted_access_token is None
        assert c.get_refresh_token() is None
        assert c.disconnected_at is not None


def test_paused_connection_still_counts_as_active(app):
    _make(app, status=GMAIL_STATUS_PAUSED)
    with app.app_context():
        # paused != disconnected: the mailbox is still connected, just not
        # auto-scanning, so it must remain the active connection.
        assert GmailConnection.active() is not None
        assert GmailConnection.active().connection_status == GMAIL_STATUS_PAUSED
