"""Gmail push watch: start/stop, renewal logic, config gating."""

from datetime import datetime, timedelta, timezone

from extensions import db
from models import GmailConnection, GMAIL_STATUS_CONNECTED
from integrations.gmail import watch, client as client_mod
from tests.gmail_fakes import FakeGmailService


def _conn(app, mode="polling", expiry=None):
    with app.app_context():
        c = GmailConnection(
            provider="gmail",
            mailbox_email="ops@corp.example",
            connection_status=GMAIL_STATUS_CONNECTED,
            protection_enabled=True,
            monitoring_mode=mode,
            last_watch_expiration=expiry,
        )
        c.set_refresh_token("rt")
        db.session.add(c)
        db.session.commit()
        return c.id


def test_start_watch_records_history_and_expiration(app, monkeypatch):
    monkeypatch.setenv("GOOGLE_PUBSUB_TOPIC", "projects/p/topics/t")
    cid = _conn(app)
    svc = FakeGmailService()
    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        resp = watch.start_watch(svc, conn)
        assert resp["historyId"] == svc.profile["historyId"]
        conn = db.session.get(GmailConnection, cid)
        assert conn.monitoring_mode == "push"
        assert conn.last_watch_expiration is not None
        assert conn.last_history_id == str(svc.profile["historyId"])
        assert svc.watch_calls  # watch() was actually called


def test_stop_watch_reverts_to_polling(app):
    cid = _conn(app, mode="push", expiry=datetime(2030, 1, 1))
    svc = FakeGmailService()
    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        watch.stop_watch(svc, conn)
        conn = db.session.get(GmailConnection, cid)
        assert conn.monitoring_mode == "polling"
        assert conn.last_watch_expiration is None
        assert svc.stop_calls == 1


def test_needs_renewal_true_when_expiring_soon(app):
    soon = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=2)
    cid = _conn(app, mode="push", expiry=soon)
    with app.app_context():
        assert watch.needs_renewal(db.session.get(GmailConnection, cid)) is True


def test_needs_renewal_false_when_far_out(app):
    far = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=5)
    cid = _conn(app, mode="push", expiry=far)
    with app.app_context():
        assert watch.needs_renewal(db.session.get(GmailConnection, cid)) is False


def test_needs_renewal_false_for_polling_mode(app):
    cid = _conn(app, mode="polling")
    with app.app_context():
        assert watch.needs_renewal(db.session.get(GmailConnection, cid)) is False


def test_renew_active_watch_noop_when_push_not_configured(app, monkeypatch):
    monkeypatch.delenv("GOOGLE_PUBSUB_TOPIC", raising=False)
    _conn(app, mode="push")
    with app.app_context():
        result = watch.renew_active_watch()
        assert result["renewed"] is False
        assert result["reason"] == "push_not_configured"


def test_renew_active_watch_rearms_when_due(app, monkeypatch):
    monkeypatch.setenv("GOOGLE_PUBSUB_TOPIC", "projects/p/topics/t")
    soon = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)
    _conn(app, mode="push", expiry=soon)
    svc = FakeGmailService()
    monkeypatch.setattr(client_mod, "build_service", lambda conn: svc)
    with app.app_context():
        result = watch.renew_active_watch()
        assert result["renewed"] is True
        assert svc.watch_calls
