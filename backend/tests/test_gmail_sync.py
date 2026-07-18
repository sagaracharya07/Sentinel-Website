"""
Gmail incremental sync: classification+storage+labelling, dedup/idempotency,
per-message isolation, History API + bounded fallback, and locking.

The Gmail service is a FakeGmailService (no network); the classifier is a
deterministic stub keyed off the subject line.
"""

from datetime import datetime, timezone

import pytest

from extensions import db
from models import Scan, GmailConnection, GMAIL_STATUS_CONNECTED
from ml import infer
from integrations.gmail import sync, client as client_mod
from tests.gmail_fakes import FakeGmailService, make_message, make_http_error


def fake_classify(subject, body, sender=""):
    s = (subject or "").lower()
    if "boom" in s:
        raise RuntimeError("classifier exploded")
    if "phish" in s:
        label, prob = "Phishing", 0.92
    elif "review" in s:
        label, prob = "Needs Review", 0.60
    else:
        label, prob = "Legitimate", 0.10
    risk = {"Phishing": "High", "Needs Review": "Medium", "Legitimate": "Low"}[label]
    return {
        "label": label,
        "phishing_probability": prob,
        "prediction_confidence": max(prob, 1 - prob),
        "confidence": prob,
        "score": round(prob * 100),
        "risk_level": risk,
        "findings": [],
        "highlights": [],
        "model_version": "test",
    }


@pytest.fixture()
def patched(monkeypatch):
    """Deterministic classifier for every sync test."""
    monkeypatch.setattr(infer, "classify", fake_classify)


def _conn(app, history_id=None):
    with app.app_context():
        c = GmailConnection(
            provider="gmail",
            mailbox_email="ops@corp.example",
            connection_status=GMAIL_STATUS_CONNECTED,
            protection_enabled=True,
        )
        c.set_refresh_token("rt")
        c.last_history_id = history_id
        db.session.add(c)
        db.session.commit()
        return c.id


def _use_service(monkeypatch, svc):
    monkeypatch.setattr(client_mod, "build_service", lambda conn: svc)


# --- happy path --------------------------------------------------------------
def test_first_sync_classifies_stores_and_quarantines(app, patched, monkeypatch):
    cid = _conn(app)
    svc = FakeGmailService(
        messages=[make_message("m1", subject="phish you", labels=["INBOX"])]
    )
    _use_service(monkeypatch, svc)

    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        summary = sync.sync_connection(conn)
        assert summary["scanned"] == 1

        row = Scan.query.filter_by(source="gmail").one()
        assert row.classification == "Phishing"
        assert row.mailbox_action == "quarantined"
        assert row.gmail_message_id == "m1"
        # Real label action applied to the (fake) mailbox.
        assert "INBOX" not in svc.messages_store["m1"]["labelIds"]
        assert conn.quarantine_label_id in svc.messages_store["m1"]["labelIds"]
        # Baseline advanced for future incremental syncs.
        conn = db.session.get(GmailConnection, cid)
        assert conn.last_history_id == svc.profile["historyId"]
        assert conn.last_successful_sync_at is not None


def test_needs_review_labeled_but_kept_in_inbox(app, patched, monkeypatch):
    cid = _conn(app)
    svc = FakeGmailService(
        messages=[make_message("m1", subject="please review", labels=["INBOX"])]
    )
    _use_service(monkeypatch, svc)
    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        sync.sync_connection(conn)
        labels = svc.messages_store["m1"]["labelIds"]
        assert "INBOX" in labels
        assert conn.needs_review_label_id in labels
        assert (
            Scan.query.filter_by(source="gmail").one().mailbox_action == "needs_review"
        )


def test_legitimate_gets_processed_label(app, patched, monkeypatch):
    cid = _conn(app)
    svc = FakeGmailService(
        messages=[make_message("m1", subject="lunch?", labels=["INBOX"])]
    )
    _use_service(monkeypatch, svc)
    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        sync.sync_connection(conn)
        labels = svc.messages_store["m1"]["labelIds"]
        assert "INBOX" in labels
        assert conn.processed_label_id in labels
        assert Scan.query.filter_by(source="gmail").one().mailbox_action == "processed"


# --- idempotency / dedup -----------------------------------------------------
def test_repeat_sync_does_not_duplicate(app, patched, monkeypatch):
    cid = _conn(app)
    svc = FakeGmailService(
        messages=[make_message("m1", subject="phish", labels=["INBOX"])]
    )
    _use_service(monkeypatch, svc)
    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        sync.sync_connection(conn)
        # Force the bounded-list path again (as if no history) -- the same
        # message id is returned but must be deduped, not re-stored.
        conn.last_history_id = None
        db.session.commit()
        summary = sync.sync_connection(conn)
        assert summary["scanned"] == 0
        assert summary["skipped_duplicates"] >= 1
        assert Scan.query.filter_by(source="gmail").count() == 1


def test_duplicate_gmail_scan_blocked_by_unique_index(app):
    cid = _conn(app)
    with app.app_context():
        # Two Scan rows for the same (connection, gmail message id) must be
        # rejected by the partial unique index -- the DB-level dedup backstop.
        db.session.add(
            Scan(
                scan_id="SCN-A",
                source="gmail",
                gmail_connection_id=cid,
                gmail_message_id="dupe",
            )
        )
        db.session.add(
            Scan(
                scan_id="SCN-B",
                source="gmail",
                gmail_connection_id=cid,
                gmail_message_id="dupe",
            )
        )
        with pytest.raises(Exception):
            db.session.commit()
        db.session.rollback()


# --- per-message isolation ---------------------------------------------------
def test_one_failed_retrieve_does_not_stop_batch(app, patched, monkeypatch):
    cid = _conn(app)
    svc = FakeGmailService(
        messages=[
            make_message("bad", subject="phish", labels=["INBOX"]),
            make_message("good", subject="phish", labels=["INBOX"]),
        ]
    )
    svc.get_raises["bad"] = make_http_error(500, "backendError")
    _use_service(monkeypatch, svc)
    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        summary = sync.sync_connection(conn)
        assert summary["failed_retrieve"] == 1
        assert summary["scanned"] == 1
        assert Scan.query.filter_by(gmail_message_id="good").count() == 1


def test_classifier_failure_marks_scan_failed_and_continues(app, patched, monkeypatch):
    cid = _conn(app)
    svc = FakeGmailService(
        messages=[
            make_message("boomer", subject="boom", labels=["INBOX"]),
            make_message("ok", subject="phish", labels=["INBOX"]),
        ]
    )
    _use_service(monkeypatch, svc)
    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        summary = sync.sync_connection(conn)
        assert summary["failed_classification"] == 1
        assert summary["scanned"] == 1
        # Scan Failed label applied to the message that broke the classifier.
        assert conn.scan_failed_label_id in svc.messages_store["boomer"]["labelIds"]


# --- history API + fallback --------------------------------------------------
def test_incremental_sync_uses_history(app, patched, monkeypatch):
    cid = _conn(app, history_id="400")
    svc = FakeGmailService(
        messages=[make_message("h1", subject="phish", labels=["INBOX"])]
    )
    svc.history_store = [
        {"messagesAdded": [{"message": {"id": "h1", "labelIds": ["INBOX"]}}]}
    ]
    _use_service(monkeypatch, svc)
    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        summary = sync.sync_connection(conn)
        assert summary["scanned"] == 1
        assert Scan.query.filter_by(gmail_message_id="h1").count() == 1


def test_expired_history_falls_back_to_bounded_list(app, patched, monkeypatch):
    cid = _conn(app, history_id="stale")
    svc = FakeGmailService(
        messages=[make_message("m1", subject="phish", labels=["INBOX"])]
    )
    svc.history_expired = True
    _use_service(monkeypatch, svc)
    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        summary = sync.sync_connection(conn)
        assert summary["scanned"] == 1  # recovered via bounded list
        conn = db.session.get(GmailConnection, cid)
        assert conn.last_history_id == svc.profile["historyId"]  # re-baselined


# --- locking / gating --------------------------------------------------------
def test_overlapping_sync_is_skipped(app, patched, monkeypatch):
    cid = _conn(app)
    svc = FakeGmailService()
    _use_service(monkeypatch, svc)
    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        conn.sync_in_progress = True
        conn.sync_lock_acquired_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.session.commit()
        summary = sync.sync_connection(conn)
        assert summary["ran"] is False
        assert summary["reason"] == "sync_already_in_progress"


def test_run_active_sync_skips_when_paused(app, patched):
    cid = _conn(app)
    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        conn.protection_enabled = False
        db.session.commit()
        result = sync.run_active_sync()
        assert result["ran"] is False
        assert result["reason"] == "protection_paused_or_not_connected"


def test_run_active_sync_no_connection(app):
    with app.app_context():
        result = sync.run_active_sync()
        assert result["ran"] is False
        assert result["reason"] == "no_active_connection"
