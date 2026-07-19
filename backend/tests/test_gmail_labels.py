"""Gmail label management: create-all, idempotency, duplicate prevention."""

import pytest

from extensions import db
from models import GmailConnection
from integrations.gmail import labels
from tests.gmail_fakes import FakeGmailService


def _conn(app):
    with app.app_context():
        c = GmailConnection(provider="gmail", mailbox_email="ops@corp.example")
        db.session.add(c)
        db.session.commit()
        return c.id


def test_ensure_labels_creates_all_and_caches_ids(app):
    cid = _conn(app)
    svc = FakeGmailService()
    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        ids = labels.ensure_sentinel_labels(svc, conn)
        assert ids["quarantine"] and ids["needs_review"]
        assert ids["processed"] and ids["scan_failed"]
        conn = db.session.get(GmailConnection, cid)
        assert conn.quarantine_label_id == ids["quarantine"]
        # parent + 4 action labels
        assert len(svc.labels_store) == 5


def test_ensure_labels_is_idempotent(app):
    cid = _conn(app)
    svc = FakeGmailService()
    with app.app_context():
        conn = db.session.get(GmailConnection, cid)
        first = labels.ensure_sentinel_labels(svc, conn)
        created_after_first = svc.create_count
        second = labels.ensure_sentinel_labels(svc, conn)
        # Second run creates nothing new and returns the same ids.
        assert svc.create_count == created_after_first
        assert first == second
        assert len(svc.labels_store) == 5


def test_create_label_handles_conflict_race(app):
    # The label already exists but create still reports a conflict (another
    # process created it first) -- create_label must re-read and return it.
    svc = FakeGmailService(
        labels=[{"id": "LBL-existing", "name": "Sentinel/Quarantine"}]
    )
    svc.force_create_conflict = True
    assert labels.create_label(svc, "Sentinel/Quarantine") == "LBL-existing"


def test_find_label_id(app):
    svc = FakeGmailService(labels=[{"id": "LBL-1", "name": "Sentinel/Processed"}])
    assert labels.find_label_id(svc, "Sentinel/Processed") == "LBL-1"
    assert labels.find_label_id(svc, "Nonexistent") is None


def test_create_label_retries_on_aborted_then_succeeds(app, monkeypatch):
    # Gmail's 409 "aborted" means nothing was created -- re-reading (as the
    # 409 "alreadyExists" case does) would find nothing, so this must retry
    # the creation itself. Seen in practice creating several labels in quick
    # succession right after a brand-new OAuth grant.
    monkeypatch.setattr(labels.time, "sleep", lambda *_: None)
    svc = FakeGmailService()
    svc.abort_remaining = 4  # succeeds on the 5th attempt, within the budget of 6
    label_id = labels.create_label(svc, "Sentinel/Quarantine")
    assert label_id
    assert svc.create_count == 5
    assert any(x["name"] == "Sentinel/Quarantine" for x in svc.labels_store)


def test_create_label_gives_up_after_repeated_aborts(app, monkeypatch):
    from integrations.gmail.exceptions import GmailRetryableError

    monkeypatch.setattr(labels.time, "sleep", lambda *_: None)
    svc = FakeGmailService()
    svc.abort_remaining = 20  # never succeeds within the retry budget
    with pytest.raises(GmailRetryableError):
        labels.create_label(svc, "Sentinel/Quarantine")
    assert svc.create_count == 6  # max_attempts, then gives up
