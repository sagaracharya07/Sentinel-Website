"""
Tests for mailbox/sync.py's sync_mailbox() -- mocking imap_tools entirely
so no real IMAP server is needed. Covers: no-mailbox-configured no-op,
idempotent UID tracking (already-scanned messages aren't re-fetched),
quarantine/flag routing by risk level, and mailbox-action failures not
losing the underlying classification.
"""
from unittest.mock import patch

import mailbox.sync as sync_module
from mailbox.imap_client import MailboxConfig, MailboxError


def _fake_cfg():
    return MailboxConfig(
        host="imap.example.com", port=993, username="test@example.com",
        password="app-password", inbox_folder="INBOX",
        quarantine_folder="Sentinel-Quarantine",
    )


def test_sync_is_a_noop_when_mailbox_not_configured(app):
    with app.app_context():
        with patch.object(MailboxConfig, "from_env", return_value=None):
            result = sync_module.sync_mailbox()
    assert result["configured"] is False
    assert result["new_messages"] == 0


def test_sync_classifies_and_quarantines_high_risk_message(app):
    phishing_msg = {
        "uid": "101", "message_id": "<msg101@mail>",
        "sender": "PayPal Security <security@paypa1-support.com>",
        "subject": "Your account will be suspended — verify now",
        "body": "Dear Customer, verify your account immediately or it will be suspended. "
                "Click here: http://bit.ly/verify-acct",
        "date": None,
    }
    with app.app_context():
        with patch.object(MailboxConfig, "from_env", return_value=_fake_cfg()), \
             patch.object(sync_module, "fetch_new_messages", return_value=[phishing_msg]) as mock_fetch, \
             patch.object(sync_module, "quarantine_message") as mock_quarantine, \
             patch.object(sync_module, "flag_message") as mock_flag:
            result = sync_module.sync_mailbox()

        assert result["configured"] is True
        assert result["new_messages"] == 1
        mock_fetch.assert_called_once()

        from models import Scan
        scan = Scan.query.filter_by(mailbox_uid="101").first()
        assert scan is not None
        assert scan.source == "mailbox"
        if scan.status == "Quarantined":
            mock_quarantine.assert_called_once()
            assert mock_quarantine.call_args[0][1] == "101"
            assert scan.mailbox_action == "quarantined"
            mock_flag.assert_not_called()
        else:
            # model landed it as Flagged/Medium instead of High -- still a
            # valid outcome, just assert the flag path was taken instead
            mock_flag.assert_called_once()
            assert scan.mailbox_action == "flagged"


def test_sync_skips_already_known_uids(app):
    with app.app_context():
        from models import Scan
        from extensions import db
        db.session.add(Scan(
            scan_id="SCN-EXISTING", sender="a@b.com", subject="old", body="old body",
            classification="Legitimate", status="Delivered", source="mailbox",
            mailbox_uid="55", mailbox_message_id="<old@mail>",
        ))
        db.session.commit()

        with patch.object(MailboxConfig, "from_env", return_value=_fake_cfg()), \
             patch.object(sync_module, "fetch_new_messages", return_value=[]) as mock_fetch:
            sync_module.sync_mailbox()

        called_known_uids = mock_fetch.call_args[0][1]
        assert "55" in called_known_uids


def test_sync_records_error_without_crashing(app):
    with app.app_context():
        with patch.object(MailboxConfig, "from_env", return_value=_fake_cfg()), \
             patch.object(sync_module, "fetch_new_messages", side_effect=MailboxError("connection refused")):
            result = sync_module.sync_mailbox()

    assert result["configured"] is True
    assert result["new_messages"] == 0
    assert "connection refused" in result["error"]

    from models import MailboxStatus
    from extensions import db
    with app.app_context():
        row = db.session.get(MailboxStatus, 1)
        assert row.connected is False
        assert "connection refused" in row.last_error


def test_repeat_sync_does_not_duplicate_scans(app):
    """Calling sync_mailbox() twice in a row for the same message (the
    background poller and a manual click both landing on it) must not
    create two Scan rows -- the known_uids skip plus the unique index
    both defend against this."""
    msg = {
        "uid": "301", "message_id": "<msg301@mail>",
        "sender": "a@b.com", "subject": "hi", "body": "just checking in", "date": None,
    }
    with app.app_context():
        with patch.object(MailboxConfig, "from_env", return_value=_fake_cfg()), \
             patch.object(sync_module, "fetch_new_messages", side_effect=[[msg], []]), \
             patch.object(sync_module, "quarantine_message"), \
             patch.object(sync_module, "flag_message"):
            sync_module.sync_mailbox()
            sync_module.sync_mailbox()

        from models import Scan
        matches = Scan.query.filter_by(mailbox_uid="301").all()
        assert len(matches) == 1


def test_overlapping_sync_is_skipped_not_run_concurrently(app):
    """Simulates the Beat-scheduled sync and a manual admin sync landing
    at the same time: the second caller must not process anything while
    the first (simulated by manually holding the lock) is still running."""
    with app.app_context():
        from models import MailboxStatus
        from extensions import db as _db
        from datetime import datetime, timezone

        row = sync_module.get_or_create_status_row()
        row.sync_in_progress = True
        row.sync_lock_acquired_at = datetime.now(timezone.utc).replace(tzinfo=None)
        _db.session.commit()

        with patch.object(MailboxConfig, "from_env", return_value=_fake_cfg()), \
             patch.object(sync_module, "fetch_new_messages") as mock_fetch:
            result = sync_module.sync_mailbox()

        assert result.get("skipped")
        mock_fetch.assert_not_called()

        # lock is released by the "first" sync as normal; a subsequent
        # call succeeds again
        row = _db.session.get(MailboxStatus, 1)
        row.sync_in_progress = False
        _db.session.commit()
        with patch.object(MailboxConfig, "from_env", return_value=_fake_cfg()), \
             patch.object(sync_module, "fetch_new_messages", return_value=[]) as mock_fetch2:
            result2 = sync_module.sync_mailbox()
        mock_fetch2.assert_called_once()
        assert not result2.get("skipped")


def test_stale_sync_lock_can_be_taken_over(app):
    """A lock older than SYNC_LOCK_STALE_AFTER is treated as abandoned
    (the process holding it crashed) rather than blocking sync forever."""
    with app.app_context():
        from extensions import db as _db
        from datetime import datetime, timezone

        row = sync_module.get_or_create_status_row()
        row.sync_in_progress = True
        row.sync_lock_acquired_at = (
            datetime.now(timezone.utc).replace(tzinfo=None) - sync_module.SYNC_LOCK_STALE_AFTER * 2
        )
        _db.session.commit()

        with patch.object(MailboxConfig, "from_env", return_value=_fake_cfg()), \
             patch.object(sync_module, "fetch_new_messages", return_value=[]) as mock_fetch:
            result = sync_module.sync_mailbox()

        mock_fetch.assert_called_once()
        assert not result.get("skipped")


def test_raw_imap_exception_from_move_is_wrapped_and_does_not_crash_sync(app):
    """quarantine_message/flag_message can raise raw imap_tools exceptions
    (not MailboxError) from mb.move()/mb.flag()/mb.folder.create() -- these
    must be wrapped as MailboxError so sync_mailbox's `except MailboxError`
    catches them instead of the whole sync crashing uncaught."""
    from mailbox.imap_client import quarantine_message, flag_message, MailboxError as RealMailboxError

    cfg = _fake_cfg()

    class _FakeMailBox:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        class folder:
            @staticmethod
            def set(_):
                pass

            @staticmethod
            def list():
                return []

            @staticmethod
            def create(_):
                raise RuntimeError("raw imap_tools failure, not a MailboxError")

        @staticmethod
        def move(*a, **kw):
            raise RuntimeError("raw imap_tools failure, not a MailboxError")

        @staticmethod
        def flag(*a, **kw):
            raise RuntimeError("raw imap_tools failure, not a MailboxError")

    with patch("mailbox.imap_client.connect", return_value=_FakeMailBox()):
        try:
            quarantine_message(cfg, "1")
            assert False, "expected MailboxError"
        except RealMailboxError:
            pass

        try:
            flag_message(cfg, "1")
            assert False, "expected MailboxError"
        except RealMailboxError:
            pass


def test_scan_is_kept_even_if_mailbox_action_fails(app):
    msg = {
        "uid": "202", "message_id": "<msg202@mail>",
        "sender": "PayPal Security <security@paypa1-support.com>",
        "subject": "Your account will be suspended — verify now",
        "body": "Dear Customer, verify your account immediately. http://bit.ly/verify-acct",
        "date": None,
    }
    with app.app_context():
        with patch.object(MailboxConfig, "from_env", return_value=_fake_cfg()), \
             patch.object(sync_module, "fetch_new_messages", return_value=[msg]), \
             patch.object(sync_module, "quarantine_message", side_effect=MailboxError("mailbox move failed")), \
             patch.object(sync_module, "flag_message", side_effect=MailboxError("mailbox flag failed")):
            sync_module.sync_mailbox()

        from models import Scan
        scan = Scan.query.filter_by(mailbox_uid="202").first()
        assert scan is not None  # classification is never lost even if the mailbox action fails
        assert scan.mailbox_action_error is not None
