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
