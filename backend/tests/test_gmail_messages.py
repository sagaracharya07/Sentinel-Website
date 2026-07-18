"""Gmail message retrieval, content extraction, and label actions."""

from types import SimpleNamespace

import pytest

from integrations.gmail import messages
from integrations.gmail.exceptions import GmailNotFoundError
from tests.gmail_fakes import FakeGmailService, make_message


def _conn():
    return SimpleNamespace(
        quarantine_label_id="LBL-Q",
        needs_review_label_id="LBL-NR",
        processed_label_id="LBL-P",
        scan_failed_label_id="LBL-SF",
    )


# --- extraction --------------------------------------------------------------
def test_extract_basic_plain_body_and_headers():
    msg = make_message(
        "m1", sender="Boss <boss@corp.example>", subject="Payroll", body="pay now"
    )
    out = messages.extract_basic(msg)
    assert out["sender"] == "Boss <boss@corp.example>"
    assert out["subject"] == "Payroll"
    assert out["body"] == "pay now"
    assert out["gmail_message_id"] == "m1"
    assert out["rfc_message_id"] == "<m1@ext.example>"


def test_extract_basic_html_fallback_when_no_plaintext():
    msg = make_message("m2", body=None, html="<p>hello <b>html</b></p>")
    out = messages.extract_basic(msg)
    assert "hello" in out["body"]


def test_extract_basic_missing_headers_are_empty():
    msg = {"id": "m3", "threadId": "t", "payload": {"headers": [], "parts": []}}
    out = messages.extract_basic(msg)
    assert out["sender"] == ""
    assert out["subject"] == ""
    assert out["body"] == ""


# --- retrieval ---------------------------------------------------------------
def test_get_message_missing_raises_not_found():
    svc = FakeGmailService(messages=[])
    with pytest.raises(GmailNotFoundError):
        messages.get_message(svc, "nope")


def test_list_history_returns_only_inbox_added():
    svc = FakeGmailService()
    svc.history_store = [
        {"messagesAdded": [{"message": {"id": "a", "labelIds": ["INBOX"]}}]},
        {
            "messagesAdded": [{"message": {"id": "b", "labelIds": ["SENT"]}}]
        },  # not inbox
        {"messagesAdded": [{"message": {"id": "a", "labelIds": ["INBOX"]}}]},  # dup
    ]
    added, latest = messages.list_history(svc, "100")
    assert added == ["a"]
    assert latest == svc.profile["historyId"]


# --- label actions (idempotent) ---------------------------------------------
def test_quarantine_adds_label_removes_inbox():
    svc = FakeGmailService(messages=[make_message("m", labels=["INBOX", "UNREAD"])])
    messages.quarantine(svc, "m", _conn())
    labels = set(svc.messages_store["m"]["labelIds"])
    assert "LBL-Q" in labels
    assert "INBOX" not in labels


def test_release_restores_inbox_and_drops_review_labels():
    svc = FakeGmailService(messages=[make_message("m", labels=["LBL-Q", "LBL-NR"])])
    messages.release(svc, "m", _conn())
    labels = set(svc.messages_store["m"]["labelIds"])
    assert "INBOX" in labels
    assert "LBL-Q" not in labels and "LBL-NR" not in labels


def test_needs_review_keeps_inbox():
    svc = FakeGmailService(messages=[make_message("m", labels=["INBOX"])])
    messages.mark_needs_review(svc, "m", _conn())
    labels = set(svc.messages_store["m"]["labelIds"])
    assert "INBOX" in labels and "LBL-NR" in labels


def test_repeated_quarantine_is_idempotent():
    svc = FakeGmailService(messages=[make_message("m", labels=["INBOX"])])
    messages.quarantine(svc, "m", _conn())
    first = set(svc.messages_store["m"]["labelIds"])
    messages.quarantine(svc, "m", _conn())  # again
    second = set(svc.messages_store["m"]["labelIds"])
    assert first == second  # no corruption, converges to same state
    assert "INBOX" not in second and "LBL-Q" in second


def test_repeated_release_is_idempotent():
    svc = FakeGmailService(messages=[make_message("m", labels=["LBL-Q"])])
    messages.release(svc, "m", _conn())
    messages.release(svc, "m", _conn())
    labels = set(svc.messages_store["m"]["labelIds"])
    assert "INBOX" in labels and "LBL-Q" not in labels
