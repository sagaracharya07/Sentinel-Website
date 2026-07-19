"""
Tests for the real Gmail label action wired into /api/admin/action's
release/confirm branches (app.py's _apply_gmail_mailbox_action). Uses the
same FakeGmailService as the sync tests -- no real Gmail account involved.
"""

from extensions import db
from models import Scan, GmailConnection, GMAIL_STATUS_CONNECTED
from integrations.gmail import client as client_mod
from tests.gmail_fakes import FakeGmailService, make_http_error, _Req


def _connection(app):
    with app.app_context():
        c = GmailConnection(
            provider="gmail",
            mailbox_email="ops@corp.example",
            connection_status=GMAIL_STATUS_CONNECTED,
            protection_enabled=True,
            processed_label_id="LBL-processed",
            needs_review_label_id="LBL-needs-review",
            quarantine_label_id="LBL-quarantine",
            scan_failed_label_id="LBL-scan-failed",
        )
        c.set_refresh_token("rt")
        db.session.add(c)
        db.session.commit()
        return c.id


def _gmail_scan(cid, scan_id, message_id, classification, status, mailbox_action):
    return Scan(
        scan_id=scan_id,
        sender="a@ext.example",
        subject="s",
        classification=classification,
        status=status,
        source="gmail",
        gmail_connection_id=cid,
        gmail_message_id=message_id,
        mailbox_action=mailbox_action,
    )


def _use_service(monkeypatch, svc):
    monkeypatch.setattr(client_mod, "build_service", lambda conn: svc)


def test_confirm_applies_real_gmail_quarantine_label(admin_client, app, monkeypatch):
    cid = _connection(app)
    svc = FakeGmailService(
        messages=[
            {"id": "m1", "threadId": "t1", "labelIds": ["INBOX", "LBL-needs-review"]}
        ]
    )
    _use_service(monkeypatch, svc)
    with app.app_context():
        db.session.add(
            _gmail_scan(cid, "SCN-G1", "m1", "Needs Review", "Flagged", "needs_review")
        )
        db.session.commit()

    resp = admin_client.post(
        "/api/admin/action", json={"scan_id": "SCN-G1", "action": "confirm"}
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["classification"] == "Phishing"
    assert body["mailbox_action"] == "quarantined"
    assert body["mailbox_action_error"] is None

    # The real (fake) mailbox actually reflects it -- not just the DB.
    assert "INBOX" not in svc.messages_store["m1"]["labelIds"]
    assert "LBL-quarantine" in svc.messages_store["m1"]["labelIds"]


def test_release_applies_real_gmail_release(admin_client, app, monkeypatch):
    cid = _connection(app)
    svc = FakeGmailService(
        messages=[
            {"id": "m2", "threadId": "t2", "labelIds": ["LBL-quarantine"]},
        ]
    )
    _use_service(monkeypatch, svc)
    with app.app_context():
        db.session.add(
            _gmail_scan(cid, "SCN-G2", "m2", "Phishing", "Quarantined", "quarantined")
        )
        db.session.commit()

    resp = admin_client.post(
        "/api/admin/action", json={"scan_id": "SCN-G2", "action": "release"}
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["classification"] == "Legitimate"
    assert body["mailbox_action"] == "none"
    assert body["mailbox_action_error"] is None

    assert "INBOX" in svc.messages_store["m2"]["labelIds"]
    assert "LBL-quarantine" not in svc.messages_store["m2"]["labelIds"]


def test_confirm_records_error_without_crashing_when_gmail_fails(
    admin_client, app, monkeypatch
):
    cid = _connection(app)
    svc = FakeGmailService(
        messages=[
            {"id": "m3", "threadId": "t3", "labelIds": ["INBOX"]},
        ]
    )

    # Force the modify() call itself to fail.
    def failing_modify(self, userId="me", id=None, body=None):
        def do():
            raise make_http_error(503, "backendError")

        return _Req(do)

    from tests.gmail_fakes import _MessagesApi

    monkeypatch.setattr(_MessagesApi, "modify", failing_modify)
    _use_service(monkeypatch, svc)

    with app.app_context():
        db.session.add(
            _gmail_scan(cid, "SCN-G3", "m3", "Needs Review", "Flagged", "needs_review")
        )
        db.session.commit()

    resp = admin_client.post(
        "/api/admin/action", json={"scan_id": "SCN-G3", "action": "confirm"}
    )
    # The route itself never crashes/500s even though the Gmail call failed.
    assert resp.status_code == 200
    body = resp.get_json()
    # The Sentinel-side verdict still updates (that's a Sentinel judgement,
    # independent of mailbox mechanics)...
    assert body["classification"] == "Phishing"
    # ...but mailbox_action is NOT falsely reported as changed, and the
    # error is visible instead.
    assert body["mailbox_action"] == "needs_review"
    assert body["mailbox_action_error"]
    assert "GmailRetryableError" in body["mailbox_action_error"]


def test_confirm_is_a_noop_for_non_gmail_scans(admin_client, app):
    # A manual/upload-sourced scan has no gmail_connection_id -- confirming
    # it must not attempt any Gmail call (and must not error).
    with app.app_context():
        db.session.add(
            Scan(
                scan_id="SCN-MANUAL",
                sender="a@ext.example",
                subject="s",
                classification="Needs Review",
                status="Flagged",
                source="manual",
            )
        )
        db.session.commit()

    resp = admin_client.post(
        "/api/admin/action", json={"scan_id": "SCN-MANUAL", "action": "confirm"}
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["classification"] == "Phishing"
    assert body["mailbox_action_error"] is None


def test_confirm_records_error_when_connection_missing(admin_client, app):
    # gmail_connection_id points at a row that doesn't exist (e.g. the
    # mailbox was disconnected after the message was originally scanned).
    with app.app_context():
        db.session.add(
            _gmail_scan(
                999999, "SCN-G4", "m4", "Needs Review", "Flagged", "needs_review"
            )
        )
        db.session.commit()

    resp = admin_client.post(
        "/api/admin/action", json={"scan_id": "SCN-G4", "action": "confirm"}
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["mailbox_action_error"] == "Gmail connection no longer available"
