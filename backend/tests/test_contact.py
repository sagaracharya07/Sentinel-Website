"""Tests for the public contact-form endpoint."""

from unittest.mock import patch


def test_contact_requires_name_email_message(client):
    resp = client.post("/api/contact", json={"email": "a@b.com", "message": "hi"})
    assert resp.status_code == 400

    resp = client.post(
        "/api/contact", json={"name": "A", "email": "not-an-email", "message": "hi"}
    )
    assert resp.status_code == 400

    resp = client.post("/api/contact", json={"name": "A", "email": "a@b.com"})
    assert resp.status_code == 400


def test_contact_rejects_oversized_message(client):
    resp = client.post(
        "/api/contact",
        json={
            "name": "A",
            "email": "a@b.com",
            "message": "x" * 5001,
        },
    )
    assert resp.status_code == 400


def test_contact_succeeds_without_recipient_configured(client):
    # CONTACT_RECIPIENT_EMAIL isn't set in the test environment -- the
    # submission should still succeed and be recorded, just not emailed.
    resp = client.post(
        "/api/contact",
        json={
            "name": "Jane",
            "email": "jane@example.com",
            "message": "How does retraining work?",
        },
    )
    assert resp.status_code == 200


def test_contact_emails_recipient_when_configured(client, monkeypatch):
    monkeypatch.setenv("CONTACT_RECIPIENT_EMAIL", "owner@example.com")
    with patch("app.send_email", return_value=True) as mock_send:
        resp = client.post(
            "/api/contact",
            json={
                "name": "Jane",
                "email": "jane@example.com",
                "message": "Hello there",
            },
        )
    assert resp.status_code == 200
    mock_send.assert_called_once()
    assert mock_send.call_args[0][0] == "owner@example.com"
