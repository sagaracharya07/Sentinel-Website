"""
Tests for self-serve registration, email verification, and password
reset. Mocks app.send_email (bound into app.py's own namespace via `from
mail.email_client import send_email`) the same way test_mailbox_sync.py
mocks imap_tools -- no real SMTP needed for the suite.
"""

from unittest.mock import patch

from models import User
from extensions import db


def _register(
    client, username="alice", email="alice@example.com", password="password123"
):
    return client.post(
        "/api/auth/register",
        json={
            "username": username,
            "email": email,
            "password": password,
        },
    )


def test_register_creates_unverified_user_role(app, client):
    with patch("app.send_email", return_value=True) as mock_send:
        resp = _register(client)
    assert resp.status_code == 201
    mock_send.assert_called_once()

    with app.app_context():
        user = User.query.filter_by(username="alice").first()
        assert user is not None
        assert user.role == "user"  # never client-settable
        assert user.email == "alice@example.com"
        assert user.email_verified is False
        assert user.verification_token is not None


def test_register_ignores_client_supplied_role(app, client):
    with patch("app.send_email", return_value=True):
        client.post(
            "/api/auth/register",
            json={
                "username": "wannabe_admin",
                "email": "wa@example.com",
                "password": "password123",
                "role": "admin",
            },
        )
    with app.app_context():
        user = User.query.filter_by(username="wannabe_admin").first()
        assert user.role == "user"


def test_register_rejects_duplicate_username(app, client):
    with patch("app.send_email", return_value=True):
        _register(client, username="bob", email="bob1@example.com")
        resp = _register(client, username="bob", email="bob2@example.com")
    assert resp.status_code == 409


def test_register_rejects_duplicate_email(app, client):
    with patch("app.send_email", return_value=True):
        _register(client, username="carol1", email="carol@example.com")
        resp = _register(client, username="carol2", email="carol@example.com")
    assert resp.status_code == 409


def test_register_rejects_weak_password(client):
    resp = _register(client, password="short")
    assert resp.status_code == 400


def test_register_rejects_invalid_email(client):
    resp = _register(client, email="not-an-email")
    assert resp.status_code == 400


def test_unverified_account_cannot_login(client):
    with patch("app.send_email", return_value=True):
        _register(client)
    resp = client.post(
        "/api/auth/login", json={"username": "alice", "password": "password123"}
    )
    assert resp.status_code == 403
    assert "verify" in resp.get_json()["error"].lower()


def test_verify_email_allows_login_after(app, client):
    with patch("app.send_email", return_value=True):
        _register(client)
    with app.app_context():
        token = User.query.filter_by(username="alice").first().verification_token

    resp = client.get(f"/verify-email/{token}", follow_redirects=False)
    assert resp.status_code == 302
    assert "verified=1" in resp.headers["Location"]

    resp = client.post(
        "/api/auth/login", json={"username": "alice", "password": "password123"}
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["email_verified"] is True


def test_verify_email_rejects_invalid_token(client):
    resp = client.get("/verify-email/not-a-real-token", follow_redirects=False)
    assert resp.status_code == 302
    assert "verify_error=1" in resp.headers["Location"]


def test_verify_email_rejects_expired_token(app, client):
    from datetime import datetime, timedelta, timezone

    with patch("app.send_email", return_value=True):
        _register(client)
    with app.app_context():
        user = User.query.filter_by(username="alice").first()
        user.verification_token_expires = datetime.now(timezone.utc).replace(
            tzinfo=None
        ) - timedelta(hours=1)
        db.session.commit()
        token = user.verification_token

    resp = client.get(f"/verify-email/{token}", follow_redirects=False)
    assert "verify_error=1" in resp.headers["Location"]


def test_forgot_password_same_response_regardless_of_email_existing(app, client):
    with patch("app.send_email", return_value=True):
        _register(client)
        resp_exists = client.post(
            "/api/auth/forgot-password", json={"email": "alice@example.com"}
        )
        resp_missing = client.post(
            "/api/auth/forgot-password", json={"email": "nobody@example.com"}
        )
    assert resp_exists.status_code == resp_missing.status_code == 200
    assert resp_exists.get_json() == resp_missing.get_json()


def test_reset_password_full_cycle(app, client):
    with patch("app.send_email", return_value=True):
        _register(client)
        with app.app_context():
            user = User.query.filter_by(username="alice").first()
            user.email_verified = True
            db.session.commit()
        client.post("/api/auth/forgot-password", json={"email": "alice@example.com"})

    with app.app_context():
        token = User.query.filter_by(username="alice").first().reset_token

    resp = client.post(
        "/api/auth/reset-password", json={"token": token, "password": "newpassword456"}
    )
    assert resp.status_code == 200

    resp = client.post(
        "/api/auth/login", json={"username": "alice", "password": "newpassword456"}
    )
    assert resp.status_code == 200

    # token is single-use
    resp = client.post(
        "/api/auth/reset-password", json={"token": token, "password": "again12345678"}
    )
    assert resp.status_code == 400


def test_reset_password_rejects_weak_new_password(app, client):
    with patch("app.send_email", return_value=True):
        _register(client)
        client.post("/api/auth/forgot-password", json={"email": "alice@example.com"})
    with app.app_context():
        token = User.query.filter_by(username="alice").first().reset_token
    resp = client.post(
        "/api/auth/reset-password", json={"token": token, "password": "weak"}
    )
    assert resp.status_code == 400


def test_change_password_requires_correct_current_password(user_client):
    resp = user_client.post(
        "/api/auth/change-password",
        json={
            "current_password": "wrong-password",
            "new_password": "newpassword456",
        },
    )
    assert resp.status_code == 400


def test_change_password_success(user_client):
    resp = user_client.post(
        "/api/auth/change-password",
        json={
            "current_password": "test_password_123",
            "new_password": "newpassword456",
        },
    )
    assert resp.status_code == 200
    user_client.post("/api/auth/logout")
    resp = user_client.post(
        "/api/auth/login", json={"username": "test_user", "password": "newpassword456"}
    )
    assert resp.status_code == 200
