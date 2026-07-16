"""
Tests for auth.py's password hashing and the login_required/admin_required
decorators, exercised through real protected routes rather than by calling
the decorators in isolation, since that's how they're actually used.
"""
from auth import create_user, verify_login


def test_password_hashing_round_trip(app):
    with app.app_context():
        create_user("alice", "correct-horse-battery-staple", role="user")
        assert verify_login("alice", "correct-horse-battery-staple") is not None
        assert verify_login("alice", "wrong-password") is None
        assert verify_login("nonexistent-user", "anything") is None


def test_password_is_not_stored_in_plaintext(app):
    with app.app_context():
        user = create_user("bob", "hunter2", role="user")
        assert user.password_hash != "hunter2"
        assert "hunter2" not in user.password_hash


def test_protected_route_requires_login(client):
    resp = client.get("/api/history")
    assert resp.status_code == 401


def test_protected_route_allows_logged_in_user(user_client):
    resp = user_client.get("/api/history")
    assert resp.status_code == 200


def test_admin_route_rejects_regular_user(user_client):
    resp = user_client.get("/api/admin/audit-log")
    assert resp.status_code == 403


def test_admin_route_allows_admin(admin_client):
    resp = admin_client.get("/api/admin/audit-log")
    assert resp.status_code == 200


def test_logout_clears_session(user_client):
    assert user_client.get("/api/auth/me").status_code == 200
    user_client.post("/api/auth/logout")
    assert user_client.get("/api/auth/me").status_code == 401
