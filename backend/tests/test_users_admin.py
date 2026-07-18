"""
Tests for the Users & Roles admin API (routes/users.py): listing, role
changes, suspend/activate, the last-admin protection, and that a suspended
account genuinely cannot authenticate.
"""

from auth import create_user


def test_list_users_requires_admin(client, user_client):
    resp = user_client.get("/api/admin/users")
    assert resp.status_code == 403


def test_list_users_requires_login(client):
    resp = client.get("/api/admin/users")
    assert resp.status_code == 401


def test_admin_can_list_users(admin_client, app):
    with app.app_context():
        create_user("alice", "password123", role="user")
    resp = admin_client.get("/api/admin/users")
    assert resp.status_code == 200
    usernames = [u["username"] for u in resp.get_json()]
    assert "alice" in usernames
    assert "test_admin" in usernames


def test_role_change_promotes_user_to_admin(admin_client, app):
    with app.app_context():
        u = create_user("bob", "password123", role="user")
        uid = u.id
    resp = admin_client.post(f"/api/admin/users/{uid}/role", json={"role": "admin"})
    assert resp.status_code == 200
    assert resp.get_json()["role"] == "admin"


def test_role_change_rejects_invalid_role(admin_client, app):
    with app.app_context():
        u = create_user("carol", "password123", role="user")
        uid = u.id
    resp = admin_client.post(
        f"/api/admin/users/{uid}/role", json={"role": "superadmin"}
    )
    assert resp.status_code == 400


def test_cannot_demote_last_remaining_admin(admin_client, app):
    with app.app_context():
        from models import User

        admin = User.query.filter_by(username="test_admin").first()
        admin_id = admin.id
    resp = admin_client.post(f"/api/admin/users/{admin_id}/role", json={"role": "user"})
    assert resp.status_code == 400
    assert "last remaining administrator" in resp.get_json()["error"]


def test_cannot_suspend_last_remaining_admin(admin_client, app):
    with app.app_context():
        from models import User

        admin = User.query.filter_by(username="test_admin").first()
        admin_id = admin.id
    resp = admin_client.post(f"/api/admin/users/{admin_id}/suspend")
    assert resp.status_code == 400


def test_can_demote_admin_when_another_admin_remains(admin_client, app):
    with app.app_context():
        u = create_user("dave", "password123", role="admin")
        uid = u.id
    resp = admin_client.post(f"/api/admin/users/{uid}/role", json={"role": "user"})
    assert resp.status_code == 200
    assert resp.get_json()["role"] == "user"


def test_suspended_user_cannot_authenticate(client, admin_client, app):
    with app.app_context():
        u = create_user("erin", "password123", role="user")
        uid = u.id

    suspend_resp = admin_client.post(f"/api/admin/users/{uid}/suspend")
    assert suspend_resp.status_code == 200
    assert suspend_resp.get_json()["is_active"] is False

    login_resp = client.post(
        "/api/auth/login", json={"username": "erin", "password": "password123"}
    )
    assert login_resp.status_code == 403
    assert "suspended" in login_resp.get_json()["error"].lower()


def test_reactivated_user_can_authenticate_again(client, admin_client, app):
    with app.app_context():
        u = create_user("frank", "password123", role="user")
        uid = u.id

    admin_client.post(f"/api/admin/users/{uid}/suspend")
    activate_resp = admin_client.post(f"/api/admin/users/{uid}/activate")
    assert activate_resp.status_code == 200
    assert activate_resp.get_json()["is_active"] is True

    login_resp = client.post(
        "/api/auth/login", json={"username": "frank", "password": "password123"}
    )
    assert login_resp.status_code == 200


def test_role_change_and_suspension_are_audited(admin_client, app):
    with app.app_context():
        u = create_user("grace", "password123", role="user")
        uid = u.id

    admin_client.post(f"/api/admin/users/{uid}/role", json={"role": "admin"})
    admin_client.post(f"/api/admin/users/{uid}/suspend")

    with app.app_context():
        from models import AuditLog

        actions = [e.action for e in AuditLog.query.filter_by(target="grace").all()]
        assert "user_role_changed" in actions
        assert "user_suspended" in actions


def test_never_exposes_password_hash(admin_client, app):
    resp = admin_client.get("/api/admin/users")
    for row in resp.get_json():
        assert "password_hash" not in row
        assert "password" not in row
