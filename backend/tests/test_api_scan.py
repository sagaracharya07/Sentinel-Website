"""
Integration tests for the scan -> persist -> history round trip, and the
feedback -> used_in_retrain flag flow that feeds Phase 2's retrain_task.
"""


def test_scan_requires_login(client):
    resp = client.post("/api/scan", json={"subject": "x", "body": "y", "from": "a@b.com"})
    assert resp.status_code == 401


def test_scan_requires_body(user_client):
    resp = user_client.post("/api/scan", json={"subject": "x", "from": "a@b.com"})
    assert resp.status_code == 400


def test_scan_rejects_oversized_body(user_client):
    resp = user_client.post("/api/scan", json={
        "subject": "x", "from": "a@b.com", "body": "a" * 20001,
    })
    assert resp.status_code == 400


def test_scan_persists_and_appears_in_history(user_client):
    resp = user_client.post("/api/scan", json={
        "subject": "Your account will be suspended — verify now",
        "from": "PayPal Security <security@paypa1-support.com>",
        "body": "Dear Customer, verify your account immediately or it will be suspended. "
                "Click here: http://bit.ly/verify-acct",
    })
    assert resp.status_code == 200
    scan = resp.get_json()
    assert scan["classification"] in ("Phishing", "Needs Review", "Legitimate")
    assert scan["scan_id"].startswith("SCN-")

    history = user_client.get("/api/history").get_json()
    assert any(s["scan_id"] == scan["scan_id"] for s in history)

    detail = user_client.get(f"/api/scan/{scan['scan_id']}").get_json()
    assert detail["scan_id"] == scan["scan_id"]


def test_scan_detail_forbidden_for_other_users(user_client, admin_client):
    scan = user_client.post("/api/scan", json={
        "subject": "hi", "from": "a@b.com", "body": "just checking in",
    }).get_json()

    from auth import create_user
    from app import app as flask_app
    with flask_app.app_context():
        create_user("other_user", "test_password_123", role="user")
    other_client = flask_app.test_client()
    other_client.post("/api/auth/login", json={"username": "other_user", "password": "test_password_123"})

    resp = other_client.get(f"/api/scan/{scan['scan_id']}")
    assert resp.status_code == 403

    # but an admin can see any scan
    resp = admin_client.get(f"/api/scan/{scan['scan_id']}")
    assert resp.status_code == 200


def test_feedback_flow_marks_scan_and_creates_unused_feedback_row(user_client):
    scan = user_client.post("/api/scan", json={
        "subject": "hi", "from": "a@b.com", "body": "just checking in about lunch",
    }).get_json()

    resp = user_client.post("/api/feedback", json={
        "scan_id": scan["scan_id"], "corrected_label": "Phishing",
    })
    assert resp.status_code == 200
    updated = resp.get_json()
    assert updated["user_feedback"] == "Phishing"

    from models import Feedback
    from app import app as flask_app
    with flask_app.app_context():
        fb = Feedback.query.filter_by(scan_id=scan["scan_id"]).first()
        assert fb is not None
        assert fb.corrected_label == "Phishing"
        assert fb.used_in_retrain is False


def test_feedback_rejects_invalid_label(user_client):
    scan = user_client.post("/api/scan", json={
        "subject": "hi", "from": "a@b.com", "body": "just checking in",
    }).get_json()
    resp = user_client.post("/api/feedback", json={
        "scan_id": scan["scan_id"], "corrected_label": "Not A Real Label",
    })
    assert resp.status_code == 400


def _login_other_user(flask_app, username="other_user"):
    from auth import create_user
    with flask_app.app_context():
        create_user(username, "test_password_123", role="user")
    other_client = flask_app.test_client()
    resp = other_client.post("/api/auth/login", json={"username": username, "password": "test_password_123"})
    assert resp.status_code == 200
    return other_client


def test_feedback_forbidden_for_other_users_scan(user_client, app):
    scan = user_client.post("/api/scan", json={
        "subject": "hi", "from": "a@b.com", "body": "just checking in",
    }).get_json()

    other_client = _login_other_user(app)
    resp = other_client.post("/api/feedback", json={
        "scan_id": scan["scan_id"], "corrected_label": "Phishing",
    })
    assert resp.status_code == 403


def test_feedback_allowed_for_admin_on_any_scan(user_client, admin_client):
    scan = user_client.post("/api/scan", json={
        "subject": "hi", "from": "a@b.com", "body": "just checking in",
    }).get_json()
    resp = admin_client.post("/api/feedback", json={
        "scan_id": scan["scan_id"], "corrected_label": "Phishing",
    })
    assert resp.status_code == 200


def test_history_hides_other_users_scans_by_default(user_client, app):
    user_client.post("/api/scan", json={"subject": "mine", "from": "a@b.com", "body": "my own message here"})

    other_client = _login_other_user(app)
    other_client.post("/api/scan", json={"subject": "theirs", "from": "a@b.com", "body": "their own message here"})

    history = other_client.get("/api/history").get_json()
    subjects = {s["subject"] for s in history}
    assert "theirs" in subjects
    assert "mine" not in subjects


def test_history_ignores_client_supplied_mine_param(user_client, app):
    """Ownership must be server-enforced, not opt-in via ?mine=true."""
    user_client.post("/api/scan", json={"subject": "mine", "from": "a@b.com", "body": "my own message here"})
    other_client = _login_other_user(app)
    other_client.post("/api/scan", json={"subject": "theirs", "from": "a@b.com", "body": "their own message here"})

    history = other_client.get("/api/history?mine=false").get_json()
    subjects = {s["subject"] for s in history}
    assert "mine" not in subjects


def test_history_shows_all_scans_for_admin(user_client, admin_client):
    user_client.post("/api/scan", json={"subject": "mine", "from": "a@b.com", "body": "my own message here"})
    history = admin_client.get("/api/history").get_json()
    assert any(s["subject"] == "mine" for s in history)


def test_stats_scoped_to_own_scans_for_regular_user(user_client, app):
    user_client.post("/api/scan", json={"subject": "mine", "from": "a@b.com", "body": "my own message here"})
    other_client = _login_other_user(app)
    other_client.post("/api/scan", json={"subject": "theirs", "from": "a@b.com", "body": "their own message here"})

    stats = other_client.get("/api/stats").get_json()
    assert stats["total"] == 1
    assert stats["scope"] == "own_scans"


def test_stats_global_for_admin(user_client, admin_client):
    user_client.post("/api/scan", json={"subject": "mine", "from": "a@b.com", "body": "my own message here"})
    stats = admin_client.get("/api/stats").get_json()
    assert stats["total"] >= 1
    assert stats["scope"] == "all_users"
