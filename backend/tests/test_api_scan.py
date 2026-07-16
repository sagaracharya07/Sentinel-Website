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
    assert scan["classification"] in ("Phishing", "Legitimate")
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
