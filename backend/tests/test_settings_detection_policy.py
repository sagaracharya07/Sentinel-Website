"""
Tests for the Detection Policy settings API (routes/settings.py): default
values, validation, persistence, audit logging, access control, and that
ml/infer.classify() actually honours an updated threshold.
"""


def test_get_requires_admin(client, user_client):
    resp = user_client.get("/api/admin/settings/detection-policy")
    assert resp.status_code == 403


def test_get_returns_defaults(admin_client):
    resp = admin_client.get("/api/admin/settings/detection-policy")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["needs_review_threshold"] == 0.5
    assert data["phishing_threshold"] == 0.75


def test_update_persists_new_thresholds(admin_client):
    resp = admin_client.post(
        "/api/admin/settings/detection-policy",
        json={"needs_review_threshold": 0.4, "phishing_threshold": 0.8},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["needs_review_threshold"] == 0.4
    assert data["phishing_threshold"] == 0.8
    assert data["updated_by"] == "test_admin"

    # persisted -- a fresh GET reflects it, not just the POST response
    again = admin_client.get("/api/admin/settings/detection-policy")
    assert again.get_json()["needs_review_threshold"] == 0.4


def test_update_rejects_overlapping_thresholds(admin_client):
    resp = admin_client.post(
        "/api/admin/settings/detection-policy",
        json={"needs_review_threshold": 0.8, "phishing_threshold": 0.5},
    )
    assert resp.status_code == 400


def test_update_rejects_out_of_range_thresholds(admin_client):
    resp = admin_client.post(
        "/api/admin/settings/detection-policy",
        json={"needs_review_threshold": 0.0, "phishing_threshold": 1.0},
    )
    assert resp.status_code == 400


def test_update_rejects_non_numeric(admin_client):
    resp = admin_client.post(
        "/api/admin/settings/detection-policy",
        json={"needs_review_threshold": "low", "phishing_threshold": 0.8},
    )
    assert resp.status_code == 400


def test_update_is_audited(admin_client, app):
    admin_client.post(
        "/api/admin/settings/detection-policy",
        json={"needs_review_threshold": 0.45, "phishing_threshold": 0.85},
    )
    with app.app_context():
        from models import AuditLog

        entries = AuditLog.query.filter_by(action="detection_policy_updated").all()
        assert len(entries) == 1


def test_classify_reads_updated_threshold_from_settings(admin_client, app):
    """decide() itself defaults to 0.75/0.50 (existing behaviour/tests
    unaffected) -- ml.infer._current_thresholds() is what classify() calls
    to override those defaults, so this proves the settings row is actually
    read rather than just asserting decide()'s own default arguments."""
    admin_client.post(
        "/api/admin/settings/detection-policy",
        json={"needs_review_threshold": 0.10, "phishing_threshold": 0.20},
    )
    with app.app_context():
        from ml.infer import _current_thresholds

        needs_review, phishing = _current_thresholds()
        assert needs_review == 0.10
        assert phishing == 0.20
