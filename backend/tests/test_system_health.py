"""
Tests for the System Health aggregator (routes/system.py): access control
and that it reports real, honestly-labelled status for each dependency
rather than a hardcoded "healthy" everywhere.
"""


def test_requires_admin(client, user_client):
    resp = user_client.get("/api/admin/system-health")
    assert resp.status_code == 403


def test_requires_login(client):
    resp = client.get("/api/admin/system-health")
    assert resp.status_code == 401


def test_returns_real_dependency_checks(admin_client):
    resp = admin_client.get("/api/admin/system-health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["overall"] in ("healthy", "degraded")
    checks = data["checks"]
    # Database is real (tests run against a real, if temporary, SQLite file).
    assert checks["database"]["status"] == "healthy"
    # No REDIS_URL is configured in the test environment (see conftest.py) --
    # this must be reported honestly as not_configured, never faked healthy.
    assert checks["redis"]["status"] == "not_configured"
    assert checks["celery_worker"]["status"] == "not_configured"
    # Celery Beat has no liveness signal this app can check yet -- must never
    # be reported as healthy without a meaningful check behind that claim.
    assert checks["celery_beat"]["status"] == "unknown"
    assert checks["gmail_mailbox"]["status"] == "not_configured"
    assert checks["model"]["status"] == "healthy"
    assert checks["model"]["info"]["version"]
    assert data["environment"] == "development"
