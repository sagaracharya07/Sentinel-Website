"""Tests for the /healthz (liveness) and /readyz (readiness) endpoints."""
from unittest.mock import patch


def test_healthz_always_ok(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True}


def test_healthz_not_rate_limited(client):
    # 5/minute on login would 429 by the 6th call; healthz must never
    # throttle a monitor polling frequently.
    for _ in range(20):
        resp = client.get("/healthz")
        assert resp.status_code == 200


def test_readyz_ok_when_database_reachable(client):
    resp = client.get("/readyz")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    assert body["checks"]["database"] == "ok"


def test_readyz_reports_database_failure(client):
    with patch("extensions.db.session.execute", side_effect=Exception("connection refused")):
        resp = client.get("/readyz")
    assert resp.status_code == 503
    body = resp.get_json()
    assert body["ok"] is False
    assert "error" in body["checks"]["database"]


def test_readyz_reports_redis_not_configured_by_default(client):
    resp = client.get("/readyz")
    assert resp.get_json()["checks"]["redis"] == "not configured"


def test_readyz_reports_redis_failure_when_configured_but_unreachable(client, monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://localhost:1/0")  # nothing listens here
    resp = client.get("/readyz")
    assert resp.status_code == 503
    assert "error" in resp.get_json()["checks"]["redis"]
