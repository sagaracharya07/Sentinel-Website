"""Pub/Sub push webhook + admin watch routes."""

import tasks
from routes import pubsub as pubsub_mod


def _enqueue_spy(monkeypatch):
    calls = {"n": 0}

    def fake_delay(*a, **k):
        calls["n"] += 1
        return None

    monkeypatch.setattr(tasks.gmail_sync_task, "delay", fake_delay)
    return calls


# --- webhook auth (fail closed) ---------------------------------------------
def test_pubsub_rejected_when_no_token_configured(client, monkeypatch):
    monkeypatch.delenv("GOOGLE_PUBSUB_VERIFICATION_TOKEN", raising=False)
    assert client.post("/api/gmail/pubsub", json={}).status_code == 403


def test_pubsub_rejects_wrong_token(client, monkeypatch):
    monkeypatch.setenv("GOOGLE_PUBSUB_VERIFICATION_TOKEN", "secret-tok")
    assert client.post("/api/gmail/pubsub?token=wrong", json={}).status_code == 403


def test_pubsub_valid_token_enqueues_sync(client, monkeypatch):
    monkeypatch.setenv("GOOGLE_PUBSUB_VERIFICATION_TOKEN", "secret-tok")
    calls = _enqueue_spy(monkeypatch)
    resp = client.post(
        "/api/gmail/pubsub?token=secret-tok",
        json={"message": {"data": "eyJlbWFpbEFkZHJlc3MiOiJ4In0="}},
    )
    assert resp.status_code == 204
    assert calls["n"] == 1


def test_pubsub_acks_even_if_enqueue_fails(client, monkeypatch):
    monkeypatch.setenv("GOOGLE_PUBSUB_VERIFICATION_TOKEN", "secret-tok")

    def boom(*a, **k):
        raise RuntimeError("broker down")

    monkeypatch.setattr(tasks.gmail_sync_task, "delay", boom)
    # Must still 204 so Pub/Sub doesn't retry-storm us while the queue is down.
    resp = client.post("/api/gmail/pubsub?token=secret-tok", json={})
    assert resp.status_code == 204


def test_pubsub_is_csrf_exempt(client, monkeypatch):
    # Real CSRF on; the webhook must still be reachable (Google sends no token).
    monkeypatch.setenv("GOOGLE_PUBSUB_VERIFICATION_TOKEN", "secret-tok")
    _enqueue_spy(monkeypatch)
    client.application.config["WTF_CSRF_ENABLED"] = True
    try:
        resp = client.post("/api/gmail/pubsub?token=secret-tok", json={})
        assert resp.status_code == 204  # not 400 (CSRF) -- exemption works
    finally:
        client.application.config["WTF_CSRF_ENABLED"] = False


# --- OIDC (production) auth mode --------------------------------------------
def test_pubsub_oidc_valid_token_enqueues(client, monkeypatch):
    monkeypatch.setenv("GOOGLE_PUBSUB_AUDIENCE", "https://app/api/gmail/pubsub")
    monkeypatch.delenv("GOOGLE_PUBSUB_VERIFICATION_TOKEN", raising=False)
    monkeypatch.setattr(
        pubsub_mod,
        "_verify_oidc",
        lambda t, a: {"email": "sa@proj.iam.gserviceaccount.com"},
    )
    calls = _enqueue_spy(monkeypatch)
    resp = client.post(
        "/api/gmail/pubsub", headers={"Authorization": "Bearer good.jwt.token"}, json={}
    )
    assert resp.status_code == 204
    assert calls["n"] == 1


def test_pubsub_oidc_missing_bearer_rejected(client, monkeypatch):
    monkeypatch.setenv("GOOGLE_PUBSUB_AUDIENCE", "https://app/api/gmail/pubsub")
    assert client.post("/api/gmail/pubsub", json={}).status_code == 403


def test_pubsub_oidc_invalid_token_rejected(client, monkeypatch):
    monkeypatch.setenv("GOOGLE_PUBSUB_AUDIENCE", "https://app/api/gmail/pubsub")

    def boom(t, a):
        raise ValueError("bad signature")

    monkeypatch.setattr(pubsub_mod, "_verify_oidc", boom)
    resp = client.post(
        "/api/gmail/pubsub", headers={"Authorization": "Bearer bad"}, json={}
    )
    assert resp.status_code == 403


def test_pubsub_oidc_wrong_service_account_rejected(client, monkeypatch):
    monkeypatch.setenv("GOOGLE_PUBSUB_AUDIENCE", "https://app/api/gmail/pubsub")
    monkeypatch.setenv(
        "GOOGLE_PUBSUB_SERVICE_ACCOUNT", "expected@proj.iam.gserviceaccount.com"
    )
    monkeypatch.setattr(
        pubsub_mod, "_verify_oidc", lambda t, a: {"email": "attacker@evil.com"}
    )
    resp = client.post(
        "/api/gmail/pubsub", headers={"Authorization": "Bearer x"}, json={}
    )
    assert resp.status_code == 403


# --- admin watch routes ------------------------------------------------------
def test_watch_start_requires_admin(user_client):
    assert user_client.post("/api/admin/gmail/watch/start").status_code == 403


def test_watch_start_requires_push_config(admin_client, monkeypatch):
    monkeypatch.delenv("GOOGLE_PUBSUB_TOPIC", raising=False)
    assert admin_client.post("/api/admin/gmail/watch/start").status_code == 400


def test_watch_stop_requires_admin(user_client):
    assert user_client.post("/api/admin/gmail/watch/stop").status_code == 403
