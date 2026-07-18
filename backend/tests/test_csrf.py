"""
Verifies CSRF protection is actually wired up, using a real browser-like
flow (fetch a token, then send it back) rather than relying on the other
test modules, which deliberately disable WTF_CSRF_ENABLED (see
conftest.py) to keep unrelated tests simple.
"""

import re


def test_state_changing_request_without_token_is_rejected(client, app):
    app.config["WTF_CSRF_ENABLED"] = True
    resp = client.post("/api/auth/logout")
    assert resp.status_code == 400


def test_state_changing_request_with_valid_token_succeeds(client, app):
    app.config["WTF_CSRF_ENABLED"] = True
    token_resp = client.get("/api/csrf-token")
    assert token_resp.status_code == 200
    token = token_resp.get_json()["csrf_token"]
    assert token

    resp = client.post("/api/auth/logout", headers={"X-CSRFToken": token})
    assert resp.status_code == 200


def test_csrf_token_endpoint_returns_a_token(client):
    resp = client.get("/api/csrf-token")
    assert resp.status_code == 200
    body = resp.get_json()
    assert re.match(r".+", body["csrf_token"] or "")
