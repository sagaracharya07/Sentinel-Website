"""
Shared pytest fixtures for the Sentinel backend test suite.

Sets up an isolated, file-based SQLite database for tests -- never the
real dev database, and never Postgres/Redis (CI wires those up separately
for the migration/job-queue sanity checks; the unit/integration tests here
don't need a live broker). Environment variables are set at *module import
time*, not inside a fixture -- app.py and db_config.py resolve DATABASE_URL
once, at import time, and conftest.py is guaranteed to load before any test
module's `from app import app`, whereas fixtures only run once a test
actually executes (too late to affect that import).
"""

import os
import sys
import tempfile

_TEST_DB_DIR = tempfile.mkdtemp(prefix="sentinel_test_")
_TEST_DB_PATH = os.path.join(_TEST_DB_DIR, "test_sentinel.db")

os.environ["SENTINEL_ENV"] = (
    "development"  # keep dev-mode defaults (insecure secret is fine for tests)
)
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB_PATH}"
os.environ.pop(
    "REDIS_URL", None
)  # rate limiter falls back to in-memory storage during tests
os.environ.pop("MAILBOX_HOST", None)
os.environ.pop("MAILBOX_USERNAME", None)
os.environ.pop("MAILBOX_PASSWORD", None)

# A test-only Fernet key so GmailConnection's encrypted-token methods work in
# tests. Generated (guaranteed valid) rather than hardcoded -- it is NOT a
# real secret and never persists; it only exercises the encrypt/decrypt
# round-trip. Real deployments supply their own TOKEN_ENCRYPTION_KEY (see
# backend/.env.example).
if not os.environ.get("TOKEN_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet

    os.environ["TOKEN_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
# Ensure Gmail OAuth env is not accidentally inherited -- tests control
# configuration explicitly via monkeypatch.
for _k in ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_OAUTH_REDIRECT_URI"):
    os.environ.pop(_k, None)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest


@pytest.fixture()
def app():
    from app import app as flask_app, limiter

    flask_app.config["TESTING"] = True
    # These are direct API-client integration tests (client.post(..., json=...)),
    # not a browser session that fetched a CSRF token first -- exercising the
    # real CSRF flow end-to-end belongs to test_csrf.py, which turns
    # WTF_CSRF_ENABLED back on for that one test. Disabling it here is the
    # documented, deliberate tradeoff (see README "CSRF protection") rather
    # than an oversight: it keeps every other test focused on the behavior
    # it's actually testing instead of every POST needing a token dance.
    flask_app.config["WTF_CSRF_ENABLED"] = False
    limiter.reset()  # tests share one process-wide in-memory limiter; start each test unthrottled
    from extensions import db

    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def _login_as(client, username, password, role):
    from auth import create_user

    create_user(username, password, role=role)
    resp = client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert resp.status_code == 200, resp.get_json()
    return client


@pytest.fixture()
def admin_client(client, app):
    with app.app_context():
        return _login_as(client, "test_admin", "test_password_123", "admin")


@pytest.fixture()
def user_client(client, app):
    with app.app_context():
        return _login_as(client, "test_user", "test_password_123", "user")
