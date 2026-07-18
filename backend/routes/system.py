"""
System Health aggregation (admin-only, read-only).

Composes checks that already exist individually (the /readyz probe's
database/Redis checks, GmailConnection status, ml/infer's model info) into
one admin-facing view, plus a Celery worker liveness ping that nothing else
in the codebase exposes yet. This is the one small addition from Checkpoint
0's approved list: "System Health aggregator -- composes /readyz + gmail
status + Celery ping into one admin view; nothing equivalent exists."

Every check is real. A dependency that can't be meaningfully verified is
reported as "unknown", never faked as healthy -- see the module docstring
requirement in the frontend-revamp direction: "Do not mark a service Healthy
without a meaningful check."
"""

import os
import logging

from flask import Blueprint, jsonify
from sqlalchemy import text

from extensions import db
from auth import admin_required
from models import GmailConnection, GMAIL_STATUS_CONNECTED
from ml import infer

logger = logging.getLogger(__name__)

system_bp = Blueprint("system", __name__)


def _check_database():
    try:
        db.session.execute(text("SELECT 1"))
        return "healthy", None
    except Exception as e:
        return "unavailable", str(e)[:200]


def _check_redis():
    redis_url = os.environ.get("REDIS_URL")
    if not redis_url:
        return "not_configured", None
    try:
        import redis as redis_lib

        redis_lib.from_url(redis_url, socket_connect_timeout=2).ping()
        return "healthy", None
    except Exception as e:
        return "unavailable", str(e)[:200]


def _check_celery_worker():
    redis_url = os.environ.get("REDIS_URL")
    if not redis_url:
        return "not_configured", None, 0
    try:
        from celery_app import celery_app

        pong = celery_app.control.inspect(timeout=1.5).ping() or {}
        return ("healthy", None, len(pong)) if pong else ("unavailable", None, 0)
    except Exception as e:
        return "unknown", str(e)[:200], 0


def _check_migration_version():
    try:
        row = db.session.execute(
            text("SELECT version_num FROM alembic_version")
        ).fetchone()
        return row[0] if row else None
    except Exception:
        return None


def _check_gmail():
    conn = GmailConnection.active()
    if not conn:
        return "not_configured", None
    if conn.connection_status == GMAIL_STATUS_CONNECTED and conn.protection_enabled:
        return "healthy", conn.mailbox_email
    if conn.connection_status == "paused":
        return "degraded", conn.mailbox_email
    return "unavailable", conn.mailbox_email


@system_bp.get("/api/admin/system-health")
@admin_required
def system_health():
    db_status, db_error = _check_database()
    redis_status, redis_error = _check_redis()
    worker_status, worker_error, worker_count = _check_celery_worker()
    gmail_status, gmail_email = _check_gmail()

    try:
        model = infer.current_info()
        model_status = "healthy"
    except Exception as e:
        model = None
        model_status = "unavailable"
        logger.warning("system_health: model info unavailable: %s", e)

    checks = {
        "web": {"status": "healthy"},
        "database": {"status": db_status, "error": db_error},
        "redis": {"status": redis_status, "error": redis_error},
        "celery_worker": {
            "status": worker_status,
            "error": worker_error,
            "worker_count": worker_count,
        },
        # Celery Beat has no built-in liveness signal this app exposes yet
        # (would need a heartbeat task or broker introspection beyond scope
        # here) -- reported honestly as unknown rather than assumed healthy.
        "celery_beat": {"status": "unknown"},
        "gmail_mailbox": {"status": gmail_status, "mailbox_email": gmail_email},
        "model": {"status": model_status, "info": model},
        "migration_version": _check_migration_version(),
    }
    overall = "healthy"
    if any(
        c.get("status") in ("unavailable",)
        for c in checks.values()
        if isinstance(c, dict)
    ):
        overall = "degraded"
    return jsonify(
        {
            "overall": overall,
            "checks": checks,
            # Read fresh on every call (not cached at import time) so this
            # always reflects the actual running process's environment.
            "environment": os.environ.get("SENTINEL_ENV", "development").strip()
            or "development",
        }
    )
