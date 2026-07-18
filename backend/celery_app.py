"""
Celery application for Sentinel's background jobs.

Replaces the two threading.Thread daemons that used to run inside the
Flask process (purge_loop, mailbox_poll_loop -- formerly in app.py) with a
supervised job queue that's safe alongside multiple web replicas: exactly
one Celery Beat scheduler enqueues periodic jobs, and any number of worker
processes can pick them up without double-processing. Both underlying jobs
were already idempotent (mailbox.sync.sync_mailbox tracks scanned UIDs;
purge_old_bodies filters on a timestamp cutoff), so moving them to a queue
doesn't change their behavior, only who's allowed to run them and how many
times.

Run (see docker-compose.yml for the full local-dev picture):
    celery -A celery_app worker --loglevel=info
    celery -A celery_app beat --loglevel=info
"""

import os

from celery import Celery

from monitoring import init_sentry

# No-op unless SENTRY_DSN is set -- see monitoring.py. Captures unhandled
# exceptions from worker/beat tasks the same way FlaskIntegration does for
# the web process (see app.py) -- without this, a task crashing would
# only show up in stdout logs, easy to miss compared to the web process's
# errors.
from sentry_sdk.integrations.celery import CeleryIntegration

init_sentry(extra_integrations=[CeleryIntegration()])

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery("sentinel", broker=REDIS_URL, backend=REDIS_URL, include=["tasks"])

# Gmail is the primary integration. Legacy IMAP polling is OFF by default now
# (Phase 12) -- it stays fully implemented and tested as a dev/legacy fallback,
# but is only scheduled when IMAP_ENABLED=true, so IMAP and Gmail can't both
# poll (and double-process) the same mailbox unless explicitly opted in.
_beat_schedule = {
    "purge-old-scan-bodies": {
        "task": "tasks.purge_old_bodies_task",
        "schedule": 600.0,  # every 10 minutes -- matches the old purge_loop cadence
    },
    # Poll the active Gmail connection on its own cadence. The task is a no-op
    # when no mailbox is connected or protection is paused, so it's harmless to
    # schedule unconditionally.
    "gmail-sync": {
        "task": "tasks.gmail_sync_task",
        "schedule": float(os.environ.get("GMAIL_POLL_SECONDS", "60")),
    },
    # Re-arm the optional Gmail push watch daily (watches expire after 7 days).
    # No-op unless push mode is configured and enabled.
    "gmail-watch-renew": {
        "task": "tasks.gmail_watch_renew_task",
        "schedule": float(os.environ.get("GMAIL_WATCH_RENEW_SECONDS", "86400")),
    },
}

if os.environ.get("IMAP_ENABLED", "false").strip().lower() == "true":
    _beat_schedule["mailbox-sync"] = {
        "task": "tasks.mailbox_sync_task",
        "schedule": float(os.environ.get("MAILBOX_POLL_SECONDS", "45")),
    }

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    beat_schedule=_beat_schedule,
)
