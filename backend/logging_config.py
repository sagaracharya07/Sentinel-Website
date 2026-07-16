"""
Structured logging setup for Sentinel's web process. 12-factor style: logs
go to stdout as single-line, leveled records, and whatever's hosting the
process (Render, Docker, etc) is responsible for collecting/aggregating
them -- this module doesn't manage log files or rotation itself.

Celery's own task logger (celery.utils.log.get_task_logger, already used
correctly in tasks.py) is left alone -- Celery configures its own logging
and duplicating that here would just produce two competing configurations
for the worker/beat processes.
"""
import logging
import os
import sys


def configure_logging():
    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    # Idempotent: ensure_seed_data() and similar startup paths can run
    # more than once in the same process (e.g. under a test runner that
    # imports app.py repeatedly) -- don't stack duplicate handlers.
    if any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    ))
    root.addHandler(handler)
