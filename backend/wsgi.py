"""
Production WSGI entrypoint (gunicorn -- see Dockerfile/docker-compose.yml
and the Render deploy config). app.py's `if __name__ == "__main__":` block
(the Flask dev server) is local-dev only and is never used in production.

Seeding (ensure_seed_data()) deliberately does NOT happen here: gunicorn
imports this module once per worker process, so seeding here would race
multiple workers against the same INSERT. See seed_startup.py, which runs
once before gunicorn spawns any workers (Dockerfile's CMD chain).
"""

from app import app  # noqa: F401 -- gunicorn imports this module and serves the `app` object
