"""
Production WSGI entrypoint (gunicorn -- see Dockerfile/docker-compose.yml
and the Render deploy config). app.py's `if __name__ == "__main__":` block
(the Flask dev server) is local-dev only and is never used in production.
"""
from app import app  # noqa: F401 -- gunicorn imports this module and serves the `app` object
