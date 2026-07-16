"""
Single source of truth for resolving the database connection string, shared
by app.py (Flask-SQLAlchemy config) and migrations/env.py (Alembic) so the
two can never disagree about which database they're pointed at.
"""
import os


def resolve_database_uri(instance_dir: str, is_production: bool) -> str:
    """
    Render (and most Postgres hosts) inject DATABASE_URL. Prefer that in any
    environment where it's set; fall back to a local SQLite file only for
    zero-config local dev -- and never in production, where a silent
    SQLite fallback would defeat the entire point of this migration.
    SQLAlchemy 1.4+ dropped support for the 'postgres://' scheme some
    providers still hand out, so rewrite it to 'postgresql://' before use.
    """
    url = os.environ.get("DATABASE_URL")
    if not url:
        if is_production:
            raise RuntimeError(
                "DATABASE_URL must be set when SENTINEL_ENV=production -- "
                "refusing to fall back to a local single-file SQLite database."
            )
        return "sqlite:///" + os.path.join(instance_dir, "sentinel.db")
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    return url
