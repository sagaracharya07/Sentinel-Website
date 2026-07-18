"""
Migration test for the gmail_connections table.

Runs Alembic base -> head against a throwaway SQLite file and asserts the
new table and its indexes exist, independent of the conftest db.create_all()
path (which builds tables straight from the models). This is what proves the
hand-written migration itself is correct, not just the model.
"""

import os
import sqlite3

from alembic import command
from alembic.config import Config

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _alembic_config():
    cfg = Config(os.path.join(BACKEND_DIR, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BACKEND_DIR, "migrations"))
    return cfg


def test_migration_base_to_head_creates_gmail_connections(tmp_path, monkeypatch):
    db_file = tmp_path / "mig.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("SENTINEL_ENV", "development")

    command.upgrade(_alembic_config(), "head")

    con = sqlite3.connect(db_file)
    try:
        tables = {
            r[0]
            for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert "gmail_connections" in tables
        # Pre-existing tables must still be created by the full chain.
        assert {"users", "scans", "feedback", "audit_log"}.issubset(tables)

        cols = {r[1] for r in con.execute("PRAGMA table_info(gmail_connections)")}
        for expected in (
            "encrypted_refresh_token",
            "encrypted_access_token",
            "connection_status",
            "protection_enabled",
            "mailbox_email",
            "last_history_id",
            "quarantine_label_id",
        ):
            assert expected in cols, f"missing column {expected}"

        indexes = {
            r[0]
            for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='gmail_connections'"
            )
        }
        assert "ix_gmail_connections_mailbox_email" in indexes
        assert "ix_gmail_connections_connection_status" in indexes
    finally:
        con.close()


def test_migration_downgrade_removes_table(tmp_path, monkeypatch):
    db_file = tmp_path / "mig2.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("SENTINEL_ENV", "development")

    cfg = _alembic_config()
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "3bf198b6ab98")  # one below the gmail revision

    con = sqlite3.connect(db_file)
    try:
        tables = {
            r[0]
            for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert "gmail_connections" not in tables
        assert "scans" in tables  # earlier schema intact
    finally:
        con.close()
