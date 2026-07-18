"""gmail sync lock + gmail detection columns on scans

Revision ID: b2d8e4a1c9f3
Revises: a1c7f2e9b4d0
Create Date: 2026-07-18 14:05:00.000000

Additive only -- no existing column/table is altered destructively:
  - gmail_connections gains a DB-backed sync lock (sync_in_progress,
    sync_lock_acquired_at), mirroring mailbox_status's IMAP lock.
  - scans gains Gmail-detection columns (gmail_connection_id,
    gmail_message_id, gmail_thread_id, gmail_history_id) plus a partial
    UNIQUE index keyed on (gmail_connection_id, gmail_message_id) so the
    same Gmail message can never be recorded twice for one connection.

All new scans columns are nullable; existing rows (manual/IMAP scans) are
unaffected. Uses plain ADD COLUMN (not batch) so SQLite doesn't rebuild the
scans table and the existing partial unique index survives untouched.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "b2d8e4a1c9f3"
down_revision: Union[str, Sequence[str], None] = "a1c7f2e9b4d0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "gmail_connections",
        sa.Column(
            "sync_in_progress", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    op.add_column(
        "gmail_connections",
        sa.Column("sync_lock_acquired_at", sa.DateTime(), nullable=True),
    )

    op.add_column(
        "scans", sa.Column("gmail_connection_id", sa.Integer(), nullable=True)
    )
    op.add_column(
        "scans", sa.Column("gmail_message_id", sa.String(length=120), nullable=True)
    )
    op.add_column(
        "scans", sa.Column("gmail_thread_id", sa.String(length=120), nullable=True)
    )
    op.add_column(
        "scans", sa.Column("gmail_history_id", sa.String(length=50), nullable=True)
    )

    op.create_index(
        op.f("ix_scans_gmail_connection_id"),
        "scans",
        ["gmail_connection_id"],
        unique=False,
    )
    op.create_index(
        "uq_scans_gmail_message",
        "scans",
        ["gmail_connection_id", "gmail_message_id"],
        unique=True,
        sqlite_where=sa.text("source = 'gmail' AND gmail_message_id IS NOT NULL"),
        postgresql_where=sa.text("source = 'gmail' AND gmail_message_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_scans_gmail_message", table_name="scans")
    op.drop_index(op.f("ix_scans_gmail_connection_id"), table_name="scans")
    op.drop_column("scans", "gmail_history_id")
    op.drop_column("scans", "gmail_thread_id")
    op.drop_column("scans", "gmail_message_id")
    op.drop_column("scans", "gmail_connection_id")

    op.drop_column("gmail_connections", "sync_lock_acquired_at")
    op.drop_column("gmail_connections", "sync_in_progress")
