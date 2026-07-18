"""add gmail_connections table

Revision ID: a1c7f2e9b4d0
Revises: 3bf198b6ab98
Create Date: 2026-07-18 13:30:00.000000

Adds the GmailConnection table backing the Google OAuth / connected-mailbox
integration (models.GmailConnection). No existing table is altered, so this
is additive and safe against the seeded database -- the prior schema and all
seeded users/scans/audit rows are untouched.

Refresh/access tokens are stored ENCRYPTED (see crypto.py); the columns hold
ciphertext, never plaintext credentials.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "a1c7f2e9b4d0"
down_revision: Union[str, Sequence[str], None] = "3bf198b6ab98"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "gmail_connections",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("owner_user_id", sa.Integer(), nullable=True),
        sa.Column(
            "provider", sa.String(length=20), nullable=False, server_default="gmail"
        ),
        sa.Column("mailbox_email", sa.String(length=255), nullable=True),
        sa.Column("provider_account_id", sa.String(length=255), nullable=True),
        sa.Column("encrypted_refresh_token", sa.Text(), nullable=True),
        sa.Column("encrypted_access_token", sa.Text(), nullable=True),
        sa.Column("token_expiry", sa.DateTime(), nullable=True),
        sa.Column("granted_scopes", sa.Text(), nullable=True),
        sa.Column(
            "connection_status",
            sa.String(length=20),
            nullable=False,
            server_default="connected",
        ),
        sa.Column(
            "protection_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column(
            "monitoring_mode",
            sa.String(length=20),
            nullable=True,
            server_default="polling",
        ),
        sa.Column("last_successful_sync_at", sa.DateTime(), nullable=True),
        sa.Column("last_attempted_sync_at", sa.DateTime(), nullable=True),
        sa.Column("last_history_id", sa.String(length=50), nullable=True),
        sa.Column("last_watch_expiration", sa.DateTime(), nullable=True),
        sa.Column("last_error_code", sa.String(length=60), nullable=True),
        sa.Column("last_error_message", sa.Text(), nullable=True),
        sa.Column("processed_label_id", sa.String(length=120), nullable=True),
        sa.Column("needs_review_label_id", sa.String(length=120), nullable=True),
        sa.Column("quarantine_label_id", sa.String(length=120), nullable=True),
        sa.Column("scan_failed_label_id", sa.String(length=120), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("disconnected_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_gmail_connections_owner_user_id"),
        "gmail_connections",
        ["owner_user_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_gmail_connections_mailbox_email"),
        "gmail_connections",
        ["mailbox_email"],
        unique=False,
    )
    op.create_index(
        "ix_gmail_connections_connection_status",
        "gmail_connections",
        ["connection_status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_gmail_connections_connection_status", table_name="gmail_connections"
    )
    op.drop_index(
        op.f("ix_gmail_connections_mailbox_email"), table_name="gmail_connections"
    )
    op.drop_index(
        op.f("ix_gmail_connections_owner_user_id"), table_name="gmail_connections"
    )
    op.drop_table("gmail_connections")
