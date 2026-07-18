"""add email_reports table

Revision ID: c3f0a6b8d21e
Revises: b2d8e4a1c9f3
Create Date: 2026-07-18 15:10:00.000000

Additive: new email_reports table backing employee `.eml` reporting
(models.EmailReport). No existing table is touched; the seeded database and
all prior rows are unaffected.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c3f0a6b8d21e"
down_revision: Union[str, Sequence[str], None] = "b2d8e4a1c9f3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "email_reports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("reporter_user_id", sa.Integer(), nullable=False),
        sa.Column("reporter_username", sa.String(length=80), nullable=True),
        sa.Column("filename", sa.String(length=255), nullable=True),
        sa.Column("stored_path", sa.String(length=500), nullable=True),
        sa.Column("scan_id", sa.String(length=20), nullable=True),
        sa.Column(
            "status", sa.String(length=20), nullable=False, server_default="pending"
        ),
        sa.Column("admin_verdict", sa.String(length=20), nullable=True),
        sa.Column("reviewed_by", sa.String(length=80), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["reporter_user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.scan_id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_email_reports_reporter_user_id"),
        "email_reports",
        ["reporter_user_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_email_reports_status"), "email_reports", ["status"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_email_reports_status"), table_name="email_reports")
    op.drop_index(op.f("ix_email_reports_reporter_user_id"), table_name="email_reports")
    op.drop_table("email_reports")
