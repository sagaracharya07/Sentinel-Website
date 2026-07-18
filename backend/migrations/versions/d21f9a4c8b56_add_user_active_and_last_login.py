"""add user is_active and last_login_at

Revision ID: d21f9a4c8b56
Revises: c3f0a6b8d21e
Create Date: 2026-07-19 09:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "d21f9a4c8b56"
down_revision: Union[str, Sequence[str], None] = "c3f0a6b8d21e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # batch_alter_table for SQLite/Postgres portability (see
    # f62b628adb3f for why). server_default=true is required, not optional:
    # the users table already has rows (seeded demo accounts) by the time
    # this runs, and a NOT NULL column with no default crashes against them.
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "is_active", sa.Boolean(), nullable=False, server_default=sa.true()
            )
        )
        batch_op.add_column(sa.Column("last_login_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_column("last_login_at")
        batch_op.drop_column("is_active")
