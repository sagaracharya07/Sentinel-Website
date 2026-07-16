"""add email verification and password reset fields to users

Revision ID: f62b628adb3f
Revises: 7062cd9cb800
Create Date: 2026-07-16 21:02:15.266783

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f62b628adb3f'
down_revision: Union[str, Sequence[str], None] = '7062cd9cb800'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # batch_alter_table (not raw op.add_column/op.create_unique_constraint)
    # because this needs to work on both SQLite (local dev -- can't ALTER
    # TABLE ADD CONSTRAINT directly, only via batch/table-recreation) and
    # Postgres (docker-compose/Render). server_default=false on
    # email_verified is required, not optional: the users table already
    # has rows (the seeded demo accounts) by the time this runs, and a
    # NOT NULL column with no default crashes against existing rows.
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('email', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('email_verified', sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column('verification_token', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('verification_token_expires', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('reset_token', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('reset_token_expires', sa.DateTime(), nullable=True))
        batch_op.create_unique_constraint('uq_users_email', ['email'])


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_constraint('uq_users_email', type_='unique')
        batch_op.drop_column('reset_token_expires')
        batch_op.drop_column('reset_token')
        batch_op.drop_column('verification_token_expires')
        batch_op.drop_column('verification_token')
        batch_op.drop_column('email_verified')
        batch_op.drop_column('email')
