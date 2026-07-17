"""mailbox sync lock and unique mailbox_uid index

Revision ID: 3bf198b6ab98
Revises: 08b35ecd1585
Create Date: 2026-07-17 22:10:57.334722

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3bf198b6ab98'
down_revision: Union[str, Sequence[str], None] = '08b35ecd1585'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    - mailbox_status gets a DB-backed sync lock (sync_in_progress +
      sync_lock_acquired_at) so the Celery-Beat-scheduled sync and a
      manual admin "Sync now" click can't run concurrently.
    - scans' plain ix_scans_mailbox_uid index is replaced with a partial
      UNIQUE index (mailbox_uid, filtered to source='mailbox' AND
      mailbox_uid IS NOT NULL so 'manual' scans' NULL mailbox_uid never
      collides) -- the DB-level backstop against a duplicate mailbox
      message ever being recorded twice, even if the lock above is
      bypassed. Verified against the existing seeded database before
      writing this: no source='mailbox' rows share a mailbox_uid, so this
      is safe to apply as-is with no data cleanup needed.
    """
    with op.batch_alter_table('mailbox_status', schema=None) as batch_op:
        batch_op.add_column(sa.Column('sync_in_progress', sa.Boolean(), nullable=True, server_default=sa.false()))
        batch_op.add_column(sa.Column('sync_lock_acquired_at', sa.DateTime(), nullable=True))

    op.drop_index(op.f('ix_scans_mailbox_uid'), table_name='scans')
    op.create_index(
        'uq_scans_mailbox_uid', 'scans', ['mailbox_uid'], unique=True,
        sqlite_where=sa.text("source = 'mailbox' AND mailbox_uid IS NOT NULL"),
        postgresql_where=sa.text("source = 'mailbox' AND mailbox_uid IS NOT NULL"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('uq_scans_mailbox_uid', table_name='scans')
    op.create_index(op.f('ix_scans_mailbox_uid'), 'scans', ['mailbox_uid'], unique=False)

    with op.batch_alter_table('mailbox_status', schema=None) as batch_op:
        batch_op.drop_column('sync_lock_acquired_at')
        batch_op.drop_column('sync_in_progress')
