"""add prediction_confidence to scans

Revision ID: 08b35ecd1585
Revises: f62b628adb3f
Create Date: 2026-07-17 22:00:18.874769

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '08b35ecd1585'
down_revision: Union[str, Sequence[str], None] = 'f62b628adb3f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Adds prediction_confidence (nullable) rather than renaming or
    repurposing the existing confidence_score column, which despite its
    name has always stored the phishing probability, not prediction
    confidence -- existing rows and any code still reading
    confidence_score keep working unchanged. Nullable because old rows
    predate this column; Scan.to_dict() derives a value for them on read
    (max(confidence_score, 1 - confidence_score)) instead of backfilling.
    """
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('prediction_confidence', sa.Float(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.drop_column('prediction_confidence')
