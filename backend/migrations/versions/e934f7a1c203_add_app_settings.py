"""add app_settings table (detection policy thresholds)

Revision ID: e934f7a1c203
Revises: d21f9a4c8b56
Create Date: 2026-07-19 09:05:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "e934f7a1c203"
down_revision: Union[str, Sequence[str], None] = "d21f9a4c8b56"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "app_settings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column(
            "needs_review_threshold", sa.Float(), nullable=False, server_default="0.5"
        ),
        sa.Column(
            "phishing_threshold", sa.Float(), nullable=False, server_default="0.75"
        ),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("updated_by", sa.String(length=80), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("app_settings")
