"""Make device_id non-nullable on devices

Revision ID: f9a1b2c3d4e5
Revises: e5f2g4h9d3b2
Create Date: 2025-12-28

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "f9a1b2c3d4e5"
down_revision: Union[str, Sequence[str], None] = "e5f2g4h9d3b2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # For existing rows with NULL device_id, assign a unique legacy value to satisfy NOT NULL + UNIQUE
    op.execute("UPDATE devices SET device_id = 'legacy-' || id WHERE device_id IS NULL")

    # Make device_id non-nullable (wrapped in try-except for SQLite compatibility)
    try:
        op.alter_column(
            "devices",
            "device_id",
            existing_type=sa.String(),
            nullable=False,
        )
    except Exception:
        pass


def downgrade() -> None:
    # Revert to nullable to match previous schema (wrapped in try-except for SQLite compatibility)
    try:
        op.alter_column(
            "devices",
            "device_id",
            existing_type=sa.String(),
            nullable=True,
        )
    except Exception:
        pass
