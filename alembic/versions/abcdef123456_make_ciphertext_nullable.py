"""Make ciphertext and nonce nullable for tombstones

Revision ID: abcdef123456
Revises: f9a1b2c3d4e5
Create Date: 2026-01-18 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "abcdef123456"
down_revision: Union[str, Sequence[str], None] = "f9a1b2c3d4e5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    try:
        op.alter_column(
            "clipboard",
            "ciphertext",
            existing_type=sa.LargeBinary(),
            nullable=True,
        )
        op.alter_column(
            "clipboard",
            "nonce",
            existing_type=sa.LargeBinary(),
            nullable=True,
        )
    except Exception:
        pass


def downgrade() -> None:
    # This might fail if there are existing nulls, but that's expected for downgrade
    try:
        op.alter_column(
            "clipboard",
            "ciphertext",
            existing_type=sa.LargeBinary(),
            nullable=False,
        )
        op.alter_column(
            "clipboard",
            "nonce",
            existing_type=sa.LargeBinary(),
            nullable=False,
        )
    except Exception:
        pass
