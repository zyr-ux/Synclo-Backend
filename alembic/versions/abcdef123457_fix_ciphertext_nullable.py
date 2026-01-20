"""Fix ciphertext and nonce nullable with batch operations

Revision ID: abcdef123457
Revises: abcdef123456
Create Date: 2026-01-18 20:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "abcdef123457"
down_revision: Union[str, Sequence[str], None] = "abcdef123456"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("clipboard") as batch_op:
        batch_op.alter_column(
            "ciphertext",
            existing_type=sa.LargeBinary(),
            nullable=True,
        )
        batch_op.alter_column(
            "nonce",
            existing_type=sa.LargeBinary(),
            nullable=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("clipboard") as batch_op:
        batch_op.alter_column(
            "ciphertext",
            existing_type=sa.LargeBinary(),
            nullable=False,
        )
        batch_op.alter_column(
            "nonce",
            existing_type=sa.LargeBinary(),
            nullable=False,
        )
