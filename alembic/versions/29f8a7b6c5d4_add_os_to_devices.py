"""add os to devices

Revision ID: 29f8a7b6c5d4
Revises: f9a1b2c3d4e5
Create Date: 2026-02-15 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '29f8a7b6c5d4'
down_revision: Union[str, Sequence[str], None] = 'be3b0384c069'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('devices', sa.Column('os', sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column('devices', 'os')
