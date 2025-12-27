"""Add index on blacklisted_tokens.expiry

Revision ID: c8a9f2d9b3a1
Revises: 6a7fa00af237
Create Date: 2025-12-27

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c8a9f2d9b3a1'
down_revision: Union[str, Sequence[str], None] = '6a7fa00af237'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        'ix_blacklisted_tokens_expiry',
        'blacklisted_tokens',
        ['expiry'],
        unique=False
    )


def downgrade() -> None:
    op.drop_index('ix_blacklisted_tokens_expiry', table_name='blacklisted_tokens')
