"""add_is_pinned_to_clipboard

Revision ID: c6d45a76a2b6
Revises: 29f8a7b6c5d4
Create Date: 2026-06-23 12:46:28.136554

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c6d45a76a2b6'
down_revision: Union[str, Sequence[str], None] = '29f8a7b6c5d4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add column with server_default for sqlite compatibility and to backfill existing records
    op.add_column('clipboard', sa.Column('is_pinned', sa.Boolean(), nullable=False, server_default='0'))
    # Create index
    op.create_index(op.f('ix_clipboard_is_pinned'), 'clipboard', ['is_pinned'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_clipboard_is_pinned'), table_name='clipboard')
    op.drop_column('clipboard', 'is_pinned')
