"""add_updated_at_to_clipboard

Revision ID: be3b0384c069
Revises: abcdef123457
Create Date: 2026-02-11 00:10:30.305978

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'be3b0384c069'
down_revision: Union[str, Sequence[str], None] = 'abcdef123457'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add column as nullable first
    op.add_column('clipboard', sa.Column('updated_at', sa.DateTime(), nullable=True))
    
    # 2. Backfill existing records (use creation timestamp as initial updated_at)
    op.execute('UPDATE clipboard SET updated_at = timestamp')
    
    # 3. Alter column to be non-nullable
    # SQLite has limited ALTER TABLE support, so we often need batch_alter_table for these operations
    # However, since we just added it, let's try standard alter first, or rely on naming convention if using limitations
    # For SQLite compatibility with batch operations:
    with op.batch_alter_table('clipboard') as batch_op:
        batch_op.alter_column('updated_at', nullable=False)
        batch_op.create_index(batch_op.f('ix_clipboard_updated_at'), ['updated_at'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('clipboard') as batch_op:
        batch_op.drop_index(batch_op.f('ix_clipboard_updated_at'))
        batch_op.drop_column('updated_at')
