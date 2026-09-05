"""add_pinned_at_and_last_seen

Revision ID: a7b8c9d0e1f2
Revises: 90b1900db2f2
Create Date: 2026-08-20 23:31:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7b8c9d0e1f2'
down_revision: Union[str, Sequence[str], None] = '90b1900db2f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('clipboard', schema=None) as batch_op:
        batch_op.add_column(sa.Column('pinned_at', sa.DateTime(), nullable=True))
        batch_op.create_index(batch_op.f('ix_clipboard_pinned_at'), ['pinned_at'], unique=False)

    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.add_column(sa.Column('last_seen', sa.DateTime(), nullable=True))
        batch_op.create_index(batch_op.f('ix_devices_last_seen'), ['last_seen'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_devices_last_seen'))
        batch_op.drop_column('last_seen')

    with op.batch_alter_table('clipboard', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_clipboard_pinned_at'))
        batch_op.drop_column('pinned_at')
