"""add_recovery_key_fields

Revision ID: 8b9c0d1e2f3a
Revises: 7a8b9c0d1e2f
Create Date: 2026-09-03 20:07:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '8b9c0d1e2f3a'
down_revision: Union[str, Sequence[str], None] = '7a8b9c0d1e2f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('recovery_wrapped_master_key', sa.LargeBinary(), nullable=False, server_default=sa.text("''")))
        batch_op.add_column(sa.Column('recovery_key_verifier', sa.String(), nullable=False, server_default=''))


def downgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('recovery_key_verifier')
        batch_op.drop_column('recovery_wrapped_master_key')
