"""use_timezone_aware_datetimes

Revision ID: 967bec859da9
Revises: a7b8c9d0e1f2
Create Date: 2026-08-21 09:36:31.472943

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '967bec859da9'
down_revision: Union[str, Sequence[str], None] = 'a7b8c9d0e1f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.alter_column('last_seen', type_=sa.DateTime(timezone=True), existing_type=sa.DateTime(), existing_nullable=True)

    with op.batch_alter_table('clipboard', schema=None) as batch_op:
        batch_op.alter_column('timestamp', type_=sa.DateTime(timezone=True), existing_type=sa.DateTime(), existing_nullable=True)
        batch_op.alter_column('deleted_at', type_=sa.DateTime(timezone=True), existing_type=sa.DateTime(), existing_nullable=True)
        batch_op.alter_column('pinned_at', type_=sa.DateTime(timezone=True), existing_type=sa.DateTime(), existing_nullable=True)
        batch_op.alter_column('updated_at', type_=sa.DateTime(timezone=True), existing_type=sa.DateTime(), existing_nullable=False)

    with op.batch_alter_table('refresh_tokens', schema=None) as batch_op:
        batch_op.alter_column('expiry', type_=sa.DateTime(timezone=True), existing_type=sa.DateTime(), existing_nullable=True)

    with op.batch_alter_table('blacklisted_tokens', schema=None) as batch_op:
        batch_op.alter_column('expiry', type_=sa.DateTime(timezone=True), existing_type=sa.DateTime(), existing_nullable=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('blacklisted_tokens', schema=None) as batch_op:
        batch_op.alter_column('expiry', type_=sa.DateTime(), existing_type=sa.DateTime(timezone=True), existing_nullable=False)

    with op.batch_alter_table('refresh_tokens', schema=None) as batch_op:
        batch_op.alter_column('expiry', type_=sa.DateTime(), existing_type=sa.DateTime(timezone=True), existing_nullable=True)

    with op.batch_alter_table('clipboard', schema=None) as batch_op:
        batch_op.alter_column('updated_at', type_=sa.DateTime(), existing_type=sa.DateTime(timezone=True), existing_nullable=False)
        batch_op.alter_column('pinned_at', type_=sa.DateTime(), existing_type=sa.DateTime(timezone=True), existing_nullable=True)
        batch_op.alter_column('deleted_at', type_=sa.DateTime(), existing_type=sa.DateTime(timezone=True), existing_nullable=True)
        batch_op.alter_column('timestamp', type_=sa.DateTime(), existing_type=sa.DateTime(timezone=True), existing_nullable=True)

    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.alter_column('last_seen', type_=sa.DateTime(), existing_type=sa.DateTime(timezone=True), existing_nullable=True)
