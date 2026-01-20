"""add tombstone fields

Revision ID: a1b2c3d4e5f6
Revises: f9a1b2c3d4e5
Create Date: 2026-01-18 13:35:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = 'f9a1b2c3d4e5'
branch_labels = None
depends_on = None


def upgrade():
    # Add columns with default values
    op.add_column('clipboard', sa.Column('is_deleted', sa.Boolean(), nullable=True))
    op.add_column('clipboard', sa.Column('deleted_at', sa.DateTime(), nullable=True))
    
    # Create indexes
    op.create_index(op.f('ix_clipboard_is_deleted'), 'clipboard', ['is_deleted'], unique=False)
    op.create_index(op.f('ix_clipboard_deleted_at'), 'clipboard', ['deleted_at'], unique=False)
    
    # Backfill existing records
    op.execute("UPDATE clipboard SET is_deleted = 0")
    
    # Make is_deleted non-nullable after backfill (sqlite specific workaround not strict needed here but good practice)
    # SQLite doesn't support ALTER COLUMN SET NOT NULL well, but for other DBs:
    # with op.batch_alter_table('clipboard') as batch_op:
    #     batch_op.alter_column('is_deleted', nullable=False)


def downgrade():
    op.drop_index(op.f('ix_clipboard_deleted_at'), table_name='clipboard')
    op.drop_index(op.f('ix_clipboard_is_deleted'), table_name='clipboard')
    op.drop_column('clipboard', 'deleted_at')
    op.drop_column('clipboard', 'is_deleted')
