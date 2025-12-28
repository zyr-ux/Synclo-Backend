"""Migrate to E2EE model

Revision ID: d4e7b3f8c2a1
Revises: c8a9f2d9b3a1
Create Date: 2025-12-28

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'd4e7b3f8c2a1'
down_revision: Union[str, Sequence[str], None] = 'c8a9f2d9b3a1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add E2EE fields to users table (only if they don't already exist)
    try:
        op.add_column('users', sa.Column('encrypted_master_key', sa.LargeBinary(), nullable=True))
    except Exception:
        pass
    
    try:
        op.add_column('users', sa.Column('salt', sa.LargeBinary(), nullable=True))
    except Exception:
        pass
    
    try:
        op.add_column('users', sa.Column('kdf_version', sa.Integer(), nullable=False, server_default='1'))
    except Exception:
        pass
    
    # Drop encryption_keys table (server no longer holds keys)
    try:
        op.drop_table('encryption_keys')
    except Exception:
        pass
    
    # Rename clipboard columns for E2EE semantics
    try:
        op.alter_column('clipboard', 'id', new_column_name='index')
    except Exception:
        pass
    
    try:
        op.alter_column('clipboard', 'uid', new_column_name='id')
    except Exception:
        pass
    
    try:
        op.alter_column('clipboard', 'encrypted_data', new_column_name='ciphertext')
    except Exception:
        pass
    
    # Add blob_version to clipboard
    try:
        op.add_column('clipboard', sa.Column('blob_version', sa.Integer(), nullable=False, server_default='1'))
    except Exception:
        pass


def downgrade() -> None:
    # Reverse clipboard changes
    op.drop_column('clipboard', 'blob_version')
    op.alter_column('clipboard', 'ciphertext', new_column_name='encrypted_data')
    op.alter_column('clipboard', 'id', new_column_name='uid')
    op.alter_column('clipboard', 'index', new_column_name='id')
    
    # Recreate encryption_keys table
    op.create_table('encryption_keys',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('key', sa.LargeBinary(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id')
    )
    op.create_index(op.f('ix_encryption_keys_id'), 'encryption_keys', ['id'], unique=False)
    
    # Remove E2EE fields from users
    op.drop_column('users', 'kdf_version')
    op.drop_column('users', 'salt')
    op.drop_column('users', 'encrypted_master_key')
