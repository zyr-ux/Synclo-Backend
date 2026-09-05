"""Replace hashed_password with auth_key_hash for zero-knowledge auth

Revision ID: e5f2g4h9d3b2
Revises: d4e7b3f8c2a1
Create Date: 2025-12-28

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'e5f2g4h9d3b2'
down_revision: Union[str, Sequence[str], None] = 'd4e7b3f8c2a1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Drop hashed_password column from users (wrapped in try-except)
    try:
        op.drop_column('users', 'hashed_password')
    except Exception:
        pass
    
    # Add auth_key_hash column for bcrypt-hashed auth key (wrapped in try-except)
    try:
        op.add_column('users', sa.Column('auth_key_hash', sa.String(), nullable=False, server_default=''))
    except Exception:
        pass


def downgrade() -> None:
    # Remove auth_key_hash column (wrapped in try-except)
    try:
        op.drop_column('users', 'auth_key_hash')
    except Exception:
        pass
    
    # Restore hashed_password column (wrapped in try-except)
    try:
        op.add_column('users', sa.Column('hashed_password', sa.String(), nullable=False, server_default=''))
    except Exception:
        pass
