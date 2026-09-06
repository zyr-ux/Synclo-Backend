"""v1 baseline consolidated schema

Revision ID: 0001_v1_baseline
Revises: 
Create Date: 2026-09-05 03:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0001_v1_baseline'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('username', sa.String(), nullable=True),
        sa.Column('auth_key_hash', sa.String(), nullable=False),
        sa.Column('encrypted_master_key', sa.LargeBinary(), nullable=False),
        sa.Column('salt', sa.LargeBinary(), nullable=False),
        sa.Column('kdf_version', sa.Integer(), server_default='1', nullable=False),
        sa.Column('recovery_wrapped_master_key', sa.LargeBinary(), nullable=False),
        sa.Column('recovery_key_verifier', sa.String(), nullable=False),
        sa.Column('session_epoch', sa.Integer(), server_default='1', nullable=False),
        sa.Column('sync_sequence', sa.Integer(), server_default='0', nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
    op.create_index(op.f('ix_users_user_id'), 'users', ['user_id'], unique=True)
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)

    # 2. devices table
    op.create_table(
        'devices',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('device_id', sa.String(), nullable=False),
        sa.Column('device_name', sa.String(), nullable=True),
        sa.Column('os', sa.String(), nullable=True),
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('push_subscription', sa.String(), nullable=True),
        sa.Column('push_subscription_updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.user_id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'device_id', name='uq_device_user_id_device_id'),
    )
    op.create_index(op.f('ix_devices_id'), 'devices', ['id'], unique=False)
    op.create_index(op.f('ix_devices_device_id'), 'devices', ['device_id'], unique=False)
    op.create_index(op.f('ix_devices_user_id'), 'devices', ['user_id'], unique=False)
    op.create_index(op.f('ix_devices_last_seen'), 'devices', ['last_seen'], unique=False)

    # 3. refresh_tokens table
    op.create_table(
        'refresh_tokens',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('token', sa.String(), nullable=False),
        sa.Column('expiry', sa.DateTime(timezone=True), nullable=False),
        sa.Column('device_id', sa.String(), nullable=False),
        sa.Column('token_id', sa.String(), nullable=False),
        sa.Column('is_revoked', sa.Boolean(), server_default='0', nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.user_id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_refresh_tokens_id'), 'refresh_tokens', ['id'], unique=False)
    op.create_index(op.f('ix_refresh_tokens_token'), 'refresh_tokens', ['token'], unique=True)
    op.create_index(op.f('ix_refresh_tokens_expiry'), 'refresh_tokens', ['expiry'], unique=False)
    op.create_index(op.f('ix_refresh_tokens_token_id'), 'refresh_tokens', ['token_id'], unique=False)

    # 4. blacklisted_tokens table
    op.create_table(
        'blacklisted_tokens',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('token', sa.String(), nullable=False),
        sa.Column('expiry', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token'),
    )
    op.create_index(op.f('ix_blacklisted_tokens_id'), 'blacklisted_tokens', ['id'], unique=False)
    op.create_index(op.f('ix_blacklisted_tokens_expiry'), 'blacklisted_tokens', ['expiry'], unique=False)

    # 5. clipboard table
    op.create_table(
        'clipboard',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('clipboard_id', sa.String(), nullable=False),
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('ciphertext', sa.LargeBinary(), nullable=True),
        sa.Column('nonce', sa.LargeBinary(), nullable=True),
        sa.Column('blob_version', sa.Integer(), server_default='1', nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), server_default='0', nullable=False),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_pinned', sa.Boolean(), server_default='0', nullable=False),
        sa.Column('pinned_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('change_number', sa.Integer(), server_default='0', nullable=False),
        sa.Column('entry_revision', sa.Integer(), server_default='1', nullable=False),
        sa.Column('last_device_id', sa.String(), nullable=True),
        sa.CheckConstraint('(is_deleted = 0 AND deleted_at IS NULL) OR (is_deleted = 1 AND deleted_at IS NOT NULL)', name='chk_clipboard_deleted_state'),
        sa.CheckConstraint('(ciphertext IS NULL AND nonce IS NULL) OR (ciphertext IS NOT NULL AND nonce IS NOT NULL)', name='chk_clipboard_payload_pair'),
        sa.CheckConstraint('NOT (is_deleted = 1 AND is_pinned = 1)', name='chk_clipboard_deleted_not_pinned'),
        sa.CheckConstraint('NOT (is_pinned = 1 AND pinned_at IS NULL)', name='chk_clipboard_pinned_has_timestamp'),
        sa.ForeignKeyConstraint(['user_id'], ['users.user_id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'clipboard_id', name='uq_clipboard_user_id_clipboard_id'),
    )
    op.create_index(op.f('ix_clipboard_id'), 'clipboard', ['id'], unique=False)
    op.create_index(op.f('ix_clipboard_clipboard_id'), 'clipboard', ['clipboard_id'], unique=False)
    op.create_index(op.f('ix_clipboard_user_id'), 'clipboard', ['user_id'], unique=False)
    op.create_index(op.f('ix_clipboard_timestamp'), 'clipboard', ['timestamp'], unique=False)
    op.create_index(op.f('ix_clipboard_is_deleted'), 'clipboard', ['is_deleted'], unique=False)
    op.create_index(op.f('ix_clipboard_deleted_at'), 'clipboard', ['deleted_at'], unique=False)
    op.create_index(op.f('ix_clipboard_is_pinned'), 'clipboard', ['is_pinned'], unique=False)
    op.create_index(op.f('ix_clipboard_pinned_at'), 'clipboard', ['pinned_at'], unique=False)
    op.create_index(op.f('ix_clipboard_updated_at'), 'clipboard', ['updated_at'], unique=False)
    op.create_index('ix_clipboard_user_change_number', 'clipboard', ['user_id', 'change_number'], unique=False)
    op.create_index('ix_clipboard_user_deleted_at', 'clipboard', ['user_id', 'is_deleted', 'deleted_at'], unique=False)


def downgrade() -> None:
    op.drop_table('clipboard')
    op.drop_table('blacklisted_tokens')
    op.drop_table('refresh_tokens')
    op.drop_table('devices')
    op.drop_table('users')
