"""cleanup_schema_renames_and_uuids

Revision ID: 3614a04efe0e
Revises: c6d45a76a2b6
Create Date: 2026-06-24 00:40:44.620333

"""
from typing import Sequence, Union
import uuid

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3614a04efe0e'
down_revision: Union[str, Sequence[str], None] = 'c6d45a76a2b6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    
    # 1. Load existing data in memory
    users_data = conn.execute(sa.text("SELECT id, email, auth_key_hash, encrypted_master_key, salt, kdf_version FROM users")).fetchall()
    devices_data = conn.execute(sa.text("SELECT id, device_id, device_name, os, user_id FROM devices")).fetchall()
    clipboard_data = conn.execute(sa.text("SELECT `index`, id, user_id, ciphertext, nonce, blob_version, timestamp, is_deleted, deleted_at, is_pinned, updated_at FROM clipboard")).fetchall()
    refresh_tokens_data = conn.execute(sa.text("SELECT id, user_id, token, expiry, device_id, family_id, is_revoked FROM refresh_tokens")).fetchall()
    
    # 2. Drop tables in correct order
    op.drop_table('refresh_tokens')
    op.drop_table('clipboard')
    op.drop_table('devices')
    op.drop_table('users')
    
    # 3. Create tables with new schema (foreign keys reference users.user_id as String)
    op.create_table('users',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('auth_key_hash', sa.String(), nullable=False),
        sa.Column('encrypted_master_key', sa.LargeBinary(), nullable=False),
        sa.Column('salt', sa.LargeBinary(), nullable=False),
        sa.Column('kdf_version', sa.Integer(), nullable=False, server_default='1'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_users_id', 'users', ['id'], unique=False)
    op.create_index('ix_users_user_id', 'users', ['user_id'], unique=True)
    op.create_index('ix_users_email', 'users', ['email'], unique=True)

    op.create_table('devices',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('device_id', sa.String(), nullable=False),
        sa.Column('device_name', sa.String(), nullable=True),
        sa.Column('os', sa.String(), nullable=True),
        sa.Column('user_id', sa.String(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_devices_id', 'devices', ['id'], unique=False)
    op.create_index('ix_devices_device_id', 'devices', ['device_id'], unique=True)
    op.create_index('ix_devices_user_id', 'devices', ['user_id'], unique=False)

    op.create_table('clipboard',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('clipboard_id', sa.String(), nullable=False),
        sa.Column('user_id', sa.String(), nullable=True),
        sa.Column('ciphertext', sa.LargeBinary(), nullable=True),
        sa.Column('nonce', sa.LargeBinary(), nullable=True),
        sa.Column('blob_version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('is_deleted', sa.Boolean(), nullable=True),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.Column('is_pinned', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_clipboard_id', 'clipboard', ['id'], unique=False)
    op.create_index('ix_clipboard_clipboard_id', 'clipboard', ['clipboard_id'], unique=True)
    op.create_index('ix_clipboard_is_deleted', 'clipboard', ['is_deleted'], unique=False)
    op.create_index('ix_clipboard_deleted_at', 'clipboard', ['deleted_at'], unique=False)
    op.create_index('ix_clipboard_is_pinned', 'clipboard', ['is_pinned'], unique=False)
    op.create_index('ix_clipboard_updated_at', 'clipboard', ['updated_at'], unique=False)

    op.create_table('refresh_tokens',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.String(), nullable=True),
        sa.Column('token', sa.String(), nullable=True),
        sa.Column('expiry', sa.DateTime(), nullable=True),
        sa.Column('device_id', sa.String(), nullable=False),
        sa.Column('token_id', sa.String(), nullable=False),
        sa.Column('is_revoked', sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_refresh_tokens_id', 'refresh_tokens', ['id'], unique=False)
    op.create_index('ix_refresh_tokens_token', 'refresh_tokens', ['token'], unique=True)
    op.create_index('ix_refresh_tokens_expiry', 'refresh_tokens', ['expiry'], unique=False)
    op.create_index('ix_refresh_tokens_token_id', 'refresh_tokens', ['token_id'], unique=False)

    # 4. Generate user_id mapping
    id_map = {}
    for u in users_data:
        u_id, u_email, u_hash, u_emk, u_salt, u_kdf = u
        u_uuid = str(uuid.uuid4())
        id_map[u_id] = u_uuid
        
        # Insert user
        conn.execute(
            sa.text("INSERT INTO users (id, user_id, email, auth_key_hash, encrypted_master_key, salt, kdf_version) VALUES (:id, :user_id, :email, :auth_key_hash, :encrypted_master_key, :salt, :kdf_version)"),
            {"id": u_id, "user_id": u_uuid, "email": u_email, "auth_key_hash": u_hash, "encrypted_master_key": u_emk, "salt": u_salt, "kdf_version": u_kdf}
        )

    # 5. Insert child tables mapping integer user_id to user_id UUID string
    for d in devices_data:
        d_id, d_devid, d_name, d_os, d_uid = d
        new_user_id = id_map.get(d_uid)
        conn.execute(
            sa.text("INSERT INTO devices (id, device_id, device_name, os, user_id) VALUES (:id, :device_id, :device_name, :os, :user_id)"),
            {"id": d_id, "device_id": d_devid, "device_name": d_name, "os": d_os, "user_id": new_user_id}
        )

    for c in clipboard_data:
        c_index, c_id, c_uid, c_ct, c_nonce, c_bv, c_ts, c_del, c_delat, c_pin, c_up = c
        new_user_id = id_map.get(c_uid)
        conn.execute(
            sa.text("INSERT INTO clipboard (id, clipboard_id, user_id, ciphertext, nonce, blob_version, timestamp, is_deleted, deleted_at, is_pinned, updated_at) VALUES (:id, :clipboard_id, :user_id, :ciphertext, :nonce, :blob_version, :timestamp, :is_deleted, :deleted_at, :is_pinned, :updated_at)"),
            {
                "id": c_index,
                "clipboard_id": c_id,
                "user_id": new_user_id,
                "ciphertext": c_ct,
                "nonce": c_nonce,
                "blob_version": c_bv,
                "timestamp": c_ts,
                "is_deleted": c_del,
                "deleted_at": c_delat,
                "is_pinned": c_pin,
                "updated_at": c_up
            }
        )

    for r in refresh_tokens_data:
        r_id, r_uid, r_token, r_exp, r_devid, r_famid, r_rev = r
        new_user_id = id_map.get(r_uid)
        conn.execute(
            sa.text("INSERT INTO refresh_tokens (id, user_id, token, expiry, device_id, token_id, is_revoked) VALUES (:id, :user_id, :token, :expiry, :device_id, :token_id, :is_revoked)"),
            {"id": r_id, "user_id": new_user_id, "token": r_token, "expiry": r_exp, "device_id": r_devid, "token_id": r_famid, "is_revoked": r_rev}
        )


def downgrade() -> None:
    conn = op.get_bind()
    
    # 1. Load existing data in memory
    users_data = conn.execute(sa.text("SELECT id, user_id, email, auth_key_hash, encrypted_master_key, salt, kdf_version FROM users")).fetchall()
    devices_data = conn.execute(sa.text("SELECT id, device_id, device_name, os, user_id FROM devices")).fetchall()
    clipboard_data = conn.execute(sa.text("SELECT id, clipboard_id, user_id, ciphertext, nonce, blob_version, timestamp, is_deleted, deleted_at, is_pinned, updated_at FROM clipboard")).fetchall()
    refresh_tokens_data = conn.execute(sa.text("SELECT id, user_id, token, expiry, device_id, token_id, is_revoked FROM refresh_tokens")).fetchall()
    
    # 2. Drop tables in correct order
    op.drop_table('refresh_tokens')
    op.drop_table('clipboard')
    op.drop_table('devices')
    op.drop_table('users')
    
    # 3. Recreate old tables
    op.create_table('users',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('auth_key_hash', sa.String(), nullable=False),
        sa.Column('encrypted_master_key', sa.LargeBinary(), nullable=False),
        sa.Column('salt', sa.LargeBinary(), nullable=False),
        sa.Column('kdf_version', sa.Integer(), nullable=False, server_default='1'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_users_id', 'users', ['id'], unique=False)
    op.create_index('ix_users_email', 'users', ['email'], unique=True)

    op.create_table('devices',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('device_id', sa.String(), nullable=False),
        sa.Column('device_name', sa.String(), nullable=True),
        sa.Column('os', sa.String(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_devices_id', 'devices', ['id'], unique=False)
    op.create_index('ix_devices_device_id', 'devices', ['device_id'], unique=True)
    op.create_index('ix_devices_user_id', 'devices', ['user_id'], unique=False)

    op.create_table('clipboard',
        sa.Column('index', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('ciphertext', sa.LargeBinary(), nullable=True),
        sa.Column('nonce', sa.LargeBinary(), nullable=True),
        sa.Column('blob_version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('is_deleted', sa.Boolean(), nullable=True),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.Column('is_pinned', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('index')
    )
    op.create_index('ix_clipboard_index', 'clipboard', ['index'], unique=False)
    op.create_index('ix_clipboard_id', 'clipboard', ['id'], unique=True)
    op.create_index('ix_clipboard_is_deleted', 'clipboard', ['is_deleted'], unique=False)
    op.create_index('ix_clipboard_deleted_at', 'clipboard', ['deleted_at'], unique=False)
    op.create_index('ix_clipboard_is_pinned', 'clipboard', ['is_pinned'], unique=False)
    op.create_index('ix_clipboard_updated_at', 'clipboard', ['updated_at'], unique=False)

    op.create_table('refresh_tokens',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('token', sa.String(), nullable=True),
        sa.Column('expiry', sa.DateTime(), nullable=True),
        sa.Column('device_id', sa.String(), nullable=False),
        sa.Column('family_id', sa.String(), nullable=False),
        sa.Column('is_revoked', sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_refresh_tokens_id', 'refresh_tokens', ['id'], unique=False)
    op.create_index('ix_refresh_tokens_token', 'refresh_tokens', ['token'], unique=True)
    op.create_index('ix_refresh_tokens_expiry', 'refresh_tokens', ['expiry'], unique=False)
    op.create_index('ix_refresh_tokens_family_id', 'refresh_tokens', ['family_id'], unique=False)

    # 4. Map UUID user_id back to integer User.id
    reverse_map = {}
    for u in users_data:
        u_id, u_uuid, u_email, u_hash, u_emk, u_salt, u_kdf = u
        reverse_map[u_uuid] = u_id
        
        # Insert user back
        conn.execute(
            sa.text("INSERT INTO users (id, email, auth_key_hash, encrypted_master_key, salt, kdf_version) VALUES (:id, :email, :auth_key_hash, :encrypted_master_key, :salt, :kdf_version)"),
            {"id": u_id, "email": u_email, "auth_key_hash": u_hash, "encrypted_master_key": u_emk, "salt": u_salt, "kdf_version": u_kdf}
        )

    # 5. Insert child data mapping UUID string back to integer user_id
    for d in devices_data:
        d_id, d_devid, d_name, d_os, d_uid = d
        old_user_id = reverse_map.get(d_uid)
        conn.execute(
            sa.text("INSERT INTO devices (id, device_id, device_name, os, user_id) VALUES (:id, :device_id, :device_name, :os, :user_id)"),
            {"id": d_id, "device_id": d_devid, "device_name": d_name, "os": d_os, "user_id": old_user_id}
        )

    for c in clipboard_data:
        c_id, c_clipid, c_uid, c_ct, c_nonce, c_bv, c_ts, c_del, c_delat, c_pin, c_up = c
        old_user_id = reverse_map.get(c_uid)
        conn.execute(
            sa.text("INSERT INTO clipboard (`index`, id, user_id, ciphertext, nonce, blob_version, timestamp, is_deleted, deleted_at, is_pinned, updated_at) VALUES (:index, :id, :user_id, :ciphertext, :nonce, :blob_version, :timestamp, :is_deleted, :deleted_at, :is_pinned, :updated_at)"),
            {
                "index": c_id,
                "id": c_clipid,
                "user_id": old_user_id,
                "ciphertext": c_ct,
                "nonce": c_nonce,
                "blob_version": c_bv,
                "timestamp": c_ts,
                "is_deleted": c_del,
                "deleted_at": c_delat,
                "is_pinned": c_pin,
                "updated_at": c_up
            }
        )

    for r in refresh_tokens_data:
        r_id, r_uid, r_token, r_exp, r_devid, r_tokid, r_rev = r
        old_user_id = reverse_map.get(r_uid)
        conn.execute(
            sa.text("INSERT INTO refresh_tokens (id, user_id, token, expiry, device_id, family_id, is_revoked) VALUES (:id, :user_id, :token, :expiry, :device_id, :family_id, :is_revoked)"),
            {"id": r_id, "user_id": old_user_id, "token": r_token, "expiry": r_exp, "device_id": r_devid, "family_id": r_tokid, "is_revoked": r_rev}
        )
