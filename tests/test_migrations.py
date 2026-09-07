import os
import shutil
import sqlite3
import tempfile
from pathlib import Path
import pytest
from alembic.config import Config
from alembic import command
from cryptography.fernet import Fernet

from app.utilities.backup_db import (
    get_default_backup_dir,
    get_default_source_db,
    perform_backup,
    restore_backup,
)
from app.utilities.decrypt_db import decrypt_database


def test_baseline_migration_applies_cleanly():
    temp_dir = tempfile.mkdtemp(prefix="synclo_test_migration_")
    test_db_path = Path(temp_dir) / "test_baseline.db"
    
    try:
        # Create Alembic config pointing to the test DB
        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{test_db_path}")
        
        # Run upgrade head
        command.upgrade(alembic_cfg, "head")
        assert test_db_path.exists()
        
        # Inspect created tables
        conn = sqlite3.connect(str(test_db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row[0] for row in cursor.fetchall()}
        
        expected_tables = {"users", "devices", "refresh_tokens", "blacklisted_tokens", "clipboard", "alembic_version"}
        assert expected_tables.issubset(tables)
        
        # Check integrity
        cursor.execute("PRAGMA integrity_check;")
        res = cursor.fetchone()
        assert res[0] == "ok"
        
        # Verify columns on clipboard table
        cursor.execute("PRAGMA table_info(clipboard);")
        columns = {row[1]: {"notnull": row[3], "dflt_value": row[4]} for row in cursor.fetchall()}
        
        assert "change_number" in columns
        assert columns["change_number"]["notnull"] == 1
        assert "entry_revision" in columns
        assert columns["entry_revision"]["notnull"] == 1
        assert "last_device_id" in columns
        assert "is_pinned" in columns
        assert "pinned_at" in columns
        
        conn.close()

        # Verify ORM models map 1:1 against the migrated database
        from datetime import datetime, timezone
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from app.models.models import User, Device, Clipboard, RefreshToken, BlacklistedToken

        engine = create_engine(f"sqlite:///{test_db_path}")
        TestSession = sessionmaker(bind=engine)
        session = TestSession()

        try:
            now = datetime.now(timezone.utc)
            user = User(
                user_id="mig_user_1",
                email="migration@test.com",
                username="migtester",
                auth_key_hash="hash",
                encrypted_master_key=b"emk_bytes",
                salt=b"salt_bytes",
                kdf_version=1,
                recovery_wrapped_master_key=b"rwmk_bytes",
                recovery_key_verifier="rkv",
            )
            session.add(user)
            session.commit()

            device = Device(
                device_id="dev_mig_1",
                device_name="Laptop",
                user_id="mig_user_1",
            )
            session.add(device)
            session.commit()

            clipboard = Clipboard(
                clipboard_id="clip_mig_1",
                user_id="mig_user_1",
                last_device_id="dev_mig_1",
                ciphertext=b"ciphertext_bytes",
                nonce=b"nonce_bytes",
                blob_version=1,
                timestamp=now,
                updated_at=now,
                change_number=1,
                entry_revision=1,
            )
            session.add(clipboard)
            session.commit()

            rt = RefreshToken(
                token="hashed_refresh_token",
                user_id="mig_user_1",
                device_id="dev_mig_1",
                token_id="tok_1",
                is_revoked=False,
                expiry=now,
            )
            session.add(rt)
            session.commit()

            bt = BlacklistedToken(
                token="blacklisted_access_token",
                expiry=now,
            )
            session.add(bt)
            session.commit()

            assert session.query(User).count() == 1
            assert session.query(Device).count() == 1
            assert session.query(Clipboard).count() == 1
            assert session.query(RefreshToken).count() == 1
            assert session.query(BlacklistedToken).count() == 1
        finally:
            session.close()
            engine.dispose()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_backup_and_restore_workflow():
    temp_dir = tempfile.mkdtemp(prefix="synclo_test_backup_")
    source_db = Path(temp_dir) / "source.db"
    backup_dir = Path(temp_dir) / "backups"
    restore_target = Path(temp_dir) / "restored.db"
    
    try:
        # Initialize source DB with a table and record
        conn = sqlite3.connect(str(source_db))
        conn.execute("CREATE TABLE test_data (id INTEGER PRIMARY KEY, note TEXT);")
        conn.execute("INSERT INTO test_data (note) VALUES ('backup_verification');")
        conn.commit()
        conn.close()
        
        # 1. Unencrypted backup
        backup_path = perform_backup(source_db, backup_dir, key=None)
        assert backup_path is not None
        assert backup_path.exists()
        assert backup_path.suffix == ".db"
        
        # Verify restore
        verify_ok = restore_backup(backup_path, restore_target, verify_only=True)
        assert verify_ok is True
        
        # Actual restore
        restore_ok = restore_backup(backup_path, restore_target, verify_only=False)
        assert restore_ok is True
        assert restore_target.exists()
        
        conn_res = sqlite3.connect(str(restore_target))
        row = conn_res.execute("SELECT note FROM test_data;").fetchone()
        assert row[0] == "backup_verification"
        conn_res.close()
        
        # 2. Encrypted backup
        key = Fernet.generate_key().decode()
        enc_backup_path = perform_backup(source_db, backup_dir, key=key)
        assert enc_backup_path is not None
        assert enc_backup_path.name.endswith(".db.enc")
        
        # Verify restore with correct key
        verify_enc_ok = restore_backup(enc_backup_path, restore_target, key=key, verify_only=True)
        assert verify_enc_ok is True
        
        # Decrypt with decrypt_db utility
        manual_decrypted = Path(temp_dir) / "manual_decrypted.db"
        dec_ok = decrypt_database(enc_backup_path, manual_decrypted, key=key)
        assert dec_ok is True
        assert manual_decrypted.exists()
        
        conn_dec = sqlite3.connect(str(manual_decrypted))
        row_dec = conn_dec.execute("SELECT note FROM test_data;").fetchone()
        assert row_dec[0] == "backup_verification"
        conn_dec.close()
        
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_default_db_and_backup_paths(monkeypatch):
    from app.core.config import Settings

    # Default Settings
    assert Settings.BACKUP_DIR == "data/backups"
    assert "data/synclo.db" in Settings.DATABASE_URL

    # Test default backup directory resolution
    monkeypatch.delenv("BACKUP_DIR", raising=False)
    assert get_default_backup_dir() == Path("data/backups")

    monkeypatch.setenv("BACKUP_DIR", "data/custom_backups")
    assert get_default_backup_dir() == Path("data/custom_backups")

    # Test default source db resolution
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert get_default_source_db() == Path("data/synclo.db")

    monkeypatch.setenv("DATABASE_URL", "sqlite:///./data/synclo.db")
    assert get_default_source_db() == Path("data/synclo.db")


def test_schema_parity_between_alembic_and_orm():
    """
    Validates complete 1:1 schema parity between Alembic migration head and SQLAlchemy Base.metadata:
    - Table existence
    - Column names, nullability, and primary keys
    """
    from sqlalchemy import inspect, create_engine
    from app.core.database import Base
    import app.models.models  # ensure models are registered on Base.metadata

    temp_dir = tempfile.mkdtemp(prefix="synclo_test_parity_")
    test_db_path = Path(temp_dir) / "test_parity.db"

    try:
        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{test_db_path}")
        command.upgrade(alembic_cfg, "head")

        engine = create_engine(f"sqlite:///{test_db_path}")
        inspector = inspect(engine)

        migrated_tables = set(inspector.get_table_names())
        orm_tables = set(Base.metadata.tables.keys())

        # All ORM tables must exist in migrated tables
        assert orm_tables.issubset(migrated_tables)

        for table_name, orm_table in Base.metadata.tables.items():
            migrated_cols = {col["name"]: col for col in inspector.get_columns(table_name)}
            for col in orm_table.columns:
                assert col.name in migrated_cols, f"Column {table_name}.{col.name} missing in migration"
                mig_col = migrated_cols[col.name]
                # Compare nullability
                assert col.nullable == mig_col["nullable"], (
                    f"Nullability mismatch on {table_name}.{col.name}: ORM={col.nullable}, Migrated={mig_col['nullable']}"
                )
                # Compare primary key
                assert bool(col.primary_key) == bool(mig_col["primary_key"]), (
                    f"Primary key mismatch on {table_name}.{col.name}"
                )

            # Compare indexes
            migrated_indexes = {idx["name"]: idx for idx in inspector.get_indexes(table_name)}
            for col in orm_table.columns:
                if col.index:
                    expected_idx_name = f"ix_{table_name}_{col.name}"
                    assert expected_idx_name in migrated_indexes, (
                        f"Column-level index {expected_idx_name} missing on {table_name}"
                    )
            for idx in orm_table.indexes:
                assert idx.name in migrated_indexes, (
                    f"Table-level index {idx.name} missing on {table_name}"
                )

        engine.dispose()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

