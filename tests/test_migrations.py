# Test Suite: Alembic Database Migrations, Schema Parity & Disaster Recovery

import shutil
import sqlite3
import tempfile
from pathlib import Path
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


# 1. Baseline Alembic migration applies cleanly and matches all ORM model definitions.
def test_baseline_migration_applies_cleanly():
    temp_dir = tempfile.mkdtemp(prefix="synclo_test_migration_")
    test_db_path = Path(temp_dir) / "test_baseline.db"

    try:
        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{test_db_path}")

        command.upgrade(alembic_cfg, "head")
        assert test_db_path.exists()

        conn = sqlite3.connect(str(test_db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row[0] for row in cursor.fetchall()}

        expected_tables = {
            "users",
            "devices",
            "refresh_tokens",
            "blacklisted_tokens",
            "clipboard",
            "alembic_version",
        }
        assert expected_tables.issubset(tables)

        cursor.execute("PRAGMA integrity_check;")
        res = cursor.fetchone()
        assert res[0] == "ok"

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

        from datetime import datetime, timezone
        from sqlalchemy import create_engine, select
        from sqlalchemy.orm import sessionmaker
        from app.database.models import User, Device, Clipboard, RefreshToken, BlacklistedToken

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

            assert len(list(session.scalars(select(User)).all())) == 1
            assert len(list(session.scalars(select(Device)).all())) == 1
            assert len(list(session.scalars(select(Clipboard)).all())) == 1
            assert len(list(session.scalars(select(RefreshToken)).all())) == 1
            assert len(list(session.scalars(select(BlacklistedToken)).all())) == 1
        finally:
            session.close()
            engine.dispose()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# 2. Database backup, restoration, encryption, and manual decryption end-to-end workflow.
def test_backup_and_restore_workflow():
    temp_dir = tempfile.mkdtemp(prefix="synclo_test_backup_")
    source_db = Path(temp_dir) / "source.db"
    backup_dir = Path(temp_dir) / "backups"
    restore_target = Path(temp_dir) / "restored.db"

    try:
        conn = sqlite3.connect(str(source_db))
        conn.execute("CREATE TABLE test_data (id INTEGER PRIMARY KEY, note TEXT);")
        conn.execute("INSERT INTO test_data (note) VALUES ('backup_verification');")
        conn.commit()
        conn.close()

        backup_path = perform_backup(source_db, backup_dir, key=None)
        assert backup_path is not None
        assert backup_path.exists()
        assert backup_path.suffix == ".db"

        verify_ok = restore_backup(backup_path, restore_target, verify_only=True)
        assert verify_ok is True

        restore_ok = restore_backup(backup_path, restore_target, verify_only=False)
        assert restore_ok is True
        assert restore_target.exists()

        conn_res = sqlite3.connect(str(restore_target))
        row = conn_res.execute("SELECT note FROM test_data;").fetchone()
        assert row[0] == "backup_verification"
        conn_res.close()

        key = Fernet.generate_key().decode()
        enc_backup_path = perform_backup(source_db, backup_dir, key=key)
        assert enc_backup_path is not None
        assert enc_backup_path.name.endswith(".db.enc")

        verify_enc_ok = restore_backup(enc_backup_path, restore_target, key=key, verify_only=True)
        assert verify_enc_ok is True

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


# 3. Resolution of default and environment-configured database and backup directory paths.
def test_default_db_and_backup_paths(monkeypatch):
    from app.core.config import Settings

    assert Settings.BACKUP_DIR == "data/backups"
    assert "data/synclo.db" in Settings.DATABASE_URL

    monkeypatch.delenv("BACKUP_DIR", raising=False)
    assert get_default_backup_dir() == Path("data/backups")

    monkeypatch.setenv("BACKUP_DIR", "data/custom_backups")
    assert get_default_backup_dir() == Path("data/custom_backups")

    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert get_default_source_db() == Path("data/synclo.db")

    monkeypatch.setenv("DATABASE_URL", "sqlite:///./data/synclo.db")
    assert get_default_source_db() == Path("data/synclo.db")


# 4. Schema parity verification between Alembic head and SQLAlchemy ORM metadata.
def test_schema_parity_between_alembic_and_orm():
    from sqlalchemy import inspect, create_engine
    from app.database.engine import Base

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

        assert orm_tables.issubset(migrated_tables)

        for table_name, orm_table in Base.metadata.tables.items():
            migrated_cols = {col["name"]: col for col in inspector.get_columns(table_name)}
            for col in orm_table.columns:
                assert col.name in migrated_cols, (
                    f"Column {table_name}.{col.name} missing in migration"
                )
                mig_col = migrated_cols[col.name]
                assert col.nullable == mig_col["nullable"], (
                    f"Nullability mismatch on {table_name}.{col.name}: ORM={col.nullable}, Migrated={mig_col['nullable']}"
                )
                assert bool(col.primary_key) == bool(dict(mig_col).get("primary_key", False)), (
                    f"Primary key mismatch on {table_name}.{col.name}"
                )

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
