# Test Suite: Backup, Database Decryption & Push Configuration Utilities

import json
import os
import sqlite3
import time
from pathlib import Path
from cryptography.fernet import Fernet
import pytest

from app.core.config import _load_allowed_push_domains
from app.utilities.backup_db import (
    perform_backup,
    prune_old_backups,
    restore_backup,
)
from app.utilities.decrypt_db import decrypt_database


def _create_sample_sqlite_db(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE test_table (id INTEGER PRIMARY KEY, value TEXT);")
    conn.execute("INSERT INTO test_table (value) VALUES ('hello_synclo');")
    conn.commit()
    conn.close()


# 1. Database backup fails gracefully when source SQLite file does not exist.
def test_perform_backup_source_does_not_exist(tmp_path):
    missing_db = tmp_path / "nonexistent.db"
    backup_dir = tmp_path / "backups"

    res = perform_backup(source_db=missing_db, backup_dir=backup_dir)
    assert res is None


# 2. Database backup aborts and cleans up temp files when integrity check fails.
def test_perform_backup_integrity_check_failure(tmp_path, monkeypatch):
    source_db = tmp_path / "source.db"
    _create_sample_sqlite_db(source_db)
    backup_dir = tmp_path / "backups"

    monkeypatch.setattr("app.utilities.backup_db.verify_sqlite_integrity", lambda p: False)

    res = perform_backup(source_db=source_db, backup_dir=backup_dir)
    assert res is None
    assert len(list(backup_dir.glob("*.tmp"))) == 0


# 3. Retention filtering prunes backups older than threshold while keeping recent backups.
def test_prune_old_backups(tmp_path):
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()

    old_file = backup_dir / "synclo_backup_20200101_000000.db"
    new_file = backup_dir / "synclo_backup_20990101_000000.db"
    unrelated_file = backup_dir / "keep_me.txt"

    for f in (old_file, new_file, unrelated_file):
        f.write_text("data")

    old_time = time.time() - (40 * 86400)
    os.utime(str(old_file), (old_time, old_time))

    prune_old_backups(backup_dir, retention_days=30)

    assert not old_file.exists()
    assert new_file.exists()
    assert unrelated_file.exists()


# 4. Database restore verify_only mode checks backup integrity without touching target database.
def test_restore_backup_verify_only_mode(tmp_path):
    source_db = tmp_path / "source.db"
    _create_sample_sqlite_db(source_db)
    backup_dir = tmp_path / "backups"
    target_db = tmp_path / "target_never_created.db"

    backup_file = perform_backup(source_db=source_db, backup_dir=backup_dir)
    assert backup_file is not None and backup_file.exists()

    success = restore_backup(backup_file=backup_file, target_db=target_db, verify_only=True)
    assert success is True
    assert not target_db.exists()


# 5. Encrypted backup restoration with incorrect Fernet key fails gracefully.
def test_restore_encrypted_backup_wrong_key_fails(tmp_path):
    source_db = tmp_path / "source.db"
    _create_sample_sqlite_db(source_db)
    backup_dir = tmp_path / "backups"
    target_db = tmp_path / "restored.db"

    correct_key = Fernet.generate_key().decode()
    wrong_key = Fernet.generate_key().decode()

    backup_file = perform_backup(source_db=source_db, backup_dir=backup_dir, key=correct_key)
    assert backup_file is not None
    assert backup_file.name.endswith(".enc")

    success = restore_backup(backup_file=backup_file, target_db=target_db, key=wrong_key)
    assert success is False


# 6. Standalone database decryption utility returns False for nonexistent input file.
def test_decrypt_database_missing_file(tmp_path):
    missing_file = tmp_path / "missing.db.enc"
    out_file = tmp_path / "out.db"
    key = Fernet.generate_key().decode()

    assert decrypt_database(missing_file, out_file, key) is False


# 7. Standalone database decryption utility returns False for malformed Fernet key string.
def test_decrypt_database_invalid_key_format(tmp_path):
    enc_file = tmp_path / "test.db.enc"
    enc_file.write_bytes(b"some_bytes")
    out_file = tmp_path / "out.db"

    assert decrypt_database(enc_file, out_file, "not-a-valid-fernet-key") is False


# 8. Standalone database decryption utility returns False when provided incorrect decryption key.
def test_decrypt_database_wrong_key(tmp_path):
    correct_key = Fernet.generate_key().decode()
    wrong_key = Fernet.generate_key().decode()

    enc_file = tmp_path / "test.db.enc"
    cipher = Fernet(correct_key.encode())
    enc_file.write_bytes(cipher.encrypt(b"SQLite format 3\x00 dummy payload"))
    out_file = tmp_path / "out.db"

    assert decrypt_database(enc_file, out_file, wrong_key) is False


# 9. Standalone database decryption utility decrypts and extracts valid SQLite database.
def test_decrypt_database_valid_workflow(tmp_path):
    source_db = tmp_path / "source.db"
    _create_sample_sqlite_db(source_db)

    key = Fernet.generate_key().decode()
    cipher = Fernet(key.encode())
    encrypted_data = cipher.encrypt(source_db.read_bytes())

    enc_file = tmp_path / "database.db.enc"
    enc_file.write_bytes(encrypted_data)

    out_file = tmp_path / "decrypted.db"
    success = decrypt_database(enc_file, out_file, key)

    assert success is True
    assert out_file.exists()

    conn = sqlite3.connect(str(out_file))
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM test_table;")
    row = cursor.fetchone()
    conn.close()
    assert row is not None and row[0] == "hello_synclo"


# 10. Push domain loader extracts and merges domains from allowed_domains and provider list.
def test_load_allowed_push_domains_merges_providers(tmp_path):
    config_file = tmp_path / "providers.json"
    content = {
        "allowed_domains": ["push.example.com", "notifications.apple.com"],
        "providers": [
            {"name": "Google FCM", "domain": "fcm.googleapis.com"},
            {"name": "Mozilla", "domain": "updates.push.services.mozilla.com"},
            {"name": "Invalid Provider Without Domain"},
        ],
    }
    config_file.write_text(json.dumps(content))

    domains = _load_allowed_push_domains(config_file)
    assert domains == {
        "push.example.com",
        "notifications.apple.com",
        "fcm.googleapis.com",
        "updates.push.services.mozilla.com",
    }


# 11. Push domain loader raises RuntimeError when configuration provides no domains.
def test_load_allowed_push_domains_empty_raises(tmp_path):
    config_file = tmp_path / "empty_providers.json"
    config_file.write_text(json.dumps({"allowed_domains": [], "providers": []}))

    with pytest.raises(RuntimeError, match="No allowed push domains configured"):
        _load_allowed_push_domains(config_file)


# 12. Push domain loader raises RuntimeError when configuration file is missing.
def test_load_allowed_push_domains_missing_file_raises(tmp_path):
    missing = tmp_path / "missing_push.json"
    with pytest.raises(RuntimeError, match="Push providers configuration file not found"):
        _load_allowed_push_domains(missing)
