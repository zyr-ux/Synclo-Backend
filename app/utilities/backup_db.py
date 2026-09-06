#!/usr/bin/env python3
import argparse
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def get_default_source_db() -> Path:
    db_url = os.environ.get("DATABASE_URL", "sqlite:///./data/synclo.db")
    if db_url.startswith("sqlite:///./"):
        return Path(db_url[len("sqlite:///./"):])
    elif db_url.startswith("sqlite:///"):
        return Path(db_url[len("sqlite:///"):])
    return Path("data/synclo.db")


def get_default_backup_dir() -> Path:
    backup_dir = os.environ.get("BACKUP_DIR", "data/backups")
    return Path(backup_dir)


def verify_sqlite_integrity(db_path: Path) -> bool:
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("PRAGMA integrity_check;")
        row = cursor.fetchone()
        conn.close()
        return row is not None and row[0] == "ok"
    except Exception as exc:
        print(f"Integrity check failed with error: {exc}", file=sys.stderr)
        return False


def prune_old_backups(backup_dir: Path, retention_days: int):
    if retention_days <= 0:
        return
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    count = 0
    for p in backup_dir.glob("synclo_backup_*"):
        if p.is_file():
            mtime = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                try:
                    p.unlink()
                    count += 1
                except Exception as exc:
                    print(f"Failed to prune old backup {p.name}: {exc}", file=sys.stderr)
    if count > 0:
        print(f"Pruned {count} backup(s) older than {retention_days} days.")


def perform_backup(
    source_db: Path,
    backup_dir: Path,
    key: Optional[str] = None,
    retention_days: int = 30,
) -> Optional[Path]:
    if not source_db.exists():
        print(f"ERROR: Source database not found at: {source_db}", file=sys.stderr)
        return None

    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    temp_fd, temp_path_str = tempfile.mkstemp(prefix="synclo_backup_", suffix=".tmp", dir=str(backup_dir))
    # Close file handle before SQLite opens the database on Windows
    os.close(temp_fd)
    temp_path = Path(temp_path_str)

    try:
        print(f"Starting online SQLite backup from {source_db}...")
        src_conn = sqlite3.connect(str(source_db))
        dst_conn = sqlite3.connect(str(temp_path))
        src_conn.backup(dst_conn)
        dst_conn.close()
        src_conn.close()

        if not verify_sqlite_integrity(temp_path):
            print("ERROR: Backup failed integrity check!", file=sys.stderr)
            if temp_path.exists():
                temp_path.unlink()
            return None

        encryption_key = key or os.environ.get("BACKUP_ENCRYPTION_KEY")
        if encryption_key:
            try:
                from cryptography.fernet import Fernet
            except ImportError:
                print("ERROR: 'cryptography' package is required for encrypted backups.", file=sys.stderr)
                if temp_path.exists():
                    temp_path.unlink()
                return None

            print("Encrypting backup snapshot using Fernet...")
            cipher = Fernet(encryption_key.strip().encode())
            with open(temp_path, "rb") as f:
                raw_bytes = f.read()
            encrypted_bytes = cipher.encrypt(raw_bytes)
            
            final_filename = f"synclo_backup_{timestamp_str}.db.enc"
            final_path = backup_dir / final_filename
            with open(final_path, "wb") as f:
                f.write(encrypted_bytes)
            temp_path.unlink()
            print(f"SUCCESS: Encrypted backup created: {final_path} ({final_path.stat().st_size} bytes)")
        else:
            print(
                "NOTICE: BACKUP_ENCRYPTION_KEY is unset. Creating unencrypted .db snapshot.\n"
                "        Zero-Knowledge Note: Clipboard content is already encrypted client-side.\n"
                "        Set BACKUP_ENCRYPTION_KEY to protect metadata (emails, device names)."
            )
            final_filename = f"synclo_backup_{timestamp_str}.db"
            final_path = backup_dir / final_filename
            shutil.move(str(temp_path), str(final_path))
            print(f"SUCCESS: Unencrypted backup created: {final_path} ({final_path.stat().st_size} bytes)")

        try:
            os.chmod(final_path, 0o600)
        except Exception:
            pass

        prune_old_backups(backup_dir, retention_days)
        return final_path

    except Exception as exc:
        print(f"ERROR: Backup failed: {exc}", file=sys.stderr)
        if temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass
        return None


def restore_backup(
    backup_file: Path,
    target_db: Path,
    key: Optional[str] = None,
    verify_only: bool = False,
) -> bool:
    if not backup_file.exists():
        print(f"ERROR: Backup file does not exist: {backup_file}", file=sys.stderr)
        return False

    is_encrypted = backup_file.suffix == ".enc" or backup_file.name.endswith(".db.enc")
    temp_dir = tempfile.mkdtemp(prefix="synclo_restore_test_")
    sandbox_db = Path(temp_dir) / "restored.db"

    try:
        if is_encrypted:
            encryption_key = key or os.environ.get("BACKUP_ENCRYPTION_KEY")
            if not encryption_key:
                print("ERROR: BACKUP_ENCRYPTION_KEY is required to restore an encrypted backup (.db.enc).", file=sys.stderr)
                return False
            try:
                from cryptography.fernet import Fernet
            except ImportError:
                print("ERROR: 'cryptography' package is required to decrypt backup.", file=sys.stderr)
                return False

            print(f"Decrypting {backup_file.name} for restoration test...")
            cipher = Fernet(encryption_key.strip().encode())
            with open(backup_file, "rb") as f:
                encrypted_bytes = f.read()
            decrypted_bytes = cipher.decrypt(encrypted_bytes)
            with open(sandbox_db, "wb") as f:
                f.write(decrypted_bytes)
        else:
            print(f"Copying unencrypted backup {backup_file.name} for verification...")
            shutil.copy2(str(backup_file), str(sandbox_db))

        if not verify_sqlite_integrity(sandbox_db):
            print("ERROR: Restored database failed SQLite integrity check!", file=sys.stderr)
            return False

        print("Integrity check PASSED.")

        if verify_only:
            print(f"SUCCESS: Verification successful. Sandbox database verified without modifying {target_db}.")
            return True

        print(f"Restoring database to target location: {target_db}...")
        target_db.parent.mkdir(parents=True, exist_ok=True)
        if target_db.exists():
            safety_copy = target_db.with_suffix(f".pre_restore_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}")
            print(f"Saving pre-restore safety copy: {safety_copy}")
            shutil.copy2(str(target_db), str(safety_copy))

        shutil.copy2(str(sandbox_db), str(target_db))
        print(f"SUCCESS: Database restored successfully to {target_db} ({target_db.stat().st_size} bytes).")
        return True

    except Exception as exc:
        print(f"ERROR: Restore/verification failed: {exc}", file=sys.stderr)
        return False
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(
        description="Synclo transaction-safe SQLite database backup and recovery utility."
    )
    parser.add_argument("--source", type=Path, default=None, help="Path to source SQLite database")
    parser.add_argument("--dest", type=Path, default=None, help="Destination directory for backups (defaults to BACKUP_DIR or data/backups)")
    parser.add_argument("--key", type=str, default=None, help="Fernet encryption key")
    parser.add_argument("--retention-days", type=int, default=30, help="Backup retention period in days")
    parser.add_argument("--restore", type=Path, default=None, help="Path to backup file to restore")
    parser.add_argument("--verify-restore", type=Path, default=None, help="Dry-run verify restore in sandbox")
    parser.add_argument("--target", type=Path, default=None, help="Target path for restore")

    args = parser.parse_args()

    source_db = args.source or get_default_source_db()
    backup_dir = args.dest or get_default_backup_dir()
    target_db = args.target or source_db

    if args.verify_restore:
        success = restore_backup(args.verify_restore, target_db, key=args.key, verify_only=True)
        sys.exit(0 if success else 1)

    if args.restore:
        success = restore_backup(args.restore, target_db, key=args.key, verify_only=False)
        sys.exit(0 if success else 1)

    result = perform_backup(
        source_db=source_db,
        backup_dir=backup_dir,
        key=args.key,
        retention_days=args.retention_days,
    )
    sys.exit(0 if result is not None else 1)


if __name__ == "__main__":
    main()
