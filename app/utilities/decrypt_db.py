#!/usr/bin/env python3
"""
Synclo Database Decryption Utility (app/utilities/decrypt_db.py)

Dedicated, standalone CLI utility for decrypting encrypted Synclo SQLite database backups (.db.enc)
into plain SQLite databases (.db), with automatic integrity verification.

Usage:
    python app/utilities/decrypt_db.py data/backups/synclo_backup_20260904_210000.db.enc
    python app/utilities/decrypt_db.py backup.db.enc --output decrypted.db --key <FernetKey>
"""

import argparse
import getpass
import os
import sqlite3
import sys
from pathlib import Path


def decrypt_database(encrypted_path: Path, output_path: Path, key: str) -> bool:
    try:
        from cryptography.fernet import Fernet, InvalidToken
    except ImportError:
        print("ERROR: 'cryptography' library is required. Install via: pip install cryptography", file=sys.stderr)
        return False

    if not encrypted_path.exists():
        print(f"ERROR: Encrypted file not found: {encrypted_path}", file=sys.stderr)
        return False

    try:
        cipher = Fernet(key.strip().encode())
    except Exception as exc:
        print(f"ERROR: Invalid Fernet key format: {exc}", file=sys.stderr)
        return False

    print(f"Reading encrypted database: {encrypted_path} ({encrypted_path.stat().st_size} bytes)")
    with open(encrypted_path, "rb") as f:
        encrypted_data = f.read()

    try:
        decrypted_data = cipher.decrypt(encrypted_data)
    except InvalidToken:
        print("ERROR: Decryption failed! The provided key is incorrect or the backup file is corrupt.", file=sys.stderr)
        return False
    except Exception as exc:
        print(f"ERROR: Decryption failed: {exc}", file=sys.stderr)
        return False

    # Write to output file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    try:
        os.chmod(output_path, 0o600)
    except Exception:
        pass

    # Integrity verification
    try:
        conn = sqlite3.connect(str(output_path))
        cursor = conn.cursor()
        cursor.execute("PRAGMA integrity_check;")
        row = cursor.fetchone()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in cursor.fetchall()]
        conn.close()

        if row and row[0] == "ok":
            print(f"SUCCESS: Decrypted database verified successfully.")
            print(f"Output: {output_path} ({output_path.stat().st_size} bytes)")
            print(f"Tables present: {', '.join(tables)}")
            return True
        else:
            print(f"WARNING: SQLite integrity check reported issues: {row}", file=sys.stderr)
            return False
    except Exception as exc:
        print(f"ERROR: Failed to verify SQLite database integrity: {exc}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt an encrypted Synclo database backup (.db.enc) into a standard SQLite database (.db)."
    )
    parser.add_argument("encrypted_file", type=Path, help="Path to the encrypted .db.enc file")
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Destination path for decrypted .db file (defaults to removing .enc suffix)"
    )
    parser.add_argument(
        "--key", "-k",
        type=str,
        default=None,
        help="Fernet encryption key (or read from BACKUP_ENCRYPTION_KEY env var)"
    )

    args = parser.parse_args()

    # Determine encryption key
    key = args.key or os.environ.get("BACKUP_ENCRYPTION_KEY")
    if not key:
        key = getpass.getpass("Enter BACKUP_ENCRYPTION_KEY: ")

    if not key:
        print("ERROR: Encryption key is required to decrypt backup.", file=sys.stderr)
        sys.exit(1)

    # Determine output path
    output_path = args.output
    if output_path is None:
        if args.encrypted_file.suffix == ".enc":
            output_path = args.encrypted_file.with_suffix("")
        else:
            output_path = args.encrypted_file.with_name(f"{args.encrypted_file.stem}_decrypted.db")

    success = decrypt_database(args.encrypted_file, output_path, key)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
