import base64
import hashlib
import hmac
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional, Tuple, overload
from sqlalchemy import delete, select
from sqlalchemy.orm import Session
from app.core.config import Settings
from app.core.database import run_in_write_transaction
from app.core.metrics import CLEANUP_FAILURES_TOTAL
from app.models.models import BlacklistedToken, RefreshToken, Clipboard, User

logger = logging.getLogger(__name__)

REFRESH_SECRET_KEY = Settings.REFRESH_TOKEN_HASH_KEY


def hash_refresh_token(token: str) -> str:
    if not isinstance(token, str) or not token:
        raise ValueError("Token must be a non-empty string")

    return hmac.new(REFRESH_SECRET_KEY, token.encode(), hashlib.sha256).hexdigest()


def strict_b64decode(value: str, field_name: str = "field") -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f"Invalid base64 encoding for {field_name}: {exc}") from exc


@dataclass
class CleanupResult:
    tombstones: List[Tuple[str, dict]]
    failures: int = 0


@overload
def ensure_utc(dt: None) -> None: ...


@overload
def ensure_utc(dt: datetime) -> datetime: ...


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_iso_utc(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if isinstance(dt, datetime):
        utc_dt = ensure_utc(dt)
        return utc_dt.isoformat().replace("+00:00", "Z") if utc_dt else None
    if hasattr(dt, "isoformat"):
        return dt.isoformat().replace("+00:00", "Z")
    return str(dt)


def parse_iso_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return (
        parsed.replace(tzinfo=timezone.utc)
        if parsed.tzinfo is None
        else parsed.astimezone(timezone.utc)
    )


def cleanup_expired_blacklisted_tokens(db: Session) -> bool:
    try:
        now_utc = datetime.now(timezone.utc)

        def mutate():
            db.execute(delete(BlacklistedToken).where(BlacklistedToken.expiry < now_utc))

        run_in_write_transaction(db, mutate)
        return True
    except Exception as exc:
        CLEANUP_FAILURES_TOTAL.labels(operation="blacklisted_tokens").inc()
        logger.error("Blacklisted-token cleanup failed: %s", exc)
        return False


def cleanup_expired_refresh_tokens(db: Session) -> bool:
    try:
        now_utc = datetime.now(timezone.utc)

        def mutate():
            db.execute(delete(RefreshToken).where(RefreshToken.expiry < now_utc))

        run_in_write_transaction(db, mutate)
        return True
    except Exception as exc:
        CLEANUP_FAILURES_TOTAL.labels(operation="refresh_tokens").inc()
        logger.error("Refresh-token cleanup failed: %s", exc)
        return False


def prune_user_clipboard(
    user_id: str, db: Session, retention_days: Optional[int] = None
) -> List[dict]:
    from app.core.database import run_in_write_transaction
    from app.services.clipboard_service import allocate_batch_sync_sequence
    from app.services.serializers import make_tombstone_payload

    retention_days = Settings.CLIPBOARD_RETENTION_DAYS if retention_days is None else retention_days
    if retention_days <= 0:
        return []

    def mutate() -> List[dict]:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=retention_days)
        stmt = select(Clipboard).where(
            Clipboard.user_id == user_id,
            Clipboard.is_deleted.is_(False),
            Clipboard.is_pinned.is_(False),
            Clipboard.updated_at < cutoff,
        )
        entries = list(db.scalars(stmt).all())
        if not entries:
            return []

        final_seq = allocate_batch_sync_sequence(db, user_id, count=len(entries))
        start_seq = final_seq - len(entries) + 1
        tombstones = []
        for index, item in enumerate(entries):
            item.is_deleted = True
            item.deleted_at = now
            item.updated_at = now
            item.timestamp = now
            item.ciphertext = None
            item.nonce = None
            item.is_pinned = False
            item.pinned_at = None
            item.change_number = start_seq + index
            item.entry_revision = (item.entry_revision or 0) + 1
            item.last_device_id = None
            tombstones.append(
                make_tombstone_payload(
                    clipboard_id=item.clipboard_id,
                    blob_version=item.blob_version,
                    timestamp=now,
                    change_number=item.change_number,
                    entry_revision=item.entry_revision,
                    last_device_id=None,
                )
            )
        return tombstones

    return run_in_write_transaction(db, mutate)


def prune_all_users_clipboard(
    db: Session, retention_days: Optional[int] = None
) -> List[Tuple[str, dict]]:
    all_tombstones: List[Tuple[str, dict]] = []
    user_ids = list(db.scalars(select(User.user_id)).all())
    for user_id in user_ids:
        tombstones = prune_user_clipboard(user_id, db, retention_days=retention_days)
        all_tombstones.extend((user_id, tombstone) for tombstone in tombstones)
    return all_tombstones


def cleanup_old_tombstones(db: Session) -> bool:
    try:
        retention_days = Settings.TOMBSTONE_RETENTION_DAYS
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)

        def mutate():
            db.execute(
                delete(Clipboard).where(
                    Clipboard.is_deleted.is_(True), Clipboard.deleted_at < cutoff_date
                )
            )

        run_in_write_transaction(db, mutate)
        return True
    except Exception as exc:
        CLEANUP_FAILURES_TOTAL.labels(operation="tombstones").inc()
        logger.error("Tombstone cleanup failed: %s", exc)
        return False


def run_all_cleanup(db: Session) -> CleanupResult:
    failures = 0
    if not cleanup_expired_blacklisted_tokens(db):
        failures += 1
    if not cleanup_expired_refresh_tokens(db):
        failures += 1
    if not cleanup_old_tombstones(db):
        failures += 1

    try:
        tombstones = prune_all_users_clipboard(db)
    except Exception as exc:
        db.rollback()
        CLEANUP_FAILURES_TOTAL.labels(operation="clipboard_pruning").inc()
        logger.error("Clipboard pruning failed: %s", exc)
        tombstones = []
        failures += 1
    return CleanupResult(tombstones=tombstones, failures=failures)


class RedactingFilter(logging.Filter):
    PATTERNS = [
        re.compile(r"Bearer\s+[A-Za-z0-9\-_.]+", re.IGNORECASE),
        re.compile(r"auth_key['\"]?\s*[:=]\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"password['\"]?\s*[:=]\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ]

    @classmethod
    def redact(cls, text: Any) -> Any:
        if not isinstance(text, str):
            return text
        for pattern in cls.PATTERNS:
            text = pattern.sub("[REDACTED]", text)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = self.redact(record.getMessage())
            record.args = ()
        except Exception:
            pass
        return True
