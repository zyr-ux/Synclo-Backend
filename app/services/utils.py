import logging
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional
from sqlalchemy.orm import Session
from app.core.config import Settings
from app.models.models import BlacklistedToken, RefreshToken, Clipboard, User

logger = logging.getLogger(__name__)

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
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)

def cleanup_expired_blacklisted_tokens(db: Session):
    try:
        now_utc = datetime.now(timezone.utc)
        db.query(BlacklistedToken).filter(BlacklistedToken.expiry < now_utc).delete()
        db.commit()
    except Exception:
        db.rollback()
        pass

def cleanup_expired_refresh_tokens(db: Session):
    try:
        now_utc = datetime.now(timezone.utc)
        db.query(RefreshToken).filter(RefreshToken.expiry < now_utc).delete()
        db.commit()
    except Exception:
        db.rollback()
        pass

def prune_user_clipboard(user_id: str, db: Session, retention_days: Optional[int] = None) -> List[dict]:
    try:
        from app.services.serializers import make_tombstone_payload
        if retention_days is None:
            retention_days = Settings.CLIPBOARD_RETENTION_DAYS

        if retention_days <= 0:
            return []

        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=retention_days)

        entries = (
            db.query(Clipboard)
            .filter(
                Clipboard.user_id == user_id,
                Clipboard.is_deleted.is_(False),
                Clipboard.is_pinned.is_(False),
                Clipboard.updated_at < cutoff
            )
            .all()
        )

        if not entries:
            return []

        tombstones = []
        for item in entries:
            item.is_deleted = True
            item.deleted_at = now
            item.updated_at = now
            item.ciphertext = None
            item.nonce = None
            item.is_pinned = False
            item.pinned_at = None

            tombstones.append(
                make_tombstone_payload(
                    clipboard_id=item.clipboard_id,
                    blob_version=item.blob_version,
                    timestamp=item.timestamp or now
                )
            )

        db.commit()
        return tombstones
    except Exception as e:
        logger.error(f"Clipboard pruning failed for user {user_id}: {e}")
        db.rollback()
        return []

def prune_all_users_clipboard(db: Session, retention_days: Optional[int] = None):
    try:
        users = db.query(User).all()
        for user in users:
            prune_user_clipboard(user.user_id, db, retention_days=retention_days)
    except Exception as e:
        logger.error(f"Global clipboard pruning failed: {e}")
        db.rollback()

def cleanup_old_tombstones(db: Session):
    try:
        retention_days = Settings.TOMBSTONE_RETENTION_DAYS
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        
        db.query(Clipboard).filter(
            Clipboard.is_deleted.is_(True),
            Clipboard.deleted_at < cutoff_date
        ).delete()
        db.commit()
    except Exception:
        db.rollback()
        pass

def run_all_cleanup(db: Session):
    cleanup_expired_blacklisted_tokens(db)
    cleanup_expired_refresh_tokens(db)
    cleanup_old_tombstones(db)
    prune_all_users_clipboard(db)