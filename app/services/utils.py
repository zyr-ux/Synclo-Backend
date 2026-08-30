import logging
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional
from sqlalchemy.orm import Session
from app.models.models import BlacklistedToken, RefreshToken, Clipboard, User

logger = logging.getLogger(__name__)

def cleanup_expired_blacklisted_tokens(db: Session):
    try:
        now_utc = datetime.now(timezone.utc)
        db.query(BlacklistedToken).filter(BlacklistedToken.expiry < now_utc).delete()
        db.commit()
    except Exception:
        db.rollback()
        # Table may not exist if migrations haven't run yet
        pass

def cleanup_expired_refresh_tokens(db: Session):
    try:
        now_utc = datetime.now(timezone.utc)
        db.query(RefreshToken).filter(RefreshToken.expiry < now_utc).delete()
        db.commit()
    except Exception:
        db.rollback()
        # Table may not exist if migrations haven't run yet
        pass

def prune_user_clipboard(user_id: str, db: Session, limit: Optional[int] = None) -> List[dict]:
    """
    Prunes excess non-pinned active clipboard entries beyond the user's limit.
    Soft-deletes excess items into tombstones and returns tombstone payloads for broadcasting.
    A limit of 0 represents infinite history (no pruning).
    """
    try:
        if limit is None:
            user = db.query(User).filter_by(user_id=user_id).first()
            if not user:
                return []
            _u: Any = user
            limit = _u.clipboard_limit

        if limit == 0:
            return []

        # Get active, non-pinned items ordered newest first
        entries = (
            db.query(Clipboard)
            .filter(
                Clipboard.user_id == user_id,
                Clipboard.is_deleted.is_(False),
                Clipboard.is_pinned.is_(False)
            )
            .order_by(Clipboard.timestamp.desc())
            .all()
        )

        if len(entries) <= limit:
            return []

        to_prune = entries[limit:]
        now = datetime.now(timezone.utc)
        tombstones = []

        for item in to_prune:
            _item: Any = item
            _item.is_deleted = True
            _item.deleted_at = now
            _item.updated_at = now
            _item.ciphertext = None
            _item.nonce = None
            _item.is_pinned = False
            _item.pinned_at = None

            ts_str = _item.timestamp.isoformat().replace("+00:00", "Z") if _item.timestamp else now.isoformat().replace("+00:00", "Z")
            tombstones.append({
                "type": "clipboard_sync",
                "id": _item.clipboard_id,
                "is_deleted": True,
                "is_pinned": False,
                "pinned_at": None,
                "timestamp": ts_str,
                "ciphertext": None,
                "nonce": None,
                "blob_version": _item.blob_version
            })

        db.commit()
        return tombstones
    except Exception as e:
        logger.error(f"Clipboard pruning failed for user {user_id}: {e}")
        db.rollback()
        return []

def prune_all_users_clipboard(db: Session):
    """
    Iterates over all users and prunes their excess non-pinned clipboard entries.
    """
    try:
        users = db.query(User).all()
        for user in users:
            _u: Any = user
            prune_user_clipboard(_u.user_id, db, limit=_u.clipboard_limit)
    except Exception as e:
        logger.error(f"Global clipboard pruning failed: {e}")
        db.rollback()

def cleanup_old_tombstones(db: Session):
    try:
        from app.core.config import Settings
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
    """
    Runs all cleanup operations:
    - Expired blacklisted tokens
    - Expired refresh tokens
    - Old tombstones (deleted clipboard entries older than retention period)
    - Auto-prune excess clipboard entries for all users
    """
    cleanup_expired_blacklisted_tokens(db)
    cleanup_expired_refresh_tokens(db)
    cleanup_old_tombstones(db)
    prune_all_users_clipboard(db)