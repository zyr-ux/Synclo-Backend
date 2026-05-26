from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.models.models import BlacklistedToken, RefreshToken, Clipboard

def cleanup_expired_blacklisted_tokens(db: Session):
    try:
        # DB stores naive UTC
        now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
        db.query(BlacklistedToken).filter(BlacklistedToken.expiry < now_naive).delete()
        db.commit()
    except Exception as e:
        db.rollback()
        # Table may not exist if migrations haven't run yet
        pass

def cleanup_expired_refresh_tokens(db: Session):
    try:
        # DB stores naive UTC
        now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
        db.query(RefreshToken).filter(RefreshToken.expiry < now_naive).delete()
        db.commit()
    except Exception as e:
        db.rollback()
        # Table may not exist if migrations haven't run yet
        pass

def cleanup_old_clipboard_entries(user_id: int, db: Session):
    # Active items are now retained indefinitely.
    # This function is kept for signature compatibility but does nothing.
    pass

def cleanup_old_tombstones(db: Session):
    try:
        from config import Settings
        retention_days = Settings.TOMBSTONE_RETENTION_DAYS
        # DB stores naive UTC
        cutoff_date = (datetime.now(timezone.utc) - timedelta(days=retention_days)).replace(tzinfo=None)
        
        db.query(Clipboard).filter(
            Clipboard.is_deleted == True,
            Clipboard.deleted_at < cutoff_date
        ).delete()
        db.commit()
    except Exception as e:
        db.rollback()
        pass

def run_all_cleanup(db: Session):
    """
    Runs all cleanup operations:
    - Expired blacklisted tokens
    - Expired refresh tokens
    - Old tombstones (deleted clipboard entries older than retention period)
    """
    cleanup_expired_blacklisted_tokens(db)
    cleanup_expired_refresh_tokens(db)
    cleanup_old_tombstones(db)