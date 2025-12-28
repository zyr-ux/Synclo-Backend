from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from models import BlacklistedToken, RefreshToken, Clipboard

def cleanup_expired_blacklisted_tokens(db: Session):
    try:
        db.query(BlacklistedToken).filter(BlacklistedToken.expiry < datetime.utcnow()).delete()
        db.commit()
    except Exception as e:
        db.rollback()
        # Table may not exist if migrations haven't run yet
        pass

def cleanup_expired_refresh_tokens(db: Session):
    try:
        db.query(RefreshToken).filter(RefreshToken.expiry < datetime.utcnow()).delete()
        db.commit()
    except Exception as e:
        db.rollback()
        # Table may not exist if migrations haven't run yet
        pass

def cleanup_old_clipboard_entries(user_id: int, db: Session):
    try:
        one_week_ago = datetime.utcnow() - timedelta(days=7)
        db.query(Clipboard).filter(
            Clipboard.user_id == user_id,
            Clipboard.timestamp < one_week_ago
        ).delete()
        db.commit()
    except Exception as e:
        db.rollback()
        # Table may not exist if migrations haven't run yet
        pass