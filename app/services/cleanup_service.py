from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
from typing import List, Tuple

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.metrics import CLEANUP_FAILURES_TOTAL
from app.database.engine import run_in_write_transaction
from app.database.models import BlacklistedToken, Clipboard, RefreshToken
from app.services.clipboard_service import prune_all_users_clipboard

logger = logging.getLogger(__name__)


@dataclass
class CleanupResult:
    tombstones: List[Tuple[str, dict]]
    failures: int = 0


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
