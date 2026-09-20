from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.engine import async_run_in_write_transaction, run_in_write_transaction
from app.database.models import Clipboard, User
from app.database.schemas import ClipboardIn, ClipboardPinUpdate
from app.services.serializers import make_tombstone_payload
from app.utilities.crypto_utils import strict_b64decode
from app.utilities.datetime_utils import ensure_utc, to_iso_utc
from app.websockets.connection_manager import manager


def allocate_batch_sync_sequence(db: Session, user_id: str, count: int = 1) -> int:
    user = db.scalars(select(User).where(User.user_id == user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if count <= 0:
        return int(user.sync_sequence or 0)

    db.execute(
        update(User).where(User.user_id == user_id).values(sync_sequence=User.sync_sequence + count)
    )
    db.refresh(user, attribute_names=["sync_sequence"])
    return int(user.sync_sequence or 0)


def allocate_sync_sequence(db: Session, user_id: str) -> int:
    return allocate_batch_sync_sequence(db, user_id, count=1)


def prune_user_clipboard(
    user_id: str, db: Session, retention_days: Optional[int] = None
) -> List[dict]:
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
    retention_days = Settings.CLIPBOARD_RETENTION_DAYS if retention_days is None else retention_days
    if retention_days <= 0:
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    candidate_stmt = (
        select(Clipboard.user_id)
        .where(
            Clipboard.is_deleted.is_(False),
            Clipboard.is_pinned.is_(False),
            Clipboard.updated_at < cutoff,
        )
        .distinct()
    )
    candidate_user_ids = list(db.scalars(candidate_stmt).all())
    if not candidate_user_ids:
        return []

    all_tombstones: List[Tuple[str, dict]] = []
    for user_id in candidate_user_ids:
        tombstones = prune_user_clipboard(user_id, db, retention_days=retention_days)
        all_tombstones.extend((user_id, tombstone) for tombstone in tombstones)
    return all_tombstones


def _evaluate_lww_conflict(
    existing: Clipboard,
    incoming_ts: datetime,
    incoming_ciphertext: Optional[bytes],
    incoming_nonce: Optional[bytes],
    incoming_device_id: Optional[str],
    is_incoming_tombstone: bool,
    incoming_is_pinned: Optional[bool] = None,
) -> Tuple[str, str]:
    existing_ts = ensure_utc(existing.timestamp)
    inc_ts = ensure_utc(incoming_ts)

    if not is_incoming_tombstone and not existing.is_deleted:
        if inc_ts > existing_ts:
            return "accept", "newer timestamp"
        elif inc_ts < existing_ts:
            return "reject", "stale timestamp"
        else:
            if existing.ciphertext == incoming_ciphertext and existing.nonce == incoming_nonce:
                if incoming_is_pinned is not None and existing.is_pinned != incoming_is_pinned:
                    return "accept", "pin status updated"
                return "noop", "identical payload and timestamp"

            existing_dev = existing.last_device_id or ""
            inc_dev = incoming_device_id or ""
            if inc_dev == existing_dev:
                return "reject", "same-device equal timestamp collision"

            # Lexicographical device_id tie-breaker for identical timestamps
            if inc_dev > existing_dev:
                return "accept", "tie-breaker won"
            else:
                return "reject", "tie-breaker lost"

    elif not is_incoming_tombstone and existing.is_deleted:
        if inc_ts > existing_ts:
            return "accept", "resurrection with newer timestamp"
        else:
            return "reject", "cannot resurrect tombstone with older or equal timestamp"

    elif is_incoming_tombstone and not existing.is_deleted:
        if inc_ts >= existing_ts:
            return "accept", "tombstone accepted"
        else:
            return "reject", "stale deletion cannot delete newer edit"

    else:
        if inc_ts > existing_ts:
            return "accept", "newer tombstone"
        return "noop", "existing tombstone preserved"


async def upsert_clipboard(
    db: Session,
    user_id: str,
    data: ClipboardIn,
    caller_device_id: Optional[str] = None,
) -> Tuple[Clipboard, str, bool]:
    raw_ciphertext = strict_b64decode(data.ciphertext, "ciphertext") if data.ciphertext else None
    raw_nonce = strict_b64decode(data.nonce, "nonce") if data.nonce else None
    incoming_ts = ensure_utc(data.timestamp)

    def mutate() -> Tuple[Clipboard, str, bool, bool, bool]:
        existing = db.scalars(
            select(Clipboard).where(Clipboard.user_id == user_id, Clipboard.clipboard_id == data.id)
        ).first()
        is_new = existing is None
        was_deleted = bool(existing and existing.is_deleted)

        if existing is not None:
            decision, reason = _evaluate_lww_conflict(
                existing,
                incoming_ts,
                raw_ciphertext,
                raw_nonce,
                caller_device_id,
                False,
                incoming_is_pinned=data.is_pinned,
            )
            if decision == "noop":
                return existing, "clipboard updated", is_new, was_deleted, True
            if decision == "reject":
                raise HTTPException(
                    status_code=409, detail=f"Conflict detected: write rejected ({reason})"
                )

            entry = existing
            entry.ciphertext = raw_ciphertext
            entry.nonce = raw_nonce
            entry.blob_version = data.blob_version
            entry.timestamp = incoming_ts
            entry.updated_at = datetime.now(timezone.utc)
            entry.is_deleted = False
            entry.deleted_at = None
            entry.is_pinned = data.is_pinned
            entry.pinned_at = (
                ensure_utc(data.pinned_at)
                if data.pinned_at
                else (datetime.now(timezone.utc) if data.is_pinned else None)
            )
            entry.entry_revision = (entry.entry_revision or 0) + 1
        else:
            entry = Clipboard(
                clipboard_id=data.id,
                user_id=user_id,
                ciphertext=raw_ciphertext,
                nonce=raw_nonce,
                blob_version=data.blob_version,
                timestamp=incoming_ts,
                is_deleted=False,
                deleted_at=None,
                is_pinned=data.is_pinned,
                pinned_at=ensure_utc(data.pinned_at)
                if data.pinned_at
                else (datetime.now(timezone.utc) if data.is_pinned else None),
                updated_at=datetime.now(timezone.utc),
                entry_revision=1,
            )
            db.add(entry)

        entry.change_number = allocate_sync_sequence(db, user_id)
        entry.last_device_id = caller_device_id
        return (
            entry,
            "clipboard updated" if not is_new else "clipboard synced",
            is_new,
            was_deleted,
            False,
        )

    entry, ret_status, is_new, was_deleted, is_noop = await async_run_in_write_transaction(
        db, mutate
    )
    db.refresh(entry)

    if is_noop:
        return entry, ret_status, True

    if is_new or was_deleted:
        for tombstone in prune_user_clipboard(user_id, db):
            await manager.broadcast_to_user(user_id=user_id, message=tombstone)

    await manager.broadcast_to_user(
        user_id=user_id,
        message={
            "type": "clipboard_sync",
            "id": entry.clipboard_id,
            "ciphertext": data.ciphertext,
            "nonce": data.nonce,
            "blob_version": entry.blob_version,
            "timestamp": to_iso_utc(entry.timestamp),
            "is_deleted": False,
            "is_pinned": entry.is_pinned,
            "pinned_at": to_iso_utc(entry.pinned_at) if entry.pinned_at else None,
            "change_number": entry.change_number,
            "entry_revision": entry.entry_revision,
            "last_device_id": entry.last_device_id,
        },
        exclude_device=caller_device_id,
    )
    return entry, ret_status, False


async def soft_delete_clipboard(
    db: Session,
    user_id: str,
    clipboard_id: str,
    caller_device_id: Optional[str] = None,
    client_timestamp: Optional[datetime] = None,
) -> Tuple[dict, bool]:
    now = datetime.now(timezone.utc)
    del_ts = ensure_utc(client_timestamp) if client_timestamp is not None else now

    def mutate() -> Optional[Clipboard]:
        entry = db.scalars(
            select(Clipboard).where(
                Clipboard.user_id == user_id, Clipboard.clipboard_id == clipboard_id
            )
        ).first()
        if entry is not None:
            decision, reason = _evaluate_lww_conflict(
                entry,
                del_ts,
                None,
                None,
                caller_device_id,
                True,
            )
            if decision == "reject":
                raise HTTPException(
                    status_code=409, detail=f"Conflict: deletion rejected ({reason})"
                )
            if decision == "noop":
                return None
        else:
            entry = Clipboard(
                clipboard_id=clipboard_id, user_id=user_id, blob_version=1, entry_revision=0
            )
            db.add(entry)

        entry.ciphertext = None
        entry.nonce = None
        entry.is_deleted = True
        entry.deleted_at = now
        entry.timestamp = del_ts
        entry.updated_at = now
        entry.is_pinned = False
        entry.pinned_at = None
        entry.change_number = allocate_sync_sequence(db, user_id)
        entry.entry_revision = (entry.entry_revision or 0) + 1
        entry.last_device_id = caller_device_id
        return entry

    entry = await async_run_in_write_transaction(db, mutate)
    if entry is None:
        return {"status": "clipboard deleted", "id": clipboard_id}, True
    db.refresh(entry)
    await manager.broadcast_to_user(
        user_id=user_id,
        message=make_tombstone_payload(
            clipboard_id=clipboard_id,
            blob_version=entry.blob_version,
            timestamp=entry.timestamp,
            change_number=entry.change_number,
            entry_revision=entry.entry_revision,
            last_device_id=entry.last_device_id,
        ),
        exclude_device=caller_device_id,
    )
    return {"status": "clipboard deleted", "id": clipboard_id}, False


async def update_pin_status(
    db: Session,
    user_id: str,
    clipboard_id: str,
    pin_data: ClipboardPinUpdate,
    caller_device_id: Optional[str] = None,
) -> Clipboard:
    def mutate() -> Clipboard:
        item = db.scalars(
            select(Clipboard).where(
                Clipboard.clipboard_id == clipboard_id, Clipboard.user_id == user_id
            )
        ).first()
        if not item:
            raise HTTPException(status_code=404, detail="Clipboard entry not found")
        if item.is_deleted:
            raise HTTPException(
                status_code=400, detail="Cannot pin or unpin a deleted clipboard entry"
            )

        item.is_pinned = pin_data.is_pinned
        now = datetime.now(timezone.utc)
        item.updated_at = now
        if pin_data.is_pinned:
            item.pinned_at = ensure_utc(pin_data.pinned_at) if pin_data.pinned_at else now
        else:
            item.pinned_at = None
        item.change_number = allocate_sync_sequence(db, user_id)
        item.entry_revision = (item.entry_revision or 0) + 1
        item.last_device_id = caller_device_id
        return item

    item = await async_run_in_write_transaction(db, mutate)
    db.refresh(item)

    broadcast_payload = {
        "type": "clipboard_pin",
        "id": item.clipboard_id,
        "is_pinned": item.is_pinned,
        "pinned_at": to_iso_utc(item.pinned_at) if item.pinned_at else None,
        "updated_at": to_iso_utc(item.updated_at),
        "change_number": item.change_number,
        "entry_revision": item.entry_revision,
        "last_device_id": item.last_device_id,
    }
    await manager.broadcast_to_user(
        user_id=user_id,
        message=broadcast_payload,
        exclude_device=caller_device_id,
    )

    return item
