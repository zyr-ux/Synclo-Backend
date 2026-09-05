
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi_limiter.depends import RateLimiter
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.models import Clipboard, User
from app.schemas.schemas import ClipboardIn, ClipboardOut, ClipboardPinUpdate, ClipboardSyncResponse
from app.core.database import run_in_write_transaction
from app.services.auth import get_db, get_current_user
from app.services.clipboard_service import (
    allocate_batch_sync_sequence,

    soft_delete_clipboard,
    update_pin_status,
    upsert_clipboard,
)
from app.services.push_service import launch_background_push
from app.services.serializers import clipboard_to_response, make_tombstone_payload
from app.utilities.helpers import ensure_utc
from app.websockets.connection_manager import manager

router = APIRouter()


@router.post("/clipboard", dependencies=[Depends(RateLimiter(times=30, seconds=60))])
async def sync_clipboard(
    data: ClipboardIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user_id: str = current_user.user_id
    caller_device_id = getattr(current_user, "current_device_id", None)

    if data.is_deleted:
        await soft_delete_clipboard(
            db=db,
            user_id=user_id,
            clipboard_id=data.id,
            caller_device_id=caller_device_id,
            client_timestamp=data.timestamp,
        )
        launch_background_push(user_id=user_id, exclude_device=caller_device_id)
        return {"status": "clipboard deleted", "id": data.id}

    entry, ret_status = await upsert_clipboard(
        db=db,
        user_id=user_id,
        data=data,
        caller_device_id=caller_device_id,
    )
    launch_background_push(user_id=user_id, exclude_device=caller_device_id)
    return {"status": ret_status, "id": entry.clipboard_id}


@router.get("/clipboard", response_model=ClipboardOut, dependencies=[Depends(RateLimiter(times=30, seconds=60))])
def get_clipboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user_id: str = current_user.user_id

    entry = (
        db.query(Clipboard)
        .filter(Clipboard.user_id == user_id, Clipboard.is_deleted.is_(False))
        .order_by(Clipboard.timestamp.desc())
        .first()
    )
    if not entry:
        raise HTTPException(status_code=404, detail="No clipboard found")

    return clipboard_to_response(entry)


@router.get("/clipboard/all", response_model=List[ClipboardOut], dependencies=[Depends(RateLimiter(times=20, seconds=60))])
def get_clipboard_all(
    include_deleted: bool = False,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Clipboard).filter_by(user_id=current_user.user_id)

    if not include_deleted:
        query = query.filter(Clipboard.is_deleted.is_(False))

    query = query.order_by(Clipboard.timestamp.desc()).limit(limit)
    entries = query.all()

    return [clipboard_to_response(entry) for entry in entries]


@router.get("/clipboard/sync", response_model=ClipboardSyncResponse, dependencies=[Depends(RateLimiter(times=20, seconds=60))])
def get_sync_clipboard(
    since_change_number: Optional[int] = Query(None, ge=0),
    since: Optional[datetime] = Query(None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user_id: str = current_user.user_id

    if since_change_number is not None:
        entries = (
            db.query(Clipboard)
            .filter(
                Clipboard.user_id == user_id,
                Clipboard.change_number > since_change_number,
            )
            .order_by(Clipboard.change_number.asc())
            .limit(limit + 1)
            .all()
        )
        has_more = len(entries) > limit
        if has_more:
            entries = entries[:limit]

        next_cursor = entries[-1].change_number if entries else None

        return {
            "entries": [clipboard_to_response(entry) for entry in entries],
            "next_offset": offset + len(entries),
            "has_more": has_more,
            "total_count": None,
            "next_cursor": next_cursor,
        }

    # Legacy timestamp / offset fallback
    query = db.query(Clipboard).filter(Clipboard.user_id == user_id)
    if since:
        since_utc = ensure_utc(since)
        retention_days = Settings.TOMBSTONE_RETENTION_DAYS
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        if since_utc < cutoff:
            raise HTTPException(status_code=410, detail="Sync state expired. Please wipe local data and resync.")
        query = query.filter(Clipboard.updated_at > since_utc)

    total_count = query.count()
    entries = query.order_by(Clipboard.updated_at.asc()).offset(offset).limit(limit).all()

    return {
        "entries": [clipboard_to_response(entry) for entry in entries],
        "next_offset": offset + len(entries),
        "has_more": (offset + len(entries)) < total_count,
        "total_count": total_count,
        "next_cursor": entries[-1].change_number if entries else None,
    }


@router.get("/clipboard/{clipboard_id}", response_model=ClipboardOut, dependencies=[Depends(RateLimiter(times=30, seconds=60))])
def get_clipboard_by_id(
    clipboard_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user_id: str = current_user.user_id
    entry = db.query(Clipboard).filter_by(clipboard_id=clipboard_id, user_id=user_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Clipboard entry not found")

    return clipboard_to_response(entry)


@router.patch("/clipboard/{clipboard_id}/pin", response_model=ClipboardOut, dependencies=[Depends(RateLimiter(times=30, seconds=60))])
async def pin_clipboard_item(
    clipboard_id: str,
    data: ClipboardPinUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user_id: str = current_user.user_id
    caller_device_id = getattr(current_user, "current_device_id", None)
    entry = await update_pin_status(
        db=db,
        user_id=user_id,
        clipboard_id=clipboard_id,
        pin_data=data,
        caller_device_id=caller_device_id,
    )
    launch_background_push(user_id=user_id, exclude_device=caller_device_id)
    return clipboard_to_response(entry)


@router.delete("/clipboard/{clipboard_id}", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def delete_clipboard_item(
    clipboard_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user_id: str = current_user.user_id
    caller_device_id = getattr(current_user, "current_device_id", None)
    await soft_delete_clipboard(
        db=db,
        user_id=user_id,
        clipboard_id=clipboard_id,
        caller_device_id=caller_device_id,
    )
    launch_background_push(user_id=user_id, exclude_device=caller_device_id)
    return {"message": "Clipboard entry deleted"}


@router.delete("/clipboard", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def delete_clipboard_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user_id: str = current_user.user_id
    caller_device_id = getattr(current_user, "current_device_id", None)

    def mutate():
        active_entries = (
            db.query(Clipboard)
            .filter(
                Clipboard.user_id == user_id,
                Clipboard.is_deleted.is_(False),
                Clipboard.is_pinned.is_(False),
            )
            .all()
        )
        if not active_entries:
            return [], 0

        now = datetime.now(timezone.utc)
        final_seq = allocate_batch_sync_sequence(db, user_id, count=len(active_entries))
        start_seq = final_seq - len(active_entries) + 1
        deleted_items = []
        for index, entry in enumerate(active_entries):
            entry.is_deleted = True
            entry.ciphertext = None
            entry.nonce = None
            entry.is_pinned = False
            entry.pinned_at = None
            entry.deleted_at = now
            entry.timestamp = now
            entry.updated_at = now
            entry.change_number = start_seq + index
            entry.entry_revision = (entry.entry_revision or 0) + 1
            entry.last_device_id = caller_device_id
            deleted_items.append(make_tombstone_payload(
                clipboard_id=entry.clipboard_id, blob_version=entry.blob_version,
                timestamp=now, change_number=entry.change_number,
                entry_revision=entry.entry_revision, last_device_id=caller_device_id,
            ))
        return deleted_items, len(active_entries)

    deleted_items, deleted_count = run_in_write_transaction(db, mutate)
    if not deleted_items:
        return {"message": "No clipboard entries to delete."}

    for tombstone in deleted_items:
        await manager.broadcast_to_user(
            user_id=user_id,
            message=tombstone,
            exclude_device=caller_device_id,
        )

    launch_background_push(user_id=user_id, exclude_device=caller_device_id)
    return {"message": f"{deleted_count} clipboard entries deleted."}
