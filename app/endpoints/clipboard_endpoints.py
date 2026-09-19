import asyncio
from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi_limiter.depends import RateLimiter
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.models import Clipboard, User
from app.database.schemas import (
    ClipboardIn,
    ClipboardOut,
    ClipboardPinUpdate,
    ClipboardSyncResponse,
    AuthContext,
)
from app.database.engine import async_run_in_write_transaction, get_db
from app.services.auth import get_auth_context
from app.services.clipboard_service import (
    allocate_batch_sync_sequence,
    soft_delete_clipboard,
    update_pin_status,
    upsert_clipboard,
)
from app.services.push_service import launch_background_push
from app.services.serializers import clipboard_to_response, make_tombstone_payload
from app.utilities.datetime_utils import ensure_utc
from app.websockets.connection_manager import manager

router = APIRouter()


@router.post("/clipboard", dependencies=[Depends(RateLimiter(times=30, seconds=60))])
async def sync_clipboard(
    data: ClipboardIn,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    user_id: str = auth.user.user_id
    caller_device_id = auth.device_id

    if data.is_deleted:
        res, is_noop = await soft_delete_clipboard(
            db=db,
            user_id=user_id,
            clipboard_id=data.id,
            caller_device_id=caller_device_id,
            client_timestamp=data.timestamp,
        )
        if not is_noop:
            launch_background_push(user_id=user_id, exclude_device=caller_device_id)
        return res

    entry, ret_status, is_noop = await upsert_clipboard(
        db=db,
        user_id=user_id,
        data=data,
        caller_device_id=caller_device_id,
    )
    if not is_noop:
        launch_background_push(user_id=user_id, exclude_device=caller_device_id)
    return {"status": ret_status, "id": entry.clipboard_id}


@router.get(
    "/clipboard",
    response_model=ClipboardOut,
    dependencies=[Depends(RateLimiter(times=30, seconds=60))],
)
def get_clipboard(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    user_id: str = auth.user.user_id

    stmt = (
        select(Clipboard)
        .where(Clipboard.user_id == user_id, Clipboard.is_deleted.is_(False))
        .order_by(Clipboard.timestamp.desc())
    )
    entry = db.scalars(stmt).first()
    if not entry:
        raise HTTPException(status_code=404, detail="No clipboard found")

    return clipboard_to_response(entry)


@router.get(
    "/clipboard/all",
    response_model=List[ClipboardOut],
    dependencies=[Depends(RateLimiter(times=20, seconds=60))],
)
def get_clipboard_all(
    include_deleted: bool = False,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    user_id: str = auth.user.user_id
    stmt = select(Clipboard).where(Clipboard.user_id == user_id)

    if not include_deleted:
        stmt = stmt.where(Clipboard.is_deleted.is_(False))

    stmt = stmt.order_by(Clipboard.timestamp.desc()).limit(limit)
    entries = list(db.scalars(stmt).all())

    return [clipboard_to_response(entry) for entry in entries]


@router.get(
    "/clipboard/sync",
    response_model=ClipboardSyncResponse,
    dependencies=[Depends(RateLimiter(times=20, seconds=60))],
)
def get_sync_clipboard(
    since_change_number: int = Query(..., ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    user_id: str = auth.user.user_id
    current_user: User = auth.user
    retention_days = Settings.TOMBSTONE_RETENTION_DAYS
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    oldest_entry = db.execute(
        select(Clipboard.change_number, Clipboard.updated_at)
        .where(Clipboard.user_id == user_id)
        .order_by(Clipboard.change_number.asc())
    ).first()
    if oldest_entry is not None:
        if since_change_number > 0 and since_change_number < oldest_entry.change_number - 1:
            raise HTTPException(
                status_code=410, detail="Sync state expired. Please wipe local data and resync."
            )
    else:
        if (current_user.sync_sequence or 0) > since_change_number:
            raise HTTPException(
                status_code=410, detail="Sync state expired. Please wipe local data and resync."
            )

    stmt = (
        select(Clipboard)
        .where(
            Clipboard.user_id == user_id,
            Clipboard.change_number > since_change_number,
        )
        .order_by(Clipboard.change_number.asc())
        .limit(limit + 1)
    )
    entries = list(db.scalars(stmt).all())

    entry_updated_at = ensure_utc(entries[0].updated_at) if entries else None
    if since_change_number > 0 and entry_updated_at is not None and entry_updated_at < cutoff:
        raise HTTPException(
            status_code=410, detail="Sync state expired. Please wipe local data and resync."
        )

    has_more = len(entries) > limit
    if has_more:
        entries = entries[:limit]

    next_cursor = entries[-1].change_number if entries else None

    return {
        "entries": [clipboard_to_response(entry) for entry in entries],
        "has_more": has_more,
        "next_cursor": next_cursor,
    }


@router.get(
    "/clipboard/{clipboard_id}",
    response_model=ClipboardOut,
    dependencies=[Depends(RateLimiter(times=30, seconds=60))],
)
def get_clipboard_by_id(
    clipboard_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    user_id: str = auth.user.user_id
    entry = db.scalars(
        select(Clipboard).where(Clipboard.clipboard_id == clipboard_id, Clipboard.user_id == user_id)
    ).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Clipboard entry not found")

    return clipboard_to_response(entry)


@router.patch(
    "/clipboard/{clipboard_id}/pin",
    response_model=ClipboardOut,
    dependencies=[Depends(RateLimiter(times=30, seconds=60))],
)
async def pin_clipboard_item(
    clipboard_id: str,
    data: ClipboardPinUpdate,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    user_id: str = auth.user.user_id
    caller_device_id = auth.device_id
    entry = await update_pin_status(
        db=db,
        user_id=user_id,
        clipboard_id=clipboard_id,
        pin_data=data,
        caller_device_id=caller_device_id,
    )
    launch_background_push(user_id=user_id, exclude_device=caller_device_id)
    return clipboard_to_response(entry)


@router.delete(
    "/clipboard/{clipboard_id}", dependencies=[Depends(RateLimiter(times=10, seconds=60))]
)
async def delete_clipboard_item(
    clipboard_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    user_id: str = auth.user.user_id
    caller_device_id = auth.device_id
    res, is_noop = await soft_delete_clipboard(
        db=db,
        user_id=user_id,
        clipboard_id=clipboard_id,
        caller_device_id=caller_device_id,
    )
    if not is_noop:
        launch_background_push(user_id=user_id, exclude_device=caller_device_id)
    return {"message": "Clipboard entry deleted"}


@router.delete("/clipboard", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def delete_clipboard_history(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    user_id: str = auth.user.user_id
    caller_device_id = auth.device_id
    chunk_size = 500

    def mutate():
        deleted_items = []
        now = datetime.now(timezone.utc)

        while True:
            stmt = (
                select(Clipboard)
                .where(
                    Clipboard.user_id == user_id,
                    Clipboard.is_deleted.is_(False),
                    Clipboard.is_pinned.is_(False),
                )
                .order_by(Clipboard.change_number.asc())
                .limit(chunk_size)
            )
            chunk = list(db.scalars(stmt).all())
            if not chunk:
                break

            final_seq = allocate_batch_sync_sequence(db, user_id, count=len(chunk))
            start_seq = final_seq - len(chunk) + 1

            for index, entry in enumerate(chunk):
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
                deleted_items.append(
                    make_tombstone_payload(
                        clipboard_id=entry.clipboard_id,
                        blob_version=entry.blob_version,
                        timestamp=now,
                        change_number=entry.change_number,
                        entry_revision=entry.entry_revision,
                        last_device_id=caller_device_id,
                    )
                )

            db.flush()

        return deleted_items, len(deleted_items)

    deleted_items, deleted_count = await async_run_in_write_transaction(db, mutate)
    if not deleted_items:
        return {"message": "No clipboard entries to delete."}

    broadcast_batch_size = 100
    for i in range(0, len(deleted_items), broadcast_batch_size):
        batch = deleted_items[i : i + broadcast_batch_size]
        await asyncio.gather(
            *(
                manager.broadcast_to_user(
                    user_id=user_id,
                    message=tombstone,
                    exclude_device=caller_device_id,
                )
                for tombstone in batch
            )
        )

    launch_background_push(user_id=user_id, exclude_device=caller_device_id)
    return {"message": f"{deleted_count} clipboard entries deleted."}
