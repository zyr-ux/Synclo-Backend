import asyncio
import base64
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi_limiter.depends import RateLimiter
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.constants import (
    ALLOWED_BLOB_VERSIONS,
    MIN_NONCE_LEN,
    MAX_NONCE_LEN,
    MAX_CIPHERTEXT_LEN,
)
from app.models.models import Clipboard, User
from app.schemas.schemas import ClipboardIn, ClipboardOut, ClipboardPinUpdate, ClipboardSyncResponse
from app.services.auth import get_db, get_current_user
from app.services.push_service import launch_background_push
from app.services.serializers import clipboard_to_response, make_tombstone_payload
from app.services.utils import prune_user_clipboard, ensure_utc
from app.websockets.connection_manager import manager


router = APIRouter()


async def _handle_tombstone(
    db: Session,
    user_id: str,
    data: ClipboardIn,
    new_timestamp: datetime,
    caller_device_id: Optional[str]
) -> dict:
    existing_entry = db.query(Clipboard).filter_by(clipboard_id=data.id, user_id=user_id).first()
    if existing_entry:
        existing_entry.ciphertext = None
        existing_entry.nonce = None
        existing_entry.blob_version = data.blob_version
        existing_entry.timestamp = new_timestamp
        existing_entry.is_deleted = True
        existing_entry.deleted_at = new_timestamp
        existing_entry.is_pinned = False
        existing_entry.pinned_at = None
        existing_entry.updated_at = datetime.now(timezone.utc)
        db.commit()
    else:
        new_entry = Clipboard(
            clipboard_id=data.id,
            user_id=user_id,
            ciphertext=None,
            nonce=None,
            blob_version=data.blob_version,
            timestamp=new_timestamp,
            is_deleted=True,
            deleted_at=new_timestamp,
            is_pinned=False,
            pinned_at=None,
            updated_at=datetime.now(timezone.utc)
        )
        db.add(new_entry)
        db.commit()

    await manager.broadcast_to_user(
        user_id=user_id,
        message=make_tombstone_payload(
            clipboard_id=data.id,
            blob_version=data.blob_version,
            timestamp=new_timestamp
        )
    )

    launch_background_push(user_id=user_id, exclude_device=caller_device_id)

    return {"status": "clipboard deleted", "id": data.id}


async def _handle_upsert(
    db: Session,
    user_id: str,
    data: ClipboardIn,
    new_timestamp: datetime,
    caller_device_id: Optional[str]
) -> dict:
    if data.ciphertext is None or data.nonce is None:
        raise HTTPException(status_code=400, detail="ciphertext and nonce are required for active entries")

    try:
        ciphertext_bytes = base64.b64decode(data.ciphertext)
        nonce_bytes = base64.b64decode(data.nonce)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding")

    if data.blob_version not in ALLOWED_BLOB_VERSIONS:
        raise HTTPException(status_code=400, detail="Unsupported blob_version")
    if not (MIN_NONCE_LEN <= len(nonce_bytes) <= MAX_NONCE_LEN):
        raise HTTPException(status_code=400, detail="nonce length out of bounds")
    if len(ciphertext_bytes) > MAX_CIPHERTEXT_LEN:
        raise HTTPException(status_code=400, detail="ciphertext too large")

    pinned_at = None
    if data.is_pinned:
        pinned_at = ensure_utc(data.pinned_at) if data.pinned_at else datetime.now(timezone.utc)

    existing_entry = db.query(Clipboard).filter_by(clipboard_id=data.id, user_id=user_id).first()
    ret_status = "clipboard synced"
    was_deleted = False
    if existing_entry:
        was_deleted = bool(existing_entry.is_deleted)
        existing_entry.ciphertext = ciphertext_bytes
        existing_entry.nonce = nonce_bytes
        existing_entry.blob_version = data.blob_version
        existing_entry.timestamp = new_timestamp
        existing_entry.is_deleted = False
        existing_entry.deleted_at = None
        existing_entry.is_pinned = data.is_pinned
        existing_entry.pinned_at = pinned_at
        existing_entry.updated_at = datetime.now(timezone.utc)
        db.commit()
        ret_status = "clipboard updated"
    else:
        new_entry = Clipboard(
            clipboard_id=data.id,
            user_id=user_id,
            ciphertext=ciphertext_bytes,
            nonce=nonce_bytes,
            blob_version=data.blob_version,
            timestamp=new_timestamp,
            is_deleted=False,
            deleted_at=None,
            is_pinned=data.is_pinned,
            pinned_at=pinned_at,
            updated_at=datetime.now(timezone.utc)
        )
        db.add(new_entry)
        db.commit()

    if not existing_entry or was_deleted:
        tombstones = prune_user_clipboard(user_id, db)
        for tombstone in tombstones:
            await manager.broadcast_to_user(
                user_id=user_id,
                message=tombstone
            )

    launch_background_push(user_id=user_id, exclude_device=caller_device_id)

    return {"status": ret_status, "id": data.id}


@router.post("/clipboard", dependencies=[Depends(RateLimiter(times=30, seconds=60))])
async def sync_clipboard(
    data: ClipboardIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user_id: str = current_user.user_id
    new_timestamp = ensure_utc(data.timestamp)
    caller_device_id = getattr(current_user, "current_device_id", None)

    if data.is_deleted:
        return await _handle_tombstone(db, user_id, data, new_timestamp, caller_device_id)
    return await _handle_upsert(db, user_id, data, new_timestamp, caller_device_id)


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
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Clipboard).filter_by(user_id=current_user.user_id)

    if not include_deleted:
        query = query.filter(Clipboard.is_deleted.is_(False))

    query = query.order_by(Clipboard.timestamp.desc())
    
    entries = query.all()
    
    return [clipboard_to_response(entry) for entry in entries]


@router.get("/clipboard/sync", response_model=ClipboardSyncResponse, dependencies=[Depends(RateLimiter(times=20, seconds=60))])
def get_sync_clipboard(
    since: Optional[datetime] = Query(None),
    limit: int = 1000,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user_id: str = current_user.user_id

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
        "total_count": total_count
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

    entry = db.query(Clipboard).filter_by(clipboard_id=clipboard_id, user_id=user_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Clipboard entry not found")

    if entry.is_deleted:
        raise HTTPException(status_code=400, detail="Cannot pin or unpin a deleted clipboard entry")

    now = datetime.now(timezone.utc)
    entry.is_pinned = data.is_pinned
    if data.is_pinned:
        if data.pinned_at:
            entry.pinned_at = ensure_utc(data.pinned_at)
        else:
            entry.pinned_at = now
    else:
        entry.pinned_at = None

    entry.updated_at = now
    db.commit()
    db.refresh(entry)

    await manager.broadcast_to_user(
        user_id=user_id,
        message={
            "type": "clipboard_pin",
            "id": clipboard_id,
            "is_pinned": entry.is_pinned,
            "pinned_at": entry.pinned_at.isoformat().replace("+00:00", "Z") if entry.pinned_at else None,
            "updated_at": entry.updated_at.isoformat().replace("+00:00", "Z")
        }
    )

    caller_device_id = getattr(current_user, "current_device_id", None)
    launch_background_push(user_id=user_id, exclude_device=caller_device_id)

    return clipboard_to_response(entry)


@router.delete("/clipboard/{clipboard_id}", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def delete_clipboard_item(
    clipboard_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user_id: str = current_user.user_id
    entry = db.query(Clipboard).filter_by(clipboard_id=clipboard_id, user_id=user_id).first()

    if not entry:
        return {"message": "Clipboard entry deleted"}

    if entry.is_deleted:
        return {"message": "Clipboard entry deleted"}

    entry.is_deleted = True
    entry.ciphertext = None
    entry.nonce = None
    entry.is_pinned = False
    entry.pinned_at = None
    entry.deleted_at = datetime.now(timezone.utc)
    entry.updated_at = datetime.now(timezone.utc)
    db.commit()
    
    await manager.broadcast_to_user(
        user_id=user_id,
        message=make_tombstone_payload(
            clipboard_id=clipboard_id,
            blob_version=entry.blob_version,
            timestamp=entry.deleted_at
        )
    )
    
    caller_device_id = getattr(current_user, "current_device_id", None)
    launch_background_push(user_id=user_id, exclude_device=caller_device_id)
    
    return {"message": "Clipboard entry deleted"}


@router.delete("/clipboard", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def delete_clipboard_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user_id: str = current_user.user_id
    active_entries = db.query(Clipboard).filter_by(
        user_id=user_id,
        is_deleted=False,
        is_pinned=False
    ).all()

    if not active_entries:
        return {"message": "No clipboard entries to delete."}

    now = datetime.now(timezone.utc)
    deleted_entries = []

    for entry in active_entries:
        entry.is_deleted = True
        entry.ciphertext = None
        entry.nonce = None
        entry.is_pinned = False
        entry.pinned_at = None
        entry.deleted_at = now
        entry.updated_at = now
        deleted_entries.append((entry.clipboard_id, entry.blob_version))
        
    db.commit()
    
    for clipboard_id, blob_version in deleted_entries:
        await manager.broadcast_to_user(
            user_id=user_id,
            message=make_tombstone_payload(
                clipboard_id=clipboard_id,
                blob_version=blob_version,
                timestamp=now
            )
        )
    
    caller_device_id = getattr(current_user, "current_device_id", None)
    launch_background_push(user_id=user_id, exclude_device=caller_device_id)
    
    return {"message": f"{len(active_entries)} clipboard entries deleted."}

