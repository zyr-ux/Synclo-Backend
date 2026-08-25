# app/endpoints/clipboard_endpoints.py

import base64
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
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
from app.services.serializers import clipboard_to_response
from app.services.utils import cleanup_old_clipboard_entries
from app.websockets.connection_manager import manager

router = APIRouter()


@router.post("/clipboard", dependencies=[Depends(RateLimiter(times=30, seconds=60))])
async def sync_clipboard(
    data: ClipboardIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    _cu: Any = current_user
    user_id: str = _cu.user_id
    # Clean old entries even on write to avoid unbounded growth if user never reads
    cleanup_old_clipboard_entries(user_id, db)

    new_timestamp = data.timestamp.replace(tzinfo=timezone.utc) if data.timestamp.tzinfo is None else data.timestamp

    if data.is_deleted:
        # Tombstone handling (mirroring WebSocket delete events)
        existing_entry = db.query(Clipboard).filter_by(clipboard_id=data.id, user_id=user_id).first()

        if existing_entry:
            _e: Any = existing_entry
            _e.ciphertext = None
            _e.nonce = None
            _e.blob_version = data.blob_version
            _e.timestamp = new_timestamp
            _e.is_deleted = True
            _e.deleted_at = new_timestamp
            _e.is_pinned = False
            _e.pinned_at = None
            _e.updated_at = datetime.now(timezone.utc)
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

        # Broadcast deletion to all connected devices
        await manager.broadcast_to_user(
            user_id=user_id,
            message={
                "id": data.id,
                "is_deleted": True,
                "is_pinned": False,
                "pinned_at": None,
                "timestamp": new_timestamp.isoformat().replace("+00:00", "Z"),
                "ciphertext": None,
                "nonce": None,
                "blob_version": data.blob_version
            }
        )

        return {"status": "clipboard deleted", "id": data.id}

    # Active Entry Handling
    if data.ciphertext is None or data.nonce is None:
        raise HTTPException(status_code=400, detail="ciphertext and nonce are required for active entries")

    # Decode base64 binary data
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
        if data.pinned_at:
            pinned_at = data.pinned_at.replace(tzinfo=timezone.utc) if data.pinned_at.tzinfo is None else data.pinned_at
        else:
            pinned_at = datetime.now(timezone.utc)

    # Upsert Logic: Check if ID exists
    existing_entry = db.query(Clipboard).filter_by(clipboard_id=data.id, user_id=user_id).first()

    if existing_entry:
        # Update existing
        _e: Any = existing_entry
        _e.ciphertext = ciphertext_bytes
        _e.nonce = nonce_bytes
        _e.blob_version = data.blob_version
        _e.timestamp = new_timestamp
        _e.is_deleted = False
        _e.deleted_at = None
        _e.is_pinned = data.is_pinned
        _e.pinned_at = pinned_at
        _e.updated_at = datetime.now(timezone.utc)
        db.commit()
        return {"status": "clipboard updated", "id": _e.clipboard_id}
    else:
        # Insert new
        new_entry = Clipboard(
            clipboard_id=data.id, # Use Client ID
            user_id=user_id,
            ciphertext=ciphertext_bytes,
            nonce=nonce_bytes,
            blob_version=data.blob_version,
            timestamp=new_timestamp, # Use Client Timestamp
            is_deleted=False,
            deleted_at=None,
            is_pinned=data.is_pinned,
            pinned_at=pinned_at,
            updated_at=datetime.now(timezone.utc)
        )
        db.add(new_entry)
        db.commit()

        _ne: Any = new_entry
        return {"status": "clipboard synced", "id": _ne.clipboard_id}


@router.get("/clipboard", response_model=ClipboardOut, dependencies=[Depends(RateLimiter(times=30, seconds=60))])
def get_clipboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    _cu: Any = current_user
    user_id: str = _cu.user_id
    cleanup_old_clipboard_entries(user_id, db)

    entry = (
        db.query(Clipboard)
        .filter_by(user_id=user_id)
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
    _cu: Any = current_user
    query = db.query(Clipboard).filter_by(user_id=_cu.user_id)

    # Default behavior: exclude deleted items unless explicitly requested
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
    _cu: Any = current_user
    user_id: str = _cu.user_id

    # Safety Check: If 'since' is older than retention period, return 410 Gone
    if since:
        since_utc = since.replace(tzinfo=timezone.utc) if since.tzinfo is None else since
        retention_days = Settings.TOMBSTONE_RETENTION_DAYS
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        if since_utc < cutoff:
            raise HTTPException(status_code=410, detail="Sync state expired. Please wipe local data and resync.")

    query = db.query(Clipboard).filter(Clipboard.user_id == user_id)
    if since:
        since_utc = since.replace(tzinfo=timezone.utc) if since.tzinfo is None else since
        query = query.filter(Clipboard.updated_at > since_utc)

    entries = query.order_by(Clipboard.updated_at.asc()).offset(offset).limit(limit).all()

    return {
        "entries": [clipboard_to_response(entry).model_dump() for entry in entries],
        "next_offset": offset + len(entries),
        "has_more": len(entries) == limit,
        "total_count": len(entries)
    }


@router.get("/clipboard/{clipboard_id}", response_model=ClipboardOut, dependencies=[Depends(RateLimiter(times=30, seconds=60))])
def get_clipboard_by_id(
    clipboard_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    _cu: Any = current_user
    user_id: str = _cu.user_id
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
    _cu: Any = current_user
    user_id: str = _cu.user_id

    entry = db.query(Clipboard).filter_by(clipboard_id=clipboard_id, user_id=user_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Clipboard entry not found")

    _entry: Any = entry
    if _entry.is_deleted:
        raise HTTPException(status_code=400, detail="Cannot pin or unpin a deleted clipboard entry")

    now = datetime.now(timezone.utc)
    _entry.is_pinned = data.is_pinned
    if data.is_pinned:
        if data.pinned_at:
            _entry.pinned_at = data.pinned_at.replace(tzinfo=timezone.utc) if data.pinned_at.tzinfo is None else data.pinned_at
        else:
            _entry.pinned_at = now
    else:
        _entry.pinned_at = None

    _entry.updated_at = now
    db.commit()
    db.refresh(entry)

    # Broadcast lightweight pin update event to all connected devices for this user
    await manager.broadcast_to_user(
        user_id=user_id,
        message={
            "type": "clipboard_pin",
            "id": clipboard_id,
            "is_pinned": _entry.is_pinned,
            "pinned_at": _entry.pinned_at.isoformat().replace("+00:00", "Z") if _entry.pinned_at else None,
            "updated_at": _entry.updated_at.isoformat().replace("+00:00", "Z")
        }
    )

    return clipboard_to_response(entry)


@router.delete("/clipboard/{clipboard_id}", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def delete_clipboard_item(
    clipboard_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    _cu: Any = current_user
    user_id: str = _cu.user_id
    # Idempotency: Check if item exists (tombstone or active)
    entry = db.query(Clipboard).filter_by(clipboard_id=clipboard_id, user_id=user_id).first()

    # If not found, return success (idempotent)
    if not entry:
        return {"message": "Clipboard entry deleted"}

    # If already deleted, return success (idempotent)
    _entry: Any = entry
    if _entry.is_deleted:
        return {"message": "Clipboard entry deleted"}

    # Soft Delete
    _entry.is_deleted = True
    _entry.ciphertext = None
    _entry.nonce = None
    _entry.is_pinned = False
    _entry.pinned_at = None
    _entry.deleted_at = datetime.now(timezone.utc)
    _entry.updated_at = datetime.now(timezone.utc)
    db.commit()
    
    # Broadcast deletion to all connected devices
    await manager.broadcast_to_user(
        user_id=user_id,
        message={
            "id": clipboard_id,
            "is_deleted": True,
            "is_pinned": False,
            "pinned_at": None,
            "timestamp": _entry.deleted_at.isoformat().replace("+00:00", "Z"),
            "ciphertext": None,
            "nonce": None,
            "blob_version": _entry.blob_version
        }
    )
    
    return {"message": "Clipboard entry deleted"}


@router.delete("/clipboard", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def delete_clipboard_history(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Soft delete all active entries
    _cu: Any = current_user
    user_id: str = _cu.user_id
    active_entries = db.query(Clipboard).filter_by(
        user_id=user_id,
        is_deleted=False,
        is_pinned=False
    ).all()

    if not active_entries:
        return {"message": "No clipboard entries to delete."}

    now = datetime.now(timezone.utc)
    deleted_entries = []  # (clipboard_id, blob_version) pairs

    for entry in active_entries:
        _e: Any = entry
        _e.is_deleted = True
        _e.ciphertext = None
        _e.nonce = None
        _e.is_pinned = False
        _e.pinned_at = None
        _e.deleted_at = now
        _e.updated_at = now
        deleted_entries.append((_e.clipboard_id, _e.blob_version))
        
    db.commit()
    
    # Broadcast deletion of all entries
    for clipboard_id, blob_version in deleted_entries:
        await manager.broadcast_to_user(
            user_id=user_id,
            message={
                "id": clipboard_id,
                "is_deleted": True,
                "is_pinned": False,
                "pinned_at": None,
                "timestamp": now.isoformat().replace("+00:00", "Z"),
                "ciphertext": None,
                "nonce": None,
                "blob_version": blob_version
            }
        )
    
    return {"message": f"{len(active_entries)} clipboard entries deleted."}
