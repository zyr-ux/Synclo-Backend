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
from app.schemas.schemas import ClipboardIn, ClipboardOut, ClipboardSyncResponse
from app.services.auth import get_db, get_current_user
from app.services.serializers import clipboard_to_response
from app.services.utils import cleanup_old_clipboard_entries
from app.websockets.connection_manager import manager

router = APIRouter()


@router.post("/clipboard", dependencies=[Depends(RateLimiter(times=30, seconds=60))])
def sync_clipboard(
    data: ClipboardIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    _cu: Any = current_user
    user_id: int = _cu.id
    # Clean old entries even on write to avoid unbounded growth if user never reads
    cleanup_old_clipboard_entries(user_id, db)

    if data.ciphertext is None or data.nonce is None:
        raise HTTPException(status_code=400, detail="ciphertext and nonce are required")

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

    new_timestamp = data.timestamp.replace(tzinfo=None) # Ensure naive for DB comparison if needed

    # Upsert Logic: Check if ID exists
    existing_entry = db.query(Clipboard).filter_by(id=data.id, user_id=user_id).first()

    if existing_entry:
        # Update existing
        _e: Any = existing_entry
        _e.ciphertext = ciphertext_bytes
        _e.nonce = nonce_bytes
        _e.blob_version = data.blob_version
        _e.timestamp = new_timestamp
        _e.is_pinned = data.is_pinned
        _e.updated_at = datetime.now(timezone.utc)
        db.commit()
        return {"status": "clipboard updated", "id": _e.id}
    else:
        # Insert new
        new_entry = Clipboard(
            id=data.id, # Use Client ID
            user_id=user_id,
            ciphertext=ciphertext_bytes,
            nonce=nonce_bytes,
            blob_version=data.blob_version,
            timestamp=new_timestamp, # Use Client Timestamp
            is_pinned=data.is_pinned,
            updated_at=datetime.now(timezone.utc)
        )
        db.add(new_entry)
        db.commit()

        _ne: Any = new_entry
        return {"status": "clipboard synced", "id": _ne.id}


@router.get("/clipboard", response_model=ClipboardOut, dependencies=[Depends(RateLimiter(times=30, seconds=60))])
def get_clipboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    _cu: Any = current_user
    user_id: int = _cu.id
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
    query = db.query(Clipboard).filter_by(user_id=_cu.id)

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
    # Safety Check: If 'since' is older than retention period, return 410 Gone
    # This forces the client to re-download everything, ensuring no zombie items (entries deleted on server but kept on client)
    if since:
        # Ensure since is aware
        since_utc = since.replace(tzinfo=timezone.utc) if since.tzinfo is None else since
        retention_days = Settings.TOMBSTONE_RETENTION_DAYS
        # Cutoff calculations
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        
        if since_utc < cutoff:
            # Client is too old. We might have deleted tombstones that they need to know about.
            # They must wipe and re-sync.
            raise HTTPException(status_code=410, detail="Sync state expired. Please wipe local data and resync.")

    _cu: Any = current_user
    query = db.query(Clipboard).filter(Clipboard.user_id == _cu.id)
    
    if since:
         # Ensure since is offset-aware UTC or naive treated as UTC
         since_utc = since.replace(tzinfo=timezone.utc) if since.tzinfo is None else since
         # Use updated_at for delta sync
         query = query.filter(Clipboard.updated_at > since_utc)
    
    # Order by updated_at asc to ensure we get the oldest changes first if limited
    # Apply offset and limit
    entries = query.order_by(Clipboard.updated_at.asc()).offset(offset).limit(limit).all()

    serialized = [clipboard_to_response(entry).model_dump() for entry in entries]

    return {
        "entries": serialized,
        "next_offset": offset + len(entries), # Useful for client sidebar/debugging if needed
        "has_more": len(entries) == limit,
        "total_count": len(entries) # This is just the page count, not total.
    }


@router.delete("/clipboard/{clipboard_id}", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def delete_clipboard_entry(
    clipboard_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    _cu: Any = current_user
    user_id: int = _cu.id
    # Idempotency: Check if item exists (tombstone or active)
    entry = db.query(Clipboard).filter_by(id=clipboard_id, user_id=user_id).first()

    # If not found, return success (idempotent)
    if not entry:
        return {"message": "Clipboard entry deleted"}

    # If already deleted, return success (idempotent)
    _entry: Any = entry
    if _entry.is_deleted:
        return {"message": "Clipboard entry deleted"}

    # Soft Delete
    _entry.is_deleted = True
    _entry.is_pinned = False
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
            "timestamp": _entry.deleted_at.isoformat() + "Z",
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
    user_id: int = _cu.id
    active_entries = db.query(Clipboard).filter_by(
        user_id=user_id,
        is_deleted=False,
        is_pinned=False
    ).all()

    if not active_entries:
        return {"message": "No clipboard entries to delete."}

    now = datetime.now(timezone.utc)
    clipboard_ids = []

    for entry in active_entries:
        _e: Any = entry
        _e.is_deleted = True
        _e.deleted_at = now
        _e.updated_at = now
        clipboard_ids.append(_e.id)
        
    db.commit()
    
    # Broadcast deletion of all entries
    for clipboard_id in clipboard_ids:
        await manager.broadcast_to_user(
            user_id=user_id,
            message={
                "id": clipboard_id,
                "is_deleted": True,
                "is_pinned": False,
                "timestamp": now.isoformat() + "Z",
                "ciphertext": None,
                "nonce": None,
                "blob_version": 1
            }
        )
    
    return {"message": f"{len(active_entries)} clipboard entries deleted."}
