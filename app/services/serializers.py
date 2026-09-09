import base64
from datetime import datetime, timezone
from typing import Any, Optional
from app.models.models import User, Clipboard, Device
from app.schemas.schemas import UserWithE2EE, ClipboardOut, DeviceOut
from app.utilities.helpers import to_iso_utc
from app.websockets.connection_manager import manager


def user_to_e2ee_response(user: User) -> UserWithE2EE:
    return UserWithE2EE(
        email=user.email,
        username=user.username,
        encrypted_master_key=base64.b64encode(user.encrypted_master_key).decode("utf-8"),
        salt=base64.b64encode(user.salt).decode("utf-8"),
        kdf_version=user.kdf_version,
    )


def clipboard_to_response(entry: Clipboard) -> ClipboardOut:
    return ClipboardOut(
        id=entry.clipboard_id,
        ciphertext=base64.b64encode(entry.ciphertext).decode("utf-8") if entry.ciphertext else None,
        nonce=base64.b64encode(entry.nonce).decode("utf-8") if entry.nonce else None,
        blob_version=entry.blob_version,
        timestamp=entry.timestamp,
        updated_at=entry.updated_at,
        is_deleted=entry.is_deleted,
        deleted_at=entry.deleted_at,
        is_pinned=bool(entry.is_pinned),
        pinned_at=entry.pinned_at,
        change_number=entry.change_number or 0,
        entry_revision=entry.entry_revision or 1,
        last_device_id=entry.last_device_id,
    )


def device_to_response(device: Device, user_id: Optional[str] = None) -> DeviceOut:
    uid = user_id or device.user_id
    return DeviceOut(
        device_id=device.device_id,
        device_name=device.device_name,
        os=device.os,
        last_seen=device.last_seen,
        is_online=manager.is_device_online(uid, device.device_id) if uid else False,
        push_enabled=bool(device.push_subscription),
    )


def make_tombstone_payload(
    clipboard_id: str,
    blob_version: int = 1,
    timestamp: Optional[Any] = None,
    change_number: Optional[int] = None,
    entry_revision: Optional[int] = None,
    last_device_id: Optional[str] = None,
) -> dict:
    if timestamp is None:
        ts_str = to_iso_utc(datetime.now(timezone.utc))
    elif isinstance(timestamp, str):
        ts_str = timestamp
    else:
        ts_str = to_iso_utc(timestamp)

    payload = {
        "type": "clipboard_sync",
        "id": clipboard_id,
        "is_deleted": True,
        "is_pinned": False,
        "pinned_at": None,
        "timestamp": ts_str,
        "ciphertext": None,
        "nonce": None,
        "blob_version": blob_version,
    }
    if change_number is not None:
        payload["change_number"] = change_number
    if entry_revision is not None:
        payload["entry_revision"] = entry_revision
    if last_device_id is not None:
        payload["last_device_id"] = last_device_id
    return payload
