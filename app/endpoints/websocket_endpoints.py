import asyncio
import base64
from datetime import datetime, timezone
import traceback
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt

from app.core.database import SessionLocal
from app.core.config import Settings
from app.core.constants import (
    ALLOWED_BLOB_VERSIONS,
    MIN_NONCE_LEN,
    MAX_NONCE_LEN,
    MAX_CIPHERTEXT_LEN,
    LOOPBACK_HOSTS,
)
from app.core.logging_config import logger
from app.models.models import Clipboard, User, Device, BlacklistedToken
from app.services.auth import SECRET_KEY, ALGORITHM
from app.services.push_service import launch_background_push
from app.services.utils import prune_user_clipboard, parse_iso_utc, to_iso_utc
from app.websockets.connection_manager import manager


router = APIRouter()


async def _validate_ws_security(websocket: WebSocket) -> bool:
    if Settings.HTTPS_ONLY:
        # Proxies terminate TLS and forward X-Forwarded-Proto
        forwarded_proto = websocket.headers.get("x-forwarded-proto", "").lower()
        is_secure = websocket.url.scheme == "wss" or forwarded_proto in ("https", "wss")
        is_loopback = websocket.url.hostname in LOOPBACK_HOSTS
        if not is_secure and not is_loopback:
            logger.warning("WebSocket connection rejected: HTTPS_ONLY is enabled and connection is insecure")
            await websocket.send_json({"type": "error", "message": "Insecure WebSocket connection rejected (WSS required)"})
            await websocket.close(code=1008)
            return False
    return True


async def _authenticate_ws(websocket: WebSocket) -> Optional[tuple[str, str, int]]:
    auth_header = websocket.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        logger.warning("WebSocket connection attempted without Bearer token")
        await websocket.send_json({"type": "error", "message": "Missing or invalid Authorization header"})
        await websocket.close(code=1008)
        return None

    token = auth_header[7:]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        exp = payload.get("exp")
        device_id = payload.get("device_id")

        if not email or not exp or not device_id:
            logger.warning(f"WebSocket token missing required fields: email={email}, exp={exp}, device_id={device_id}")
            await websocket.send_json({"type": "error", "message": "Invalid token: missing required fields"})
            await websocket.close(code=1008)
            return None
    except JWTError as e:
        logger.warning(f"WebSocket token validation failed: {e}")
        await websocket.send_json({"type": "error", "message": "Invalid token"})
        await websocket.close(code=1008)
        return None

    db = SessionLocal()
    try:
        if db.query(BlacklistedToken).filter_by(token=token).first():
            logger.warning(f"WebSocket connection attempted with blacklisted token for {email}")
            await websocket.send_json({"type": "error", "message": "Token has been revoked"})
            await websocket.close(code=1008)
            return None

        user = db.query(User).filter(User.email == email).first()
        if not user:
            logger.warning(f"WebSocket connection attempted for non-existent user: {email}")
            await websocket.send_json({"type": "error", "message": "User not found"})
            await websocket.close(code=1008)
            return None

        device = db.query(Device).filter_by(user_id=user.user_id, device_id=device_id).first()
        if not device:
            logger.warning(f"WebSocket connection attempted with unauthorized device {device_id} for user {email}")
            await websocket.send_json({"type": "error", "message": "Unauthorized device"})
            await websocket.close(code=1008)
            return None

        return user.user_id, device_id, exp
    finally:
        db.close()


def _update_device_last_seen(user_id: str, device_id: str):
    session = SessionLocal()
    try:
        dev = session.query(Device).filter_by(user_id=user_id, device_id=device_id).first()
        if dev:
            dev.last_seen = datetime.now(timezone.utc)
            session.commit()
    except Exception as err:
        session.rollback()
        logger.warning(f"Failed to update device last_seen: {err}")
    finally:
        session.close()


def _save_clipboard_entry(
    user_id: str,
    msg_id: str,
    msg_ts: datetime,
    is_deleted: bool,
    is_pinned: bool,
    pinned_at_val: Optional[datetime],
    ciphertext_bytes: Optional[bytes],
    nonce_bytes: Optional[bytes],
    blob_version: int
) -> dict:
    session = SessionLocal()
    try:
        existing = session.query(Clipboard).filter_by(clipboard_id=msg_id, user_id=user_id).first()

        if existing:
            existing.is_deleted = is_deleted
            existing.timestamp = msg_ts
            existing.blob_version = blob_version

            if is_deleted:
                existing.ciphertext = None
                existing.nonce = None
                existing.is_pinned = False
                existing.pinned_at = None
                existing.deleted_at = msg_ts
                existing.updated_at = datetime.now(timezone.utc)
            else:
                existing.ciphertext = ciphertext_bytes
                existing.nonce = nonce_bytes
                existing.is_pinned = is_pinned
                existing.pinned_at = pinned_at_val
                existing.deleted_at = None
                existing.updated_at = datetime.now(timezone.utc)

            session.commit()
            entry_resp = {
                "id": existing.clipboard_id,
                "timestamp": existing.timestamp,
                "is_deleted": existing.is_deleted,
                "is_pinned": existing.is_pinned,
                "pinned_at": existing.pinned_at,
                "blob_version": existing.blob_version
            }
        else:
            new_entry = Clipboard(
                clipboard_id=msg_id,
                user_id=user_id,
                ciphertext=ciphertext_bytes,
                nonce=nonce_bytes,
                blob_version=blob_version,
                timestamp=msg_ts,
                is_deleted=is_deleted,
                is_pinned=is_pinned if not is_deleted else False,
                pinned_at=pinned_at_val if not is_deleted else None,
                deleted_at=msg_ts if is_deleted else None,
                updated_at=datetime.now(timezone.utc)
            )
            session.add(new_entry)
            session.commit()
            entry_resp = {
                "id": new_entry.clipboard_id,
                "timestamp": new_entry.timestamp,
                "is_deleted": new_entry.is_deleted,
                "is_pinned": new_entry.is_pinned,
                "pinned_at": new_entry.pinned_at,
                "blob_version": new_entry.blob_version
            }

        pruned_tombstones = []
        if not is_deleted and not existing:
            pruned_tombstones = prune_user_clipboard(user_id, session)

        entry_resp["pruned_tombstones"] = pruned_tombstones
        return entry_resp
    except Exception as e:
        session.rollback()
        return {"error": str(e)}
    finally:
        session.close()


async def _process_clipboard_message(
    websocket: WebSocket,
    user_id: str,
    device_id: str,
    data: dict
):
    msg_id = data.get("id")
    is_deleted = data.get("is_deleted", False)
    is_pinned = data.get("is_pinned", False)
    pinned_at_str = data.get("pinned_at")

    msg_ts_str = data.get("timestamp")
    ciphertext = data.get("ciphertext")
    nonce = data.get("nonce")
    blob_version = data.get("blob_version", 1)

    if not msg_id or not msg_ts_str:
        await websocket.send_json({"type": "error", "message": "Missing required fields (id, timestamp)"})
        return

    if not is_deleted:
        if not ciphertext or not nonce:
            await websocket.send_json({"type": "error", "message": "Missing ciphertext/nonce for active entry"})
            return
    else:
        ciphertext = None
        nonce = None

    try:
        msg_ts = parse_iso_utc(msg_ts_str)
    except ValueError:
        await websocket.send_json({"type": "error", "message": "Invalid timestamp format (ISO8601 required)"})
        return

    pinned_at_val = None
    if is_pinned and not is_deleted:
        if pinned_at_str:
            try:
                pinned_at_val = parse_iso_utc(pinned_at_str)
            except ValueError:
                await websocket.send_json({"type": "error", "message": "Invalid pinned_at format (ISO8601 required)"})
                return
        else:
            pinned_at_val = datetime.now(timezone.utc)

    ciphertext_bytes = None
    nonce_bytes = None

    if not is_deleted:
        if ciphertext is None or nonce is None:
            await websocket.send_json({"type": "error", "message": "Missing ciphertext/nonce"})
            return
        try:
            ciphertext_bytes = base64.b64decode(ciphertext)
            nonce_bytes = base64.b64decode(nonce)
        except Exception:
            await websocket.send_json({"type": "error", "message": "Invalid base64 encoding"})
            return

        if blob_version not in ALLOWED_BLOB_VERSIONS:
            await websocket.send_json({"type": "error", "message": "Unsupported blob_version"})
            return
        if not (MIN_NONCE_LEN <= len(nonce_bytes) <= MAX_NONCE_LEN):
            await websocket.send_json({"type": "error", "message": "nonce length out of bounds"})
            return
        if len(ciphertext_bytes) > MAX_CIPHERTEXT_LEN:
            await websocket.send_json({"type": "error", "message": "ciphertext too large"})
            return

    entry_data = await asyncio.to_thread(
        _save_clipboard_entry,
        user_id,
        msg_id,
        msg_ts,
        is_deleted,
        is_pinned,
        pinned_at_val,
        ciphertext_bytes,
        nonce_bytes,
        blob_version
    )

    if "error" in entry_data:
        logger.error(f"DB Error processing clipboard item: {entry_data['error']}")
        return

    broadcast_payload = {
        "type": "clipboard_sync",
        "id": entry_data["id"],
        "timestamp": to_iso_utc(entry_data["timestamp"]),
        "is_deleted": entry_data["is_deleted"],
        "is_pinned": entry_data["is_pinned"],
        "pinned_at": to_iso_utc(entry_data.get("pinned_at")),
        "blob_version": entry_data["blob_version"],
        "ciphertext": ciphertext if not entry_data["is_deleted"] else None,
        "nonce": nonce if not entry_data["is_deleted"] else None,
    }

    await manager.broadcast_to_user(
        user_id=user_id,
        message=broadcast_payload,
        exclude_device=device_id
    )

    launch_background_push(user_id=user_id, exclude_device=device_id)

    for tombstone in entry_data.get("pruned_tombstones", []):
        await manager.broadcast_to_user(
            user_id=user_id,
            message=tombstone
        )

    await websocket.send_json({
        "type": "ack",
        "id": entry_data["id"]
    })


@router.websocket("/sync")
async def websocket_sync(websocket: WebSocket):
    await websocket.accept()

    if not await _validate_ws_security(websocket):
        return

    auth_result = await _authenticate_ws(websocket)
    if auth_result is None:
        return

    user_id, device_id, exp = auth_result

    logger.info(f"WebSocket connection accepted for user_id={user_id}, device_id={device_id}")
    await manager.connect(user_id, device_id, websocket)
    await asyncio.to_thread(_update_device_last_seen, user_id, device_id)

    try:
        while True:
            if datetime.now(timezone.utc).timestamp() >= exp:
                await websocket.send_json({"type": "error", "message": "Token expired"})
                await websocket.close(code=4001)
                break

            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=45)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
                try:
                    pong = await asyncio.wait_for(websocket.receive_json(), timeout=10)
                    if pong.get("type") != "pong":
                        raise ValueError("Invalid pong")
                    await asyncio.to_thread(_update_device_last_seen, user_id, device_id)
                    continue
                except WebSocketDisconnect:
                    logger.warning("Client disconnected during ping/pong")
                    break
                except Exception as e:
                    logger.warning(f"WebSocket ping/pong failed: {e}")
                    try:
                        await websocket.close(code=4002)
                    except RuntimeError:
                        pass
                    break

            if data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
                await asyncio.to_thread(_update_device_last_seen, user_id, device_id)
                continue

            await _process_clipboard_message(websocket, user_id, device_id, data)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        logger.error(traceback.format_exc())
        try:
            await websocket.close(code=1011)
        except RuntimeError:
            pass
    finally:
        manager.disconnect(user_id, device_id)
        await asyncio.to_thread(_update_device_last_seen, user_id, device_id)
