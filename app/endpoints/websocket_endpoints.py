# app/endpoints/websocket_endpoints.py

import asyncio
import base64
from datetime import datetime, timezone
import traceback
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt

from app.core.database import SessionLocal
from app.core.config import Settings
from app.core.constants import (
    ALLOWED_BLOB_VERSIONS,
    MIN_NONCE_LEN,
    MAX_NONCE_LEN,
    MAX_CIPHERTEXT_LEN,
)
from app.core.logging_config import logger
from app.models.models import Clipboard, User, Device, BlacklistedToken
from app.services.auth import SECRET_KEY, ALGORITHM
from app.services.push_service import launch_background_push
from app.services.utils import prune_user_clipboard
from app.websockets.connection_manager import manager


router = APIRouter()


@router.websocket("/sync")
async def websocket_sync(websocket: WebSocket):
    # Accept the connection first - we MUST do this before any close operations
    await websocket.accept()

    # If HTTPS_ONLY is enabled, reject insecure WebSocket connections from non-loopback clients
    if Settings.HTTPS_ONLY:
        forwarded_proto = websocket.headers.get("x-forwarded-proto", "").lower()
        is_secure = websocket.url.scheme == "wss" or forwarded_proto in ("https", "wss")
        is_loopback = websocket.url.hostname in {"localhost", "127.0.0.1", "::1", "testserver"}
        if not is_secure and not is_loopback:
            logger.warning("WebSocket connection rejected: HTTPS_ONLY is enabled and connection is insecure")
            await websocket.send_json({"type": "error", "message": "Insecure WebSocket connection rejected (WSS required)"})
            await websocket.close(code=1008)
            return
    
    # Extract token from Authorization header
    auth_header = websocket.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        logger.warning("WebSocket connection attempted without Bearer token")
        await websocket.send_json({"type": "error", "message": "Missing or invalid Authorization header"})
        await websocket.close(code=1008)
        return
    
    token = auth_header[7:]  # Remove "Bearer " prefix
    
    # Now decode and validate the token to extract user info
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        exp = payload.get("exp")
        device_id = payload.get("device_id")

        if not email or not exp or not device_id:
            logger.warning(f"WebSocket token missing required fields: email={email}, exp={exp}, device_id={device_id}")
            await websocket.send_json({"type": "error", "message": "Invalid token: missing required fields"})
            await websocket.close(code=1008)
            return
    except JWTError as e:
        logger.warning(f"WebSocket token validation failed: {e}")
        await websocket.send_json({"type": "error", "message": "Invalid token"})
        await websocket.close(code=1008)
        return
    
    # Validate the user exists and device is authorized
    db = SessionLocal()
    try:
        # Check if token is blacklisted
        if db.query(BlacklistedToken).filter_by(token=token).first():
            logger.warning(f"WebSocket connection attempted with blacklisted token for {email}")
            await websocket.send_json({"type": "error", "message": "Token has been revoked"})
            await websocket.close(code=1008)
            return

        user = db.query(User).filter(User.email == email).first()
        if not user:
            logger.warning(f"WebSocket connection attempted for non-existent user: {email}")
            await websocket.send_json({"type": "error", "message": "User not found"})
            await websocket.close(code=1008)
            return

        # Check if device belongs to this user
        device = db.query(Device).filter_by(user_id=user.user_id, device_id=device_id).first()
        if not device:
            logger.warning(f"WebSocket connection attempted with unauthorized device {device_id} for user {email}")
            await websocket.send_json({"type": "error", "message": "Unauthorized device"})
            await websocket.close(code=1008)
            return
        
        # Store user_id for use in the connection
        _ws_user: Any = user
        user_id: str = _ws_user.user_id
    finally:
        db.close()

    # Connection validated successfully
    logger.info(f"WebSocket connection accepted for user_id={user_id}, device_id={device_id}")
    await manager.connect(user_id, device_id, websocket)

    def update_device_last_seen(uid: str, dev_id: str):
        session = SessionLocal()
        try:
            dev = session.query(Device).filter_by(user_id=uid, device_id=dev_id).first()
            if dev:
                _d: Any = dev
                _d.last_seen = datetime.now(timezone.utc)
                session.commit()
        except Exception as err:
            session.rollback()
            logger.warning(f"Failed to update device last_seen: {err}")
        finally:
            session.close()

    await asyncio.to_thread(update_device_last_seen, user_id, device_id)
    
    try:
        while True:
            # Expiry check - compare Unix timestamps correctly
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
                    await asyncio.to_thread(update_device_last_seen, user_id, device_id)
                    continue
                except WebSocketDisconnect:
                    # Connection already closed by client, don't try to close again
                    logger.warning("Client disconnected during ping/pong")
                    break
                except Exception as e:
                    logger.warning(f"WebSocket ping/pong failed: {e}")
                    try:
                        await websocket.close(code=4002)
                    except RuntimeError:
                        # Connection already closed, skip
                        pass
                    break

            if data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
                await asyncio.to_thread(update_device_last_seen, user_id, device_id)
                continue

            # Unified Message Handling (Upsert & Delete)
            # We no longer separate "type": "delete". Everything is an event.
            
            msg_id = data.get("id")
            # Client determines deletion status
            is_deleted = data.get("is_deleted", False)
            is_pinned = data.get("is_pinned", False)
            pinned_at_str = data.get("pinned_at")
            
            msg_ts_str = data.get("timestamp")
            ciphertext = data.get("ciphertext")
            nonce = data.get("nonce")
            blob_version = data.get("blob_version", 1)
            
            if not msg_id or not msg_ts_str:
                await websocket.send_json({"type": "error", "message": "Missing required fields (id, timestamp)"})
                continue

            # Validation based on is_deleted status
            if not is_deleted:
                if not ciphertext or not nonce:
                    await websocket.send_json({"type": "error", "message": "Missing ciphertext/nonce for active entry"})
                    continue
            else:
                # If deleted, we enforce nulls for data privacy/storage optimization
                ciphertext = None
                nonce = None
            
            try:
                parsed_ts = datetime.fromisoformat(msg_ts_str.replace('Z', '+00:00'))
                msg_ts = parsed_ts.replace(tzinfo=timezone.utc) if parsed_ts.tzinfo is None else parsed_ts
            except ValueError:
                await websocket.send_json({"type": "error", "message": "Invalid timestamp format (ISO8601 required)"})
                continue

            pinned_at_val = None
            if is_pinned and not is_deleted:
                if pinned_at_str:
                    try:
                        parsed_pinned_ts = datetime.fromisoformat(pinned_at_str.replace('Z', '+00:00'))
                        pinned_at_val = parsed_pinned_ts.replace(tzinfo=timezone.utc) if parsed_pinned_ts.tzinfo is None else parsed_pinned_ts
                    except ValueError:
                        await websocket.send_json({"type": "error", "message": "Invalid pinned_at format (ISO8601 required)"})
                        continue
                else:
                    pinned_at_val = datetime.now(timezone.utc)
            
            ciphertext_bytes = None
            nonce_bytes = None

            if not is_deleted:
                if ciphertext is None or nonce is None:
                    await websocket.send_json({"type": "error", "message": "Missing ciphertext/nonce"})
                    continue
                try:
                    ciphertext_bytes = base64.b64decode(ciphertext)
                    nonce_bytes = base64.b64decode(nonce)
                except Exception:
                    await websocket.send_json({"type": "error", "message": "Invalid base64 encoding"})
                    continue

                if blob_version not in ALLOWED_BLOB_VERSIONS:
                    await websocket.send_json({"type": "error", "message": "Unsupported blob_version"})
                    continue
                if not (MIN_NONCE_LEN <= len(nonce_bytes) <= MAX_NONCE_LEN):
                    await websocket.send_json({"type": "error", "message": "nonce length out of bounds"})
                    continue
                if len(ciphertext_bytes) > MAX_CIPHERTEXT_LEN:
                    await websocket.send_json({"type": "error", "message": "ciphertext too large"})
                    continue

            # Run blocking DB operations in a separate thread
            def save_clipboard_entry():
                session = SessionLocal()
                try:
                    existing = session.query(Clipboard).filter_by(clipboard_id=msg_id, user_id=user_id).first()

                    if existing:
                        _ex: Any = existing
                        _ex.is_deleted = is_deleted
                        _ex.timestamp = msg_ts
                        _ex.blob_version = blob_version

                        if is_deleted:
                            _ex.ciphertext = None
                            _ex.nonce = None
                            _ex.is_pinned = False
                            _ex.pinned_at = None
                            _ex.deleted_at = msg_ts
                            _ex.updated_at = datetime.now(timezone.utc)
                        else:
                            _ex.ciphertext = ciphertext_bytes
                            _ex.nonce = nonce_bytes
                            _ex.is_pinned = is_pinned
                            _ex.pinned_at = pinned_at_val
                            _ex.deleted_at = None
                            _ex.updated_at = datetime.now(timezone.utc)

                        session.commit()
                        entry_resp = {
                            "id": _ex.clipboard_id,
                            "timestamp": _ex.timestamp,
                            "is_deleted": _ex.is_deleted,
                            "is_pinned": _ex.is_pinned,
                            "pinned_at": _ex.pinned_at,
                            "blob_version": _ex.blob_version
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
                        _ne: Any = new_entry
                        entry_resp = {
                            "id": _ne.clipboard_id,
                            "timestamp": _ne.timestamp,
                            "is_deleted": _ne.is_deleted,
                            "is_pinned": _ne.is_pinned,
                            "pinned_at": _ne.pinned_at,
                            "blob_version": _ne.blob_version
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

            # Execute in thread pool to avoid blocking event loop
            entry_data: Any = await asyncio.to_thread(save_clipboard_entry)

            if "error" in entry_data:
                 logger.error(f"DB Error processing clipboard item: {entry_data['error']}")
                 continue

            def format_iso_utc(dt: Any):
                if dt is None:
                    return None
                if hasattr(dt, "isoformat"):
                    return dt.isoformat().replace("+00:00", "Z")
                return str(dt)

            # Broadcast to other devices (excluding sender)
            broadcast_payload = {
                "type": "clipboard_sync",
                "id": entry_data["id"],
                "timestamp": format_iso_utc(entry_data["timestamp"]),
                "is_deleted": entry_data["is_deleted"],
                "is_pinned": entry_data["is_pinned"],
                "pinned_at": format_iso_utc(entry_data.get("pinned_at")),
                "blob_version": entry_data["blob_version"]
            }
            
            if not entry_data["is_deleted"]:
                broadcast_payload["ciphertext"] = ciphertext
                broadcast_payload["nonce"] = nonce
            else:
                broadcast_payload["ciphertext"] = None
                broadcast_payload["nonce"] = None

            await manager.broadcast_to_user(
                user_id=user_id,
                message=broadcast_payload,
                exclude_device=device_id
            )

            # Trigger push notification dispatch to background devices (excluding sender)
            launch_background_push(user_id=user_id, exclude_device=device_id)

            # Broadcast any pruned tombstones to all devices
            for tombstone in entry_data.get("pruned_tombstones", []):
                await manager.broadcast_to_user(
                    user_id=user_id,
                    message=tombstone
                )

            # Send acknowledgment back to the sender
            await websocket.send_json({
                "type": "ack",
                "id": entry_data["id"]
            })


    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        logger.error(traceback.format_exc())
        try:
            await websocket.close(code=1011) # Internal Error
        except RuntimeError:
            # Connection already closed, skip
            pass
    finally:
        manager.disconnect(user_id, device_id)
        await asyncio.to_thread(update_device_last_seen, user_id, device_id)
