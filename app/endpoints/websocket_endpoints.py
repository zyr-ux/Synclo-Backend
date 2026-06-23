# app/endpoints/websocket_endpoints.py

import asyncio
import base64
from datetime import datetime, timezone
import traceback
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt

from app.core.database import SessionLocal
from app.core.constants import (
    ALLOWED_BLOB_VERSIONS,
    MIN_NONCE_LEN,
    MAX_NONCE_LEN,
    MAX_CIPHERTEXT_LEN,
)
from app.core.logging_config import logger
from app.models.models import Clipboard, User, Device, BlacklistedToken
from app.services.auth import SECRET_KEY, ALGORITHM
from app.websockets.connection_manager import manager

router = APIRouter()


@router.websocket("/sync")
async def websocket_sync(websocket: WebSocket):
    # Accept the connection first - we MUST do this before any close operations
    await websocket.accept()
    
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
        device = db.query(Device).filter_by(user_id=user.id, device_id=device_id).first()
        if not device:
            logger.warning(f"WebSocket connection attempted with unauthorized device {device_id} for user {email}")
            await websocket.send_json({"type": "error", "message": "Unauthorized device"})
            await websocket.close(code=1008)
            return
        
        # Store user_id for use in the connection
        _ws_user: Any = user
        user_id: int = _ws_user.id
    finally:
        db.close()

    # Connection validated successfully
    logger.info(f"WebSocket connection accepted for user_id={user_id}, device_id={device_id}")
    await manager.connect(user_id, device_id, websocket)
    
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
                continue
            
            # Unified Message Handling (Upsert & Delete)
            # We no longer separate "type": "delete". Everything is an event.
            
            msg_id = data.get("id")
            # Client determines deletion status
            is_deleted = data.get("is_deleted", False)
            is_pinned = data.get("is_pinned", False)
            
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
                msg_ts = datetime.fromisoformat(msg_ts_str.replace('Z', '+00:00')).replace(tzinfo=None)
            except ValueError:
                await websocket.send_json({"type": "error", "message": "Invalid timestamp format (ISO8601 required)"})
                continue
            
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
                    existing = session.query(Clipboard).filter_by(id=msg_id, user_id=user_id).first()

                    if existing:
                        _ex: Any = existing
                        _ex.is_deleted = is_deleted
                        _ex.timestamp = msg_ts
                        _ex.blob_version = blob_version

                        if is_deleted:
                            _ex.ciphertext = None
                            _ex.nonce = None
                            _ex.is_pinned = False
                            _ex.deleted_at = msg_ts
                            _ex.updated_at = datetime.now(timezone.utc)
                        else:
                            _ex.ciphertext = ciphertext_bytes
                            _ex.nonce = nonce_bytes
                            _ex.is_pinned = is_pinned
                            _ex.deleted_at = None
                            _ex.updated_at = datetime.now(timezone.utc)

                        session.commit()
                        return {
                            "id": _ex.id,
                            "timestamp": _ex.timestamp,
                            "is_deleted": _ex.is_deleted,
                            "is_pinned": _ex.is_pinned,
                            "blob_version": _ex.blob_version
                        }
                    else:
                        new_entry = Clipboard(
                            id=msg_id,
                            user_id=user_id,
                            ciphertext=ciphertext_bytes,
                            nonce=nonce_bytes,
                            blob_version=blob_version,
                            timestamp=msg_ts,
                            is_deleted=is_deleted,
                            is_pinned=is_pinned if not is_deleted else False,
                            deleted_at=msg_ts if is_deleted else None,
                            updated_at=datetime.now(timezone.utc)
                        )
                        session.add(new_entry)
                        session.commit()
                        _ne: Any = new_entry
                        return {
                            "id": _ne.id,
                            "timestamp": _ne.timestamp,
                            "is_deleted": _ne.is_deleted,
                            "is_pinned": _ne.is_pinned,
                            "blob_version": _ne.blob_version
                        }
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

            # Broadcast to other devices (excluding sender)
            broadcast_payload = {
                "id": entry_data["id"],
                "timestamp": entry_data["timestamp"].isoformat(),
                "is_deleted": entry_data["is_deleted"],
                "is_pinned": entry_data["is_pinned"],
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
