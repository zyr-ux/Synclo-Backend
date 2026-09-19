import asyncio
from datetime import datetime, timezone
import time
import traceback
from typing import Optional

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError

from app.database.engine import SessionLocal, run_in_write_transaction
from app.core.config import Settings
from app.core.constants import LOOPBACK_HOSTS
from app.core.logging_config import logger
from sqlalchemy import select
from app.database.models import User, Device, BlacklistedToken
from app.database.schemas import ClipboardIn
from app.services.auth import SECRET_KEY, ALGORITHM
from app.services.clipboard_service import upsert_clipboard, soft_delete_clipboard
from app.services.push_service import launch_background_push
from app.websockets.connection_manager import manager


router = APIRouter()


async def _validate_ws_security(websocket: WebSocket) -> bool:
    if Settings.HTTPS_ONLY:
        client_ip = websocket.client.host if websocket.client else ""
        forwarded_proto = ""
        if client_ip in LOOPBACK_HOSTS:
            forwarded_proto = websocket.headers.get("x-forwarded-proto", "").lower()
        is_secure = websocket.url.scheme == "wss" or forwarded_proto in ("https", "wss")
        is_loopback = websocket.url.hostname in LOOPBACK_HOSTS
        if not is_secure and not is_loopback:
            logger.warning(
                "WebSocket connection rejected: HTTPS_ONLY is enabled and connection is insecure"
            )
            await websocket.send_json(
                {
                    "type": "error",
                    "message": "Insecure WebSocket connection rejected (WSS required)",
                }
            )
            await websocket.close(code=1008)
            return False
    return True


async def _close_token_expired(websocket: WebSocket) -> None:
    await websocket.send_json({"type": "error", "message": "Token expired"})
    await websocket.close(code=4001)


async def _authenticate_ws(websocket: WebSocket) -> Optional[tuple[str, str, int]]:
    auth_header = websocket.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        logger.warning("WebSocket connection attempted without Bearer token")
        await websocket.send_json(
            {"type": "error", "message": "Missing or invalid Authorization header"}
        )
        await websocket.close(code=1008)
        return None

    token = auth_header[7:]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        exp = payload.get("exp")
        device_id = payload.get("device_id")
        epoch = payload.get("epoch")

        if not email or not exp or not device_id or epoch is None:
            logger.warning(
                "WebSocket token missing required fields: has_email=%s, exp=%s, device_id=%s, epoch=%s",
                bool(email),
                exp,
                device_id,
                epoch,
            )
            await websocket.send_json(
                {"type": "error", "message": "Invalid token: missing required fields"}
            )
            await websocket.close(code=1008)
            return None
    except ExpiredSignatureError as e:
        logger.warning("WebSocket token validation failed: %s", e)
        await _close_token_expired(websocket)
        return None
    except InvalidTokenError as e:
        logger.warning("WebSocket token validation failed: %s", e)
        await websocket.send_json({"type": "error", "message": "Invalid token"})
        await websocket.close(code=1008)
        return None

    db = SessionLocal()
    try:
        if db.scalars(select(BlacklistedToken).where(BlacklistedToken.token == token)).first():
            logger.warning("WebSocket connection attempted with blacklisted token")
            await websocket.send_json({"type": "error", "message": "Token has been revoked"})
            await websocket.close(code=1008)
            return None

        user = db.scalars(select(User).where(User.email == email)).first()
        if not user:
            logger.warning("WebSocket connection attempted for non-existent user")
            await websocket.send_json({"type": "error", "message": "User not found"})
            await websocket.close(code=1008)
            return None

        if epoch != user.session_epoch:
            logger.warning(
                "WebSocket token session_epoch mismatch for user %s: %s vs %s",
                user.user_id,
                epoch,
                user.session_epoch,
            )
            await websocket.send_json(
                {"type": "session_invalidated", "reason": "credentials_changed"}
            )
            await websocket.close(code=4004)
            return None

        device = db.scalars(
            select(Device).where(Device.user_id == user.user_id, Device.device_id == device_id)
        ).first()
        if not device:
            logger.warning(
                "WebSocket connection attempted with unauthorized device %s for user %s",
                device_id,
                user.user_id,
            )
            await websocket.send_json({"type": "error", "message": "Unauthorized device"})
            await websocket.close(code=1008)
            return None

        def mutate():
            device.last_seen = datetime.now(timezone.utc)

        run_in_write_transaction(db, mutate)

        return user.user_id, device_id, exp
    finally:
        db.close()


_last_seen_cache: dict[tuple[str, str], float] = {}
_LAST_SEEN_THROTTLE_SECONDS = 60.0


def _update_device_last_seen(user_id: str, device_id: str, force: bool = False):
    key = (user_id, device_id)
    now_mono = time.monotonic()
    if not force:
        last_updated = _last_seen_cache.get(key, 0.0)
        if now_mono - last_updated < _LAST_SEEN_THROTTLE_SECONDS:
            return

    session = SessionLocal()
    try:

        def mutate():
            dev = session.scalars(
                select(Device).where(Device.user_id == user_id, Device.device_id == device_id)
            ).first()
            if dev:
                dev.last_seen = datetime.now(timezone.utc)

        run_in_write_transaction(session, mutate)
        _last_seen_cache[key] = now_mono
    except Exception as err:
        logger.warning("Failed to update device last_seen: %s", err)
    finally:
        session.close()


async def _process_clipboard_message(
    websocket: WebSocket, user_id: str, device_id: str, data: dict
):
    msg_id = data.get("id")
    msg_ts = data.get("timestamp")

    if not msg_id or not msg_ts:
        await websocket.send_json(
            {"type": "error", "message": "Missing required fields (id, timestamp)"}
        )
        return

    try:
        clipboard_in = ClipboardIn.model_validate(data)
    except Exception as err:
        await websocket.send_json({"type": "error", "message": f"Invalid payload: {err}"})
        return

    session = SessionLocal()
    try:
        device = session.scalars(
            select(Device).where(Device.user_id == user_id, Device.device_id == device_id)
        ).first()
        if not device:
            await websocket.send_json(
                {
                    "type": "device_deleted",
                    "message": "This device has been removed from your account",
                }
            )
            await websocket.close(code=4003)
            return

        if clipboard_in.is_deleted:
            _, is_noop = await soft_delete_clipboard(
                db=session,
                user_id=user_id,
                clipboard_id=msg_id,
                caller_device_id=device_id,
                client_timestamp=clipboard_in.timestamp,
            )
        else:
            _, _, is_noop = await upsert_clipboard(
                db=session,
                user_id=user_id,
                data=clipboard_in,
                caller_device_id=device_id,
            )

        if not is_noop:
            launch_background_push(user_id=user_id, exclude_device=device_id)

        await websocket.send_json(
            {
                "type": "ack",
                "id": msg_id,
            }
        )
    except HTTPException as exc:
        if exc.status_code == 409:
            await websocket.send_json(
                {
                    "type": "error",
                    "id": msg_id,
                    "code": "conflict",
                    "message": exc.detail,
                }
            )
        else:
            await websocket.send_json(
                {
                    "type": "error",
                    "message": exc.detail,
                }
            )
    except Exception as exc:
        logger.error("Error processing websocket clipboard item: %s", exc)
        await websocket.send_json(
            {
                "type": "error",
                "message": "Internal error processing clipboard item",
            }
        )
    finally:
        session.close()


@router.websocket("/sync")
async def websocket_sync(websocket: WebSocket):
    await websocket.accept()

    if not await _validate_ws_security(websocket):
        return

    auth_result = await _authenticate_ws(websocket)
    if auth_result is None:
        return

    user_id, device_id, exp = auth_result

    logger.info("WebSocket connection accepted for user_id=%s, device_id=%s", user_id, device_id)
    await manager.connect(user_id, device_id, websocket)

    try:
        while True:
            if datetime.now(timezone.utc).timestamp() >= exp:
                await _close_token_expired(websocket)
                break

            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=45)
            except asyncio.TimeoutError:
                if datetime.now(timezone.utc).timestamp() >= exp:
                    await _close_token_expired(websocket)
                    break

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
                    logger.warning("WebSocket ping/pong failed: %s", e)
                    try:
                        await websocket.close(code=4002)
                    except RuntimeError:
                        pass
                    break

            if datetime.now(timezone.utc).timestamp() >= exp:
                await _close_token_expired(websocket)
                break

            if data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
                await asyncio.to_thread(_update_device_last_seen, user_id, device_id)
                continue

            await _process_clipboard_message(websocket, user_id, device_id, data)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error("WebSocket error: %s", e)
        logger.error(traceback.format_exc())
        try:
            await websocket.close(code=1011)
        except RuntimeError:
            pass
    finally:
        manager.disconnect(user_id, device_id, websocket)
        await asyncio.to_thread(_update_device_last_seen, user_id, device_id, True)
        _last_seen_cache.pop((user_id, device_id), None)
