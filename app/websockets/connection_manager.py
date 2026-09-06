import asyncio
import json
import logging
from typing import Any, Dict, Optional
from uuid import uuid4
from fastapi import WebSocket

from app.core.metrics import (
    ACTIVE_WEBSOCKETS,
    WEBSOCKET_BROADCAST_FAILURES_TOTAL,
    WEBSOCKET_EVENTS_TOTAL,
)

logger = logging.getLogger("clipboard_sync")

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Dict[str, WebSocket]] = {}
        self.redis: Optional[Any] = None
        self._listener_task: Optional[asyncio.Task] = None
        self._node_id = uuid4().hex

    def _update_active_metric(self):
        total = sum(len(devices) for devices in self.active_connections.values())
        ACTIVE_WEBSOCKETS.set(total)

    async def connect(self, user_id: str, device_id: str, websocket: WebSocket):
        if user_id not in self.active_connections:
            self.active_connections[user_id] = {}
        self.active_connections[user_id][device_id] = websocket
        self._update_active_metric()

    def disconnect(self, user_id: str, device_id: str, websocket: Optional[WebSocket] = None):
        devices = self.active_connections.get(user_id)
        if devices is None:
            return

        current = devices.get(device_id)
        if websocket is not None and current is not websocket:
            return

        devices.pop(device_id, None)
        if not devices:
            self.active_connections.pop(user_id, None)
        self._update_active_metric()

    async def disconnect_device(self, user_id: str, device_id: str):
        await self._disconnect_device_local(user_id, device_id)

        if self.redis:
            envelope = {
                "action": "disconnect_device",
                "user_id": user_id,
                "device_id": device_id,
                "sender": self._node_id,
            }
            try:
                await self.redis.publish(self._channel(user_id), json.dumps(envelope))
            except Exception as exc:
                WEBSOCKET_BROADCAST_FAILURES_TOTAL.labels(operation="disconnect_device_publish").inc()
                logger.warning("WebSocket device disconnect publication failed: %s", exc)

    async def _disconnect_device_local(self, user_id: str, device_id: str):
        if user_id in self.active_connections:
            ws = self.active_connections[user_id].get(device_id)
            if ws:
                try:
                    await ws.send_json({
                        "type": "device_deleted",
                        "message": "This device has been removed from your account"
                    })
                    await ws.close(code=4003)
                except (RuntimeError, ConnectionError):
                    pass
                finally:
                    self.disconnect(user_id, device_id)

    async def disconnect_user(
        self,
        user_id: str,
        code: int = 4000,
        message: Optional[dict] = None,
    ):
        if message is None and code == 4004:
            message = {"type": "session_invalidated", "reason": "credentials_changed"}

        await self._disconnect_user_local(user_id, code=code, message=message)

        if self.redis:
            envelope = {
                "action": "disconnect_user",
                "user_id": user_id,
                "code": code,
                "message": message,
                "sender": self._node_id,
            }
            try:
                await self.redis.publish(self._channel(user_id), json.dumps(envelope))
            except Exception as exc:
                WEBSOCKET_BROADCAST_FAILURES_TOTAL.labels(operation="disconnect_publish").inc()
                logger.warning("WebSocket disconnect publication failed: %s", exc)

    async def _disconnect_user_local(
        self,
        user_id: str,
        code: int = 4000,
        message: Optional[dict] = None,
    ):
        if user_id in self.active_connections:
            for device_id, ws in list(self.active_connections[user_id].items()):
                if message:
                    try:
                        await ws.send_json(message)
                    except (RuntimeError, ConnectionError):
                        pass
                try:
                    await ws.close(code=code)
                except (RuntimeError, ConnectionError):
                    pass
                finally:
                    self.disconnect(user_id, device_id)

    def get_user_devices(self, user_id: str) -> Dict[str, WebSocket]:
        return self.active_connections.get(user_id, {})

    def is_device_online(self, user_id: str, device_id: str) -> bool:
        return device_id in self.get_user_devices(user_id)

    async def broadcast_to_user(self, user_id: str, message: dict, exclude_device: Optional[str] = None):
        event_type = message.get("type", "unknown") if isinstance(message, dict) else "unknown"
        WEBSOCKET_EVENTS_TOTAL.labels(event_type=event_type).inc()

        await self._broadcast_local(user_id, message, exclude_device)

        if self.redis:
            envelope = {
                "user_id": user_id,
                "exclude_device": exclude_device,
                "message": message,
                "sender": self._node_id,
            }
            try:
                await self.redis.publish(self._channel(user_id), json.dumps(envelope))
            except Exception as exc:
                WEBSOCKET_BROADCAST_FAILURES_TOTAL.labels(operation="broadcast_publish").inc()
                logger.warning("WebSocket broadcast publication failed: %s", exc)

    async def _broadcast_local(self, user_id: str, message: dict, exclude_device: Optional[str] = None):
        for device_id, ws in list(self.get_user_devices(user_id).items()):
            if device_id != exclude_device:
                try:
                    await ws.send_json(message)
                except (RuntimeError, ConnectionError):
                    self.disconnect(user_id, device_id)
                except Exception as e:
                    logger.error(f"Unexpected error broadcasting to device {device_id}: {e}")
                    self.disconnect(user_id, device_id)

    def set_redis(self, redis_client):
        self.redis = redis_client

    async def start_listener(self):
        if not self.redis or self._listener_task:
            return

        redis = self.redis

        async def _listen():
            pubsub = redis.pubsub()
            await pubsub.psubscribe(self._channel("*"))
            try:
                async for message in pubsub.listen():
                    if message.get("type") not in {"pmessage", "message"}:
                        continue
                    data = json.loads(message.get("data"))
                    if data.get("sender") == self._node_id:
                        continue
                    if data.get("action") == "disconnect_user":
                        user_id = data.get("user_id")
                        if user_id:
                            await self._disconnect_user_local(
                                user_id,
                                code=data.get("code", 4000),
                                message=data.get("message"),
                            )
                        continue
                    if data.get("action") == "disconnect_device":
                        user_id = data.get("user_id")
                        device_id = data.get("device_id")
                        if user_id and device_id:
                            await self._disconnect_device_local(user_id, device_id)
                        continue
                    user_id = data.get("user_id")
                    payload = data.get("message")
                    exclude = data.get("exclude_device")
                    if user_id is None or payload is None:
                        continue
                    await self._broadcast_local(user_id, payload, exclude)
            finally:
                await pubsub.close()

        self._listener_task = asyncio.create_task(_listen())

    async def stop_listener(self):
        if self._listener_task:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
            self._listener_task = None

    def _channel(self, user_id):
        return f"clipboard:user:{user_id}"


manager = ConnectionManager()
