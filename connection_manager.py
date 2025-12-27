from typing import Dict, Optional
from fastapi import WebSocket
import asyncio
import json

class ConnectionManager:
    def __init__(self):
        # Structure: { user_id: { device_id: websocket } }
        self.active_connections: Dict[int, Dict[str, WebSocket]] = {}
        self.redis = None
        self._listener_task: Optional[asyncio.Task] = None
        self._node_id = id(self)

    async def connect(self, user_id: int, device_id: str, websocket: WebSocket):
        if user_id not in self.active_connections:
            self.active_connections[user_id] = {}
        self.active_connections[user_id][device_id] = websocket

    def disconnect(self, user_id: int, device_id: str):
        if user_id in self.active_connections:
            self.active_connections[user_id].pop(device_id, None)
            if not self.active_connections[user_id]:
                self.active_connections.pop(user_id, None)

    async def disconnect_device(self, user_id: int, device_id: str):
        #Forcefully disconnect a specific device.
        if user_id in self.active_connections:
            ws = self.active_connections[user_id].get(device_id)
            if ws:
                await ws.close(code=4000) # Normal closure
                self.disconnect(user_id, device_id)

    async def disconnect_user(self, user_id: int):
        #Forcefully disconnect all devices for a user.
        if user_id in self.active_connections:
            # Create a list of items to iterate safely while modifying the dict
            for device_id, ws in list(self.active_connections[user_id].items()):
                await ws.close(code=4000)
                self.disconnect(user_id, device_id)

    def get_user_devices(self, user_id: int) -> Dict[str, WebSocket]:
        return self.active_connections.get(user_id, {})

    async def broadcast_to_user(self, user_id: int, message: dict, exclude_device: str = None):
        await self._broadcast_local(user_id, message, exclude_device)

        if self.redis:
            envelope = {
                "user_id": user_id,
                "exclude_device": exclude_device,
                "message": message,
                "sender": self._node_id,
            }
            await self.redis.publish(self._channel(user_id), json.dumps(envelope))

    async def _broadcast_local(self, user_id: int, message: dict, exclude_device: str = None):
        # Iterate over a copy of items to prevent runtime errors if connections drop during broadcast
        for device_id, ws in list(self.get_user_devices(user_id).items()):
            if device_id != exclude_device:
                try:
                    await ws.send_json(message)
                except Exception:
                    # If sending fails, assume connection is dead and remove it
                    self.disconnect(user_id, device_id)

    def set_redis(self, redis_client):
        self.redis = redis_client

    async def start_listener(self):
        if not self.redis or self._listener_task:
            return

        async def _listen():
            pubsub = self.redis.pubsub()
            await pubsub.psubscribe(self._channel("*"))
            try:
                async for message in pubsub.listen():
                    if message.get("type") not in {"pmessage", "message"}:
                        continue
                    data = json.loads(message.get("data"))
                    if data.get("sender") == self._node_id:
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