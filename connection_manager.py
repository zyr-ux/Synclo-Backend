from typing import Dict
from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        # Structure: { user_id: { device_id: websocket } }
        self.active_connections: Dict[int, Dict[str, WebSocket]] = {}

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
        # Iterate over a copy of items to prevent runtime errors if connections drop during broadcast
        for device_id, ws in list(self.get_user_devices(user_id).items()):
            if device_id != exclude_device:
                try:
                    await ws.send_json(message)
                except Exception:
                    # If sending fails, assume connection is dead and remove it
                    self.disconnect(user_id, device_id)