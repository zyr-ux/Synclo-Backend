import sys
from unittest.mock import MagicMock, AsyncMock
import os
import base64
import time
import json
from datetime import datetime, timezone

# --- MOCK SETUP (copied from verify_delta_sync.py) ---
# Mock Redis BEFORE importing main to avoid connection attempts
mock_redis_module = MagicMock()
mock_redis_client = AsyncMock()

# handle pubsub
mock_pubsub = MagicMock()
mock_pubsub.psubscribe = AsyncMock()
mock_pubsub.subscribe = AsyncMock()
mock_pubsub.close = AsyncMock()

async def async_iter():
    if False: yield None

mock_pubsub.listen.return_value = async_iter()
mock_redis_client.pubsub = MagicMock(return_value=mock_pubsub)
mock_redis_module.Redis.from_url.return_value = mock_redis_client
sys.modules["redis.asyncio"] = mock_redis_module

# Also mock fastapi_limiter before import
mock_limiter = MagicMock()
sys.modules["fastapi_limiter"] = mock_limiter

# Create a dummy RateLimiter class
from fastapi import Request, Response

class MockRateLimiter:
    def __init__(self, times=1, seconds=1, **kwargs): pass
    async def __call__(self, request: Request, response: Response): pass

mock_limiter_depends = MagicMock()
mock_limiter_depends.RateLimiter = MockRateLimiter
sys.modules["fastapi_limiter.depends"] = mock_limiter_depends

# Mock FastAPILimiter init just in case
mock_limiter.FastAPILimiter.init = AsyncMock()

# --- IMPORTS ---
# Add parent directory to sys.path to allow importing main
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
# Now import main
from main import app

# --- TEST LOGIC ---

def generate_random_base64(length=32):
    return base64.b64encode(os.urandom(length)).decode('utf-8')

def test_device_os():
    with TestClient(app) as client:
        # 1. Register User with OS
        email = f"test_os_{int(time.time())}_{os.urandom(4).hex()}@example.com"
        device_id = f"dev_{int(time.time())}"
        auth_key = generate_random_base64(32)
        enc_mk = generate_random_base64(32)
        salt = generate_random_base64(32)
        
        print(f"Registering user: {email}")
        reg_data = {
            "email": email,
            "auth_key": auth_key,
            "device_id": device_id,
            "device_name": "Test Device 1",
            "os": "Android 14",
            "encrypted_master_key": enc_mk,
            "salt": salt,
            "kdf_version": 1
        }
        
        resp = client.post("/register", json=reg_data)
        assert resp.status_code == 200, f"Registration failed: {resp.text}"
        res = resp.json()
        token = res["access_token"]
        print("Registration successful.")
        
        # 2. Check Device OS via GET /devices
        print("Checking device OS...")
        resp = client.get("/devices", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200, f"Get devices failed: {resp.text}"
        devices = resp.json()
        print(f"Devices found: {json.dumps(devices, indent=2)}")
        
        target_device = next((d for d in devices if d["device_id"] == device_id), None)
        assert target_device, "Device not found in list."
        assert target_device.get("os") == "Android 14", f"OS mismatch! Expected 'Android 14', got '{target_device.get('os')}'"
        print("OS verification passed for Registration.")
        
        # 3. Login with new device and OS
        device_id_2 = f"dev2_{int(time.time())}"
        print(f"Logging in with new device: {device_id_2}")
        
        login_data = {
            "email": email,
            "auth_key": auth_key,
            "device_id": device_id_2,
            "device_name": "Test Device 2",
            "os": "iOS 17"
        }
        
        resp = client.post("/login", json=login_data)
        assert resp.status_code == 200, f"Login failed: {resp.text}"
        res = resp.json()
        token_2 = res["access_token"]
        print("Login successful.")
        
        # 4. Check Device 2 OS
        print("Checking device 2 OS...")
        resp = client.get("/devices", headers={"Authorization": f"Bearer {token_2}"})
        devices = resp.json()
        target_device_2 = next((d for d in devices if d["device_id"] == device_id_2), None)
        
        assert target_device_2, "Device 2 not found."
        assert target_device_2.get("os") == "iOS 17", f"OS mismatch for device 2! Expected 'iOS 17', got '{target_device_2.get('os')}'"
        print("OS verification passed for Login (New Device).")

        # 5. Update Existing Device OS via Login
        print("Updating OS for device 2 via Login...")
        login_data_update = {
            "email": email,
            "auth_key": auth_key,
            "device_id": device_id_2,
            "device_name": "Test Device 2 Updated",
            "os": "iOS 18 Beta"
        }
        
        resp = client.post("/login", json=login_data_update)
        assert resp.status_code == 200, f"Login update failed: {resp.text}"
        print("Login update successful.")
        
        # Check if OS updated
        resp = client.get("/devices", headers={"Authorization": f"Bearer {token_2}"})
        devices = resp.json()
        target_device_2_updated = next((d for d in devices if d["device_id"] == device_id_2), None)
        
        assert target_device_2_updated.get("os") == "iOS 18 Beta", f"OS update failed! Expected 'iOS 18 Beta', got '{target_device_2_updated.get('os')}'"
        print("OS update verification passed.")
        
        print("\nALL TESTS PASSED")

if __name__ == "__main__":
    try:
        test_device_os()
    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
