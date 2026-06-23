import sys
from unittest.mock import MagicMock, AsyncMock
import os
import base64
import time
import json
from datetime import datetime, timezone

# --- MOCK SETUP (copied from verify_delta_sync.py) ---
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

# Mock fastapi_limiter before import
mock_limiter = MagicMock()
sys.modules["fastapi_limiter"] = mock_limiter

from fastapi import Request, Response

class MockRateLimiter:
    def __init__(self, times=1, seconds=1, **kwargs): pass
    async def __call__(self, request: Request, response: Response): pass

mock_limiter_depends = MagicMock()
mock_limiter_depends.RateLimiter = MockRateLimiter
sys.modules["fastapi_limiter.depends"] = mock_limiter_depends
mock_limiter.FastAPILimiter.init = AsyncMock()

# Add parent directory to sys.path to allow importing main
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from app.main import app

def generate_random_base64(length=32):
    return base64.b64encode(os.urandom(length)).decode('utf-8')

def test_clipboard_pin():
    with TestClient(app) as client:
        # 1. Register User
        email = f"test_pin_{int(time.time())}_{os.urandom(4).hex()}@example.com"
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
            "encrypted_master_key": enc_mk,
            "salt": salt,
            "kdf_version": 1
        }
        
        resp = client.post("/register", json=reg_data)
        assert resp.status_code == 200, f"Registration failed: {resp.text}"
        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print("Registration successful.")

        # 2. Add Pinned Item
        pinned_id = "pinned_" + os.urandom(4).hex()
        resp = client.post("/clipboard", json={
            "id": pinned_id,
            "ciphertext": base64.b64encode(b"pinned payload").decode('utf-8'),
            "nonce": base64.b64encode(b"nonce1111").decode('utf-8'),
            "blob_version": 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "is_pinned": True
        }, headers=headers)
        assert resp.status_code == 200, f"Failed to add pinned item: {resp.text}"
        print("Added pinned item successfully.")

        # 3. Add Unpinned Item
        unpinned_id = "unpinned_" + os.urandom(4).hex()
        resp = client.post("/clipboard", json={
            "id": unpinned_id,
            "ciphertext": base64.b64encode(b"unpinned payload").decode('utf-8'),
            "nonce": base64.b64encode(b"nonce2222").decode('utf-8'),
            "blob_version": 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "is_pinned": False
        }, headers=headers)
        assert resp.status_code == 200, f"Failed to add unpinned item: {resp.text}"
        print("Added unpinned item successfully.")

        # 4. Verify items are retrieved with correct is_pinned flags
        resp = client.get("/clipboard/all", headers=headers)
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) == 2, f"Expected 2 items, got {len(items)}"
        
        pinned_item = next((item for item in items if item["id"] == pinned_id), None)
        unpinned_item = next((item for item in items if item["id"] == unpinned_id), None)
        
        assert pinned_item is not None, "Pinned item not returned"
        assert unpinned_item is not None, "Unpinned item not returned"
        assert pinned_item["is_pinned"] is True, "Expected pinned item to have is_pinned=True"
        assert unpinned_item["is_pinned"] is False, "Expected unpinned item to have is_pinned=False"
        print("Retrieval check passed. Pinned item metadata verified.")

        # 5. Bulk Delete: DELETE /clipboard (should only affect unpinned item)
        print("Triggering bulk delete /clipboard...")
        resp = client.delete("/clipboard", headers=headers)
        assert resp.status_code == 200
        
        # Check active items remaining (without include_deleted)
        resp = client.get("/clipboard/all", headers=headers)
        assert resp.status_code == 200
        active_items = resp.json()
        assert len(active_items) == 1, f"Expected 1 active item (pinned), got {len(active_items)}"
        assert active_items[0]["id"] == pinned_id, f"Expected active item to be the pinned one, got {active_items[0]['id']}"
        print("Bulk delete successfully bypassed pinned item.")

        # Check full history (including deleted)
        resp = client.get("/clipboard/all", params={"include_deleted": True}, headers=headers)
        assert resp.status_code == 200
        all_items = resp.json()
        assert len(all_items) == 2
        deleted_item = next((item for item in all_items if item["id"] == unpinned_id), None)
        assert deleted_item["is_deleted"] is True, "Expected unpinned item to be soft-deleted"
        
        # 6. Single Item Delete: DELETE /clipboard/{pinned_id} (should successfully delete the pinned item)
        print("Manually deleting the pinned item...")
        resp = client.delete(f"/clipboard/{pinned_id}", headers=headers)
        assert resp.status_code == 200
        
        # Verify both items are now deleted
        resp = client.get("/clipboard/all", headers=headers)
        assert resp.status_code == 200
        assert len(resp.json()) == 0, "Expected 0 active items"

        # Check that pinned item was soft-deleted and is_pinned set to False
        resp = client.get("/clipboard/all", params={"include_deleted": True}, headers=headers)
        assert resp.status_code == 200
        items_after_all_deleted = resp.json()
        target_pinned_after_deleted = next((item for item in items_after_all_deleted if item["id"] == pinned_id), None)
        assert target_pinned_after_deleted["is_deleted"] is True, "Pinned item should be soft-deleted"
        assert target_pinned_after_deleted["is_pinned"] is False, "Pinned item should be unpinned on deletion"
        print("Single item delete verified successfully.")

        print("\nCLIPBOARD PIN SYSTEM TESTS PASSED")

if __name__ == "__main__":
    try:
        test_clipboard_pin()
    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
