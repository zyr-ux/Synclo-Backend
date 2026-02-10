import sys
import datetime
from unittest.mock import MagicMock, AsyncMock

# Mock Redis BEFORE importing main to avoid connection attempts
mock_redis_module = MagicMock()
mock_redis_client = AsyncMock()

# handle pubsub
mock_pubsub = MagicMock()
mock_pubsub.psubscribe = AsyncMock()
mock_pubsub.subscribe = AsyncMock()
mock_pubsub.close = AsyncMock()

async def async_iter():
    # Empty generator
    if False:
        yield None

mock_pubsub.listen.return_value = async_iter()

# pubsub() is a sync method returning the pubsub object
mock_redis_client.pubsub = MagicMock(return_value=mock_pubsub)

mock_redis_module.Redis.from_url.return_value = mock_redis_client
sys.modules["redis.asyncio"] = mock_redis_module

# Also mock fastapi_limiter before import
mock_limiter = MagicMock()
sys.modules["fastapi_limiter"] = mock_limiter

# Create a dummy RateLimiter class to avoid FastAPI inspecting MagicMock attributes
# We need to import Request/Response to type hint correctly for FastAPI
from fastapi import Request, Response

class MockRateLimiter:
    def __init__(self, times=1, seconds=1, **kwargs):
        pass
    
    async def __call__(self, request: Request, response: Response):
        pass

mock_limiter_depends = MagicMock()
mock_limiter_depends.RateLimiter = MockRateLimiter
sys.modules["fastapi_limiter.depends"] = mock_limiter_depends

from fastapi.testclient import TestClient
# Now import main
from main import app, get_db
import os
import base64
import time

# Mock FastAPILimiter init just in case
mock_limiter.FastAPILimiter.init = AsyncMock()

def generate_random_email():
    return f"test_{int(time.time())}_{os.urandom(4).hex()}@example.com"

def get_auth_headers(client, email):
    # Register first
    device_id = f"dev_{os.urandom(4).hex()}"
    auth_key = base64.b64encode(os.urandom(32)).decode('utf-8')
    enc_mk = base64.b64encode(os.urandom(32)).decode('utf-8')
    salt = base64.b64encode(os.urandom(16)).decode('utf-8')
    
    reg_data = {
        "email": email,
        "auth_key": auth_key,
        "device_id": device_id,
        "device_name": "Test Device",
        "encrypted_master_key": enc_mk,
        "salt": salt,
        "kdf_version": 1
    }
    
    resp = client.post("/register", json=reg_data)
    assert resp.status_code == 200, f"Register failed: {resp.text}"
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_delta_sync():
    # Use context manager for startup/shutdown events
    with TestClient(app) as client:
        email = generate_random_email()
        headers = get_auth_headers(client, email)
        
        print(f"Created user: {email}")

        # 1. Initial Sync (Since None) - Should be empty
        resp = client.get("/clipboard/sync", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["entries"]) == 0
        print("Initial sync empty: OK")

        # Capture time T0 (Client's last sync time)
        t0 = datetime.datetime.now(datetime.timezone.utc)
        
        # Wait a bit to ensure T0 < next operations
        time.sleep(1)

        # 2. Add Item A
        item_a_id = "item_a_" + os.urandom(4).hex()
        resp = client.post("/clipboard", json={
            "id": item_a_id,
            "ciphertext": base64.b64encode(b"ciphertextA").decode('utf-8'),
            "nonce": base64.b64encode(b"nonceAAAA").decode('utf-8'), # 9 bytes
            "blob_version": 1,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }, headers=headers)
        assert resp.status_code == 200
        print("Added Item A: OK")

        # 3. Sync Since T0 -> Should get Item A
        resp = client.get("/clipboard/sync", params={"since": t0.isoformat()}, headers=headers)
        assert resp.status_code == 200, f"Sync failed: {resp.text}"
        data = resp.json()
        if "entries" not in data:
             print(f"FAILED DATA: {data}")
        assert len(data["entries"]) == 1
        assert data["entries"][0]["id"] == item_a_id
        
        # Get T1 from Item A's updated_at
        item_a_updated_at = data["entries"][0]["updated_at"]
        print(f"Sync since T0 returned A: OK. T1={item_a_updated_at}")
        
        # Wait for distinct timestamp
        time.sleep(1)

        # 4. Add Item B
        item_b_id = "item_b_" + os.urandom(4).hex()
        resp = client.post("/clipboard", json={
            "id": item_b_id,
            "ciphertext": base64.b64encode(b"ciphertextB").decode('utf-8'),
            "nonce": base64.b64encode(b"nonceBBBB").decode('utf-8'), # 9 bytes
            "blob_version": 1,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }, headers=headers)
        assert resp.status_code == 200
        print("Added Item B: OK")

        # 5. Sync Since T1 -> Should get Item B only
        resp = client.get("/clipboard/sync", params={"since": item_a_updated_at}, headers=headers)
        data = resp.json()
        assert len(data["entries"]) == 1
        assert data["entries"][0]["id"] == item_b_id
        
        item_b_updated_at = data["entries"][0]["updated_at"]
        print(f"Sync since T1 returned B only: OK. T2={item_b_updated_at}")

        time.sleep(1)

        # 6. Update Item A
        resp = client.post("/clipboard", json={
            "id": item_a_id,
            "ciphertext": base64.b64encode(b"ciphertextA_updated").decode('utf-8'),
            "nonce": base64.b64encode(b"nonceAAAA").decode('utf-8'), # 9 bytes
            "blob_version": 1,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }, headers=headers)
        assert resp.status_code == 200
        print("Updated Item A: OK")

        # 7. Sync Since T2 -> Should get Item A (updated)
        resp = client.get("/clipboard/sync", params={"since": item_b_updated_at}, headers=headers)
        data = resp.json()
        assert len(data["entries"]) == 1
        assert data["entries"][0]["id"] == item_a_id
        
        item_a_updated_at_2 = data["entries"][0]["updated_at"]
        print(f"Sync since T2 returned updated A: OK. T3={item_a_updated_at_2}")

        time.sleep(1)

        # 8. Delete Item B
        resp = client.delete(f"/clipboard/{item_b_id}", headers=headers)
        assert resp.status_code == 200
        print("Deleted Item B: OK")

        # 9. Sync Since T3 -> Should get Item B (deleted)
        resp = client.get("/clipboard/sync", params={"since": item_a_updated_at_2}, headers=headers)
        data = resp.json()
        assert len(data["entries"]) == 1
        assert data["entries"][0]["id"] == item_b_id
        assert data["entries"][0]["is_deleted"] == True
        print("Sync since T3 returned deleted B: OK")

        # 10. Expired Sync -> Should return 410
        # Create a timestamp 31 days ago
        expired_ts = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=31)
        resp = client.get("/clipboard/sync", params={"since": expired_ts.isoformat()}, headers=headers)
        assert resp.status_code == 410, f"Expired sync failed: {resp.status_code} {resp.text}"
        print("Expired sync returned 410: OK")

        # 11. Pagination Test
        # Create a few more items with distinct updated_at (controlled by sleep or just rapid fire if resolution is high enough)
        # SQLite resolution might be tricky, so let's sleep a tiny bit.
        
        # Add 3 items
        for i in range(3):
            cid = f"page_item_{i}_{os.urandom(4).hex()}"
            client.post("/clipboard", json={
                "id": cid,
                "ciphertext": base64.b64encode(f"content{i}".encode()).decode(),
                "nonce": base64.b64encode(b"noncePPPP").decode(),
                "blob_version": 1,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }, headers=headers)
            time.sleep(0.1) # Ensure distinct updated_at
            
        # Get last sync time before these 3 items (it was item_a_updated_at_2 or similar, but let's just query all)
        # We want to test pagination on the WHOLE set.
        
        # Request limit=2 (should get 2 items)
        resp = client.get("/clipboard/sync", params={"limit": 2}, headers=headers)
        data = resp.json()
        assert len(data["entries"]) == 2
        assert data["has_more"] == True
        print("Pagination limit=2 returned 2 items: OK")
        
        # Request offset=2 (should get the rest)
        resp = client.get("/clipboard/sync", params={"limit": 2, "offset": 2}, headers=headers)
        data = resp.json()
        assert len(data["entries"]) >= 1 # We added at least 3 new ones + previous ones
        print("Pagination offset=2 returned items: OK")

        print("\nALL TESTS PASSED")

if __name__ == "__main__":
    try:
        test_delta_sync()
    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        import traceback
        traceback.print_exc()
