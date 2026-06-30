import sys
from unittest.mock import MagicMock, AsyncMock

# Mock Redis BEFORE importing main to avoid connection attempts
mock_redis_module = MagicMock()
mock_redis_client = AsyncMock()
mock_pubsub = MagicMock()
mock_pubsub.psubscribe = AsyncMock()
mock_pubsub.subscribe = AsyncMock()
mock_pubsub.close = AsyncMock()

async def async_iter():
    if False:
        yield None

mock_pubsub.listen.return_value = async_iter()
mock_redis_client.pubsub = MagicMock(return_value=mock_pubsub)
mock_redis_module.Redis.from_url.return_value = mock_redis_client
sys.modules["redis.asyncio"] = mock_redis_module

# Also mock fastapi_limiter before import
mock_limiter = MagicMock()
sys.modules["fastapi_limiter"] = mock_limiter

# Create a dummy RateLimiter class to avoid FastAPI inspecting MagicMock attributes
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
from app.main import app

# Mock FastAPILimiter init just in case
mock_limiter.FastAPILimiter.init = AsyncMock()

def test_health_endpoint():
    with TestClient(app) as client:
        path = "/api/health"
        resp = client.get(path)
        assert resp.status_code == 200, f"Expected 200 for {path}, got {resp.status_code}"
        
        # Verify JSON response
        data = resp.json()
        assert data.get("status") == "ok", f"Expected status 'ok', got {data.get('status')}"
        assert data.get("server") == "synclo", f"Expected server 'synclo', got {data.get('server')}"
        
        # Verify custom headers
        assert "Synclo-Server" in resp.headers, f"Header 'Synclo-Server' is missing in response for {path}"
        assert resp.headers["Synclo-Server"] == "genuine", f"Expected header value 'genuine', got {resp.headers['Synclo-Server']}"
        
        print(f"Health endpoint ({path}) response:", data)
        print(f"Health endpoint ({path}) headers:", dict(resp.headers))
        
        # Verify root /health is gone (should return 404)
        gone_resp = client.get("/health")
        assert gone_resp.status_code == 404, f"Expected 404 for /health, got {gone_resp.status_code}"
        
        print("HEALTH CHECK VERIFICATION PASSED")

if __name__ == "__main__":
    test_health_endpoint()
