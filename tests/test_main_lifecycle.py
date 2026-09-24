# Test Suite: Application Lifecycle, Exception Handlers & Background Tasks

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import APIRouter, HTTPException
from starlette.testclient import TestClient

from app.main import app, periodic_cleanup
from app.services.cleanup_service import CleanupResult


# 1. Unhandled exceptions trigger the internal exception handler returning 500 JSON.
def test_internal_exception_handler_returns_500_json():
    router = APIRouter()

    @router.get("/api/test-internal-crash-route")
    def crash_endpoint():
        raise RuntimeError("Simulated unhandled server crash")

    app.include_router(router)
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            res = client.get("/api/test-internal-crash-route")
            assert res.status_code == 500
            assert res.json() == {"detail": "Internal Server Error"}
    finally:
        app.routes[:] = [
            r for r in app.routes if getattr(r, "path", None) != "/api/test-internal-crash-route"
        ]


# 2. HTTPException triggers the HTTP exception handler returning formatted JSON error.
def test_http_exception_handler_returns_json_body():
    router = APIRouter()

    @router.get("/api/test-custom-http-route")
    def custom_http_endpoint():
        raise HTTPException(status_code=418, detail="I am a teapot")

    app.include_router(router)
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            res = client.get("/api/test-custom-http-route")
            assert res.status_code == 418
            assert res.json() == {"detail": "I am a teapot"}
    finally:
        app.routes[:] = [
            r for r in app.routes if getattr(r, "path", None) != "/api/test-custom-http-route"
        ]


# 3. Server health check endpoint returns 200 OK and genuine server header.
def test_health_check_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok", "server": "synclo"}
    assert res.headers.get("Synclo-Server") == "genuine"


# 4. Periodic cleanup background loop broadcasts tombstones and triggers push notifications.
@pytest.mark.asyncio
async def test_periodic_cleanup_broadcasts_tombstones_and_triggers_push():
    sample_tombstones = [
        ("user_alpha", {"type": "clipboard_sync", "id": "tomb_1"}),
        ("user_beta", {"type": "clipboard_sync", "id": "tomb_2"}),
        ("user_alpha", {"type": "clipboard_sync", "id": "tomb_3"}),
    ]
    mock_result = CleanupResult(tombstones=sample_tombstones, failures=0)

    with patch.object(app.state, "redis", None):
        with patch("app.main._execute_cleanup", return_value=mock_result):
            with patch("app.main.manager.broadcast_to_user", new_callable=AsyncMock) as mock_bcast:
                with patch("app.main.launch_background_push") as mock_push:
                    task = asyncio.create_task(periodic_cleanup())
                    await asyncio.sleep(0.02)
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

                    assert mock_bcast.call_count == 3
                    mock_bcast.assert_any_call(
                        user_id="user_alpha", message={"type": "clipboard_sync", "id": "tomb_1"}
                    )
                    mock_bcast.assert_any_call(
                        user_id="user_beta", message={"type": "clipboard_sync", "id": "tomb_2"}
                    )
                    mock_bcast.assert_any_call(
                        user_id="user_alpha", message={"type": "clipboard_sync", "id": "tomb_3"}
                    )

                    assert mock_push.call_count == 2
                    mock_push.assert_any_call(user_id="user_alpha")
                    mock_push.assert_any_call(user_id="user_beta")
