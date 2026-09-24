# Test Suite: WebSocket ConnectionManager Unit & Resilience Tests

from unittest.mock import AsyncMock
import pytest

from app.websockets.connection_manager import ConnectionManager


@pytest.fixture
def clean_manager():
    return ConnectionManager()


# 1. Disconnect attempt using stale mismatched WebSocket reference acts as a no-op.
@pytest.mark.asyncio
async def test_disconnect_mismatched_websocket_noop(clean_manager):
    ws_current = AsyncMock()
    ws_stale = AsyncMock()

    await clean_manager.connect("user-1", "dev-1", ws_current)
    assert clean_manager.is_device_online("user-1", "dev-1") is True

    clean_manager.disconnect("user-1", "dev-1", websocket=ws_stale)
    assert clean_manager.is_device_online("user-1", "dev-1") is True

    clean_manager.disconnect("user-1", "dev-1", websocket=ws_current)
    assert clean_manager.is_device_online("user-1", "dev-1") is False
    assert "user-1" not in clean_manager.active_connections


# 2. Local broadcast gracefully handles serialization exceptions and cleans up broken connections.
@pytest.mark.asyncio
async def test_broadcast_local_generic_exception_disconnects(clean_manager):
    broken_ws = AsyncMock()
    broken_ws.send_json.side_effect = TypeError("Unexpected serialization failure")

    await clean_manager.connect("user-1", "dev-broken", broken_ws)
    assert clean_manager.is_device_online("user-1", "dev-broken") is True

    await clean_manager._broadcast_local("user-1", {"type": "test"})
    assert clean_manager.is_device_online("user-1", "dev-broken") is False


# 3. Local broadcast filters out excluded origin device correctly.
@pytest.mark.asyncio
async def test_broadcast_local_exclude_device(clean_manager):
    ws1 = AsyncMock()
    ws2 = AsyncMock()

    await clean_manager.connect("user-1", "dev-1", ws1)
    await clean_manager.connect("user-1", "dev-2", ws2)

    msg = {"type": "clipboard_sync", "payload": "xyz"}
    await clean_manager._broadcast_local("user-1", msg, exclude_device="dev-1")

    ws1.send_json.assert_not_called()
    ws2.send_json.assert_called_once_with(msg)


# 4. Device disconnection handles Redis publish failure gracefully and closes socket locally.
@pytest.mark.asyncio
async def test_disconnect_device_redis_publish_failure(clean_manager):
    mock_redis = AsyncMock()
    mock_redis.publish.side_effect = ConnectionError("Redis cluster unreachable")
    clean_manager.set_redis(mock_redis)

    ws = AsyncMock()
    await clean_manager.connect("user-1", "dev-1", ws)

    await clean_manager.disconnect_device("user-1", "dev-1")

    assert clean_manager.is_device_online("user-1", "dev-1") is False
    ws.close.assert_called_once_with(code=4003)


# 5. User disconnection dispatches custom warning message and specific close code.
@pytest.mark.asyncio
async def test_disconnect_user_with_custom_message_and_code(clean_manager):
    ws1 = AsyncMock()
    ws2 = AsyncMock()

    await clean_manager.connect("user-1", "dev-1", ws1)
    await clean_manager.connect("user-1", "dev-2", ws2)

    custom_msg = {"type": "account_suspended", "detail": "Terms violation"}
    await clean_manager.disconnect_user("user-1", code=4002, message=custom_msg)

    for ws in (ws1, ws2):
        ws.send_json.assert_called_once_with(custom_msg)
        ws.close.assert_called_once_with(code=4002)

    assert "user-1" not in clean_manager.active_connections


# 6. User disconnection with close code 4004 auto-populates session invalidation message.
@pytest.mark.asyncio
async def test_disconnect_user_code_4004_auto_populates_message(clean_manager):
    ws = AsyncMock()
    await clean_manager.connect("user-1", "dev-1", ws)

    await clean_manager.disconnect_user("user-1", code=4004, message=None)

    ws.send_json.assert_called_once_with(
        {"type": "session_invalidated", "reason": "credentials_changed"}
    )
    ws.close.assert_called_once_with(code=4004)


# 7. Active connection tracking accurately increments and decrements connection states.
@pytest.mark.asyncio
async def test_active_metrics_tracking(clean_manager):
    ws1 = AsyncMock()
    ws2 = AsyncMock()
    ws3 = AsyncMock()

    await clean_manager.connect("user-1", "dev-1", ws1)
    await clean_manager.connect("user-1", "dev-2", ws2)
    await clean_manager.connect("user-2", "dev-1", ws3)

    assert sum(len(d) for d in clean_manager.active_connections.values()) == 3

    clean_manager.disconnect("user-1", "dev-1", ws1)
    assert sum(len(d) for d in clean_manager.active_connections.values()) == 2

    clean_manager.disconnect("user-1", "dev-2", ws2)
    assert "user-1" not in clean_manager.active_connections
    assert sum(len(d) for d in clean_manager.active_connections.values()) == 1
