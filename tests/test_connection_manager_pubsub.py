"""
Test Suite: ConnectionManager Distributed Redis Pub/Sub Relay & Isolation

Scenarios Targeted:
1. broadcast_to_user publishes to Redis and a remote node's listener relays to its local WebSocket.
2. Listener ignores messages published by its own node (sender self-exclusion via _node_id).
3. disconnect_user publishes to Redis and a remote node's listener executes _disconnect_user_local.
4. disconnect_device publishes to Redis and a remote node's listener executes _disconnect_device_local.
5. Listener skips malformed envelopes, missing fields, and non-message types gracefully.
"""

import asyncio
import json
from unittest.mock import AsyncMock

import fakeredis
import pytest

from app.websockets.connection_manager import ConnectionManager


@pytest.fixture
def fake_redis_pair():
    server = fakeredis.FakeServer()
    r1 = fakeredis.FakeAsyncRedis(server=server)
    r2 = fakeredis.FakeAsyncRedis(server=server)
    return r1, r2


@pytest.mark.asyncio
async def test_broadcast_publishes_to_redis_and_remote_listener_relays(fake_redis_pair):
    r1, r2 = fake_redis_pair
    manager_a = ConnectionManager()
    manager_b = ConnectionManager()
    manager_a.set_redis(r1)
    manager_b.set_redis(r2)

    await manager_a.start_listener()
    await manager_b.start_listener()
    await asyncio.sleep(0.02)

    ws_dev1 = AsyncMock()
    ws_dev2 = AsyncMock()
    await manager_a.connect("user_shared", "dev_1", ws_dev1)
    await manager_b.connect("user_shared", "dev_2", ws_dev2)

    payload = {"type": "clipboard_sync", "id": "clip_relay_test", "is_deleted": False}
    # Manager A broadcasts, excluding dev_1
    await manager_a.broadcast_to_user("user_shared", payload, exclude_device="dev_1")

    for _ in range(20):
        if ws_dev2.send_json.called:
            break
        await asyncio.sleep(0.01)

    assert not ws_dev1.send_json.called
    assert ws_dev2.send_json.called
    ws_dev2.send_json.assert_called_once_with(payload)

    await manager_a.stop_listener()
    await manager_b.stop_listener()
    await r1.aclose()
    await r2.aclose()


@pytest.mark.asyncio
async def test_listener_ignores_own_messages(fake_redis_pair):
    r1, _ = fake_redis_pair
    manager = ConnectionManager()
    manager.set_redis(r1)
    await manager.start_listener()
    await asyncio.sleep(0.02)

    ws_dev1 = AsyncMock()
    await manager.connect("user_single", "dev_1", ws_dev1)

    payload = {"type": "clipboard_sync", "id": "clip_self_ignore"}
    await manager.broadcast_to_user("user_single", payload)
    assert ws_dev1.send_json.call_count == 1

    await asyncio.sleep(0.05)
    # Delivery count should still be 1 (redis bounce was ignored)
    assert ws_dev1.send_json.call_count == 1

    await manager.stop_listener()
    await r1.aclose()


@pytest.mark.asyncio
async def test_disconnect_user_relay_via_pubsub(fake_redis_pair):
    r1, r2 = fake_redis_pair
    manager_a = ConnectionManager()
    manager_b = ConnectionManager()
    manager_a.set_redis(r1)
    manager_b.set_redis(r2)

    await manager_a.start_listener()
    await manager_b.start_listener()
    await asyncio.sleep(0.02)

    ws_dev2 = AsyncMock()
    await manager_b.connect("user_to_disconnect", "dev_2", ws_dev2)
    assert manager_b.is_device_online("user_to_disconnect", "dev_2")

    await manager_a.disconnect_user(
        "user_to_disconnect", code=4004, message={"type": "session_invalidated"}
    )

    for _ in range(20):
        if not manager_b.is_device_online("user_to_disconnect", "dev_2"):
            break
        await asyncio.sleep(0.01)

    assert not manager_b.is_device_online("user_to_disconnect", "dev_2")
    ws_dev2.send_json.assert_called_once_with({"type": "session_invalidated"})
    ws_dev2.close.assert_called_once_with(code=4004)

    await manager_a.stop_listener()
    await manager_b.stop_listener()
    await r1.aclose()
    await r2.aclose()


@pytest.mark.asyncio
async def test_disconnect_device_relay_via_pubsub(fake_redis_pair):
    r1, r2 = fake_redis_pair
    manager_a = ConnectionManager()
    manager_b = ConnectionManager()
    manager_a.set_redis(r1)
    manager_b.set_redis(r2)

    await manager_a.start_listener()
    await manager_b.start_listener()
    await asyncio.sleep(0.02)

    ws_dev2 = AsyncMock()
    ws_dev3 = AsyncMock()
    await manager_b.connect("user_multi_dev", "dev_2", ws_dev2)
    await manager_b.connect("user_multi_dev", "dev_3", ws_dev3)

    await manager_a.disconnect_device("user_multi_dev", "dev_2")

    for _ in range(20):
        if not manager_b.is_device_online("user_multi_dev", "dev_2"):
            break
        await asyncio.sleep(0.01)

    assert not manager_b.is_device_online("user_multi_dev", "dev_2")
    assert manager_b.is_device_online("user_multi_dev", "dev_3")
    ws_dev2.close.assert_called_once_with(code=4003)
    assert not ws_dev3.close.called

    await manager_a.stop_listener()
    await manager_b.stop_listener()
    await r1.aclose()
    await r2.aclose()


@pytest.mark.asyncio
async def test_listener_skips_malformed_and_non_message_types(fake_redis_pair):
    r1, _ = fake_redis_pair
    manager = ConnectionManager()
    manager.set_redis(r1)
    await manager.start_listener()
    await asyncio.sleep(0.02)

    ws_dev = AsyncMock()
    await manager.connect("user_robust", "dev_robust", ws_dev)

    # 1. Envelope missing required user_id / message payload
    await r1.publish(
        "clipboard:user:user_robust",
        json.dumps({"sender": "other_node", "user_id": None, "message": None}),
    )
    await asyncio.sleep(0.02)

    # 2. Envelope with unrecognized schema without user_id
    await r1.publish(
        "clipboard:user:user_robust",
        json.dumps({"sender": "other_node", "unrecognized_key": 123}),
    )
    await asyncio.sleep(0.02)

    # 3. Disconnect user envelope missing user_id
    await r1.publish(
        "clipboard:user:user_robust",
        json.dumps({"sender": "other_node", "action": "disconnect_user"}),
    )
    await asyncio.sleep(0.02)

    # 4. Disconnect device envelope missing device_id
    await r1.publish(
        "clipboard:user:user_robust",
        json.dumps({"sender": "other_node", "action": "disconnect_device", "user_id": "user_robust"}),
    )
    await asyncio.sleep(0.02)

    # 5. Raw non-JSON string (should be safely discarded without killing listener)
    await r1.publish(
        "clipboard:user:user_robust",
        "not-a-valid-json-payload-{{{",
    )
    await asyncio.sleep(0.02)

    # Verify listener loop is still running and device is still online and unharmed
    assert manager.is_device_online("user_robust", "dev_robust")

    # 6. Subsequent valid payload should still be received and broadcasted
    await r1.publish(
        "clipboard:user:user_robust",
        json.dumps({
            "sender": "other_node",
            "user_id": "user_robust",
            "message": {"type": "test_broadcast"},
            "exclude_device": None,
        }),
    )
    await asyncio.sleep(0.02)
    ws_dev.send_json.assert_called_once_with({"type": "test_broadcast"})

    await manager.stop_listener()
    await r1.aclose()
