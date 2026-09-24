# Test Suite: ConnectionManager Distributed Redis Pub/Sub Relay & Isolation

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


# 1. Pub/Sub broadcast relays payloads to remote listeners while excluding sender device.
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


# 2. Redis listener ignores echoed messages published by its own instance node ID.
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
    assert ws_dev1.send_json.call_count == 1

    await manager.stop_listener()
    await r1.aclose()


# 3. Disconnect user command relays via Pub/Sub to terminate all user sessions on remote listeners.
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


# 4. Disconnect device command relays via Pub/Sub to terminate target device while keeping others alive.
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


# 5. Redis listener drops malformed envelopes and non-JSON payloads without terminating loop.
@pytest.mark.asyncio
async def test_listener_skips_malformed_and_non_message_types(fake_redis_pair):
    r1, _ = fake_redis_pair
    manager = ConnectionManager()
    manager.set_redis(r1)
    await manager.start_listener()
    await asyncio.sleep(0.02)

    ws_dev = AsyncMock()
    await manager.connect("user_robust", "dev_robust", ws_dev)

    await r1.publish(
        "clipboard:user:user_robust",
        json.dumps({"sender": "other_node", "user_id": None, "message": None}),
    )
    await asyncio.sleep(0.02)

    await r1.publish(
        "clipboard:user:user_robust",
        json.dumps({"sender": "other_node", "unrecognized_key": 123}),
    )
    await asyncio.sleep(0.02)

    await r1.publish(
        "clipboard:user:user_robust",
        json.dumps({"sender": "other_node", "action": "disconnect_user"}),
    )
    await asyncio.sleep(0.02)

    await r1.publish(
        "clipboard:user:user_robust",
        json.dumps({"sender": "other_node", "action": "disconnect_device", "user_id": "user_robust"}),
    )
    await asyncio.sleep(0.02)

    await r1.publish(
        "clipboard:user:user_robust",
        "not-a-valid-json-payload-{{{",
    )
    await asyncio.sleep(0.02)

    assert manager.is_device_online("user_robust", "dev_robust")

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
