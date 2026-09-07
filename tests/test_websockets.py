"""
Test Suite: Real-Time WebSocket Synchronization & Event Broadcasting

Scenarios Targeted:
1. WebSocket connection lifecycle and heartbeat ping/pong message exchange.
2. Synchronous clipboard creation via WebSocket receiving server acknowledgment ({'type': 'ack'}).
3. Live broadcast of display username changes across connected client devices.
4. Live broadcast of email address updates across connected client devices.
5. Live multi-device clipboard sync propagation from device 1 to device 2.
6. Connection rejection (error frame / close 1008) when authentication credentials are missing.
"""

import pytest
from starlette.websockets import WebSocketDisconnect
from tests.conftest import make_clipboard_payload


_MAX_WS_RECV_ATTEMPTS = 50


def _receive_non_ping(ws):
    """Receive the next non-ping message, with a guard against infinite loops."""
    for _ in range(_MAX_WS_RECV_ATTEMPTS):
        msg = ws.receive_json()
        if msg.get("type") == "ping":
            ws.send_json({"type": "pong"})
            continue
        return msg
    raise TimeoutError(
        f"Did not receive a non-ping message after {_MAX_WS_RECV_ATTEMPTS} attempts"
    )


def test_websocket_connect_and_ping(client, auth_user):
    token = auth_user["access_token"]
    with client.websocket_connect("/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}) as ws:
        # Send ping
        ws.send_json({"type": "ping"})
        response = _receive_non_ping(ws)
        assert response.get("type") == "pong"


def test_websocket_clipboard_sync_event(client, auth_user):
    token = auth_user["access_token"]
    with client.websocket_connect("/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}) as ws:
        # Send clipboard item over websocket
        clip_id = "ws_clip_item_01"
        ws.send_json(make_clipboard_payload(clip_id))
        resp = _receive_non_ping(ws)
        assert resp.get("type") == "ack"
        assert resp.get("id") == clip_id


def test_websocket_broadcast_on_username_update(client, user_factory):
    # Setup user with 2 devices
    user = user_factory(username="orig_name")

    # Register device 2
    dev2_res = client.post("/api/v1/login", json={
        "email": user["email"],
        "auth_key": user["auth_key"],
        "device_id": "ws_device_2",
        "device_name": "Device 2",
        "os": "Android",
    })
    token_dev2 = dev2_res.json()["access_token"]

    # Device 2 connects to WebSocket
    with client.websocket_connect("/ws/v1/sync", headers={"Authorization": f"Bearer {token_dev2}"}) as ws_dev2:
        # Device 1 updates username via REST
        resp_update = client.put(
            "/api/v1/user/username",
            json={"username": "broadcasted_name"},
            headers=user["headers"],
        )
        assert resp_update.status_code == 200

        # Device 2 should receive username_updated broadcast
        msg = _receive_non_ping(ws_dev2)
        assert msg.get("type") == "username_updated"
        assert msg.get("username") == "broadcasted_name"


def test_websocket_broadcast_on_email_update(client, user_factory):
    user = user_factory()
    dev2_res = client.post("/api/v1/login", json={
        "email": user["email"],
        "auth_key": user["auth_key"],
        "device_id": "ws_device_email_2",
        "device_name": "Device 2",
        "os": "iOS",
    })
    token_dev2 = dev2_res.json()["access_token"]

    with client.websocket_connect("/ws/v1/sync", headers={"Authorization": f"Bearer {token_dev2}"}) as ws_dev2:
        new_email = f"new_{user['email']}"
        res = client.put(
            "/api/v1/user/email",
            json={"email": new_email},
            headers=user["headers"],
        )
        assert res.status_code == 200

        msg = _receive_non_ping(ws_dev2)
        assert msg.get("type") == "email_updated"
        assert msg.get("email") == new_email


def test_websocket_clipboard_broadcast_to_other_devices(client, user_factory):
    user = user_factory()
    dev2_res = client.post("/api/v1/login", json={
        "email": user["email"],
        "auth_key": user["auth_key"],
        "device_id": "ws_device_clip_2",
        "device_name": "Device 2",
        "os": "Android",
    })
    token_dev2 = dev2_res.json()["access_token"]

    with client.websocket_connect("/ws/v1/sync", headers=user["headers"]) as ws1:
        with client.websocket_connect("/ws/v1/sync", headers={"Authorization": f"Bearer {token_dev2}"}) as ws2:
            clip_id = "broadcast_item_123"
            ws1.send_json(make_clipboard_payload(clip_id, timestamp="2026-08-20T12:00:00Z"))
            ack = _receive_non_ping(ws1)
            assert ack.get("type") == "ack"

            # Device 2 should receive broadcast
            broadcast_msg = _receive_non_ping(ws2)
            assert broadcast_msg.get("type") == "clipboard_sync"
            assert broadcast_msg.get("id") == clip_id
            assert broadcast_msg.get("is_deleted") is False


def test_replaced_websocket_disconnect_does_not_remove_current_connection():
    from unittest.mock import MagicMock
    from app.websockets.connection_manager import ConnectionManager

    manager = ConnectionManager()
    old_socket = MagicMock()
    new_socket = MagicMock()
    manager.active_connections["user"] = {"device": new_socket}

    manager.disconnect("user", "device", old_socket)

    assert manager.active_connections["user"]["device"] is new_socket


def test_websocket_rejects_missing_auth(client):
    from starlette.websockets import WebSocketDisconnect
    with client.websocket_connect("/ws/v1/sync") as ws:
        msg = ws.receive_json()
        assert msg.get("type") == "error"
        assert "Authorization" in msg.get("message", "")
        with pytest.raises(WebSocketDisconnect) as exc_info:
            ws.receive_json()
        assert exc_info.value.code == 1008


def test_websocket_rejects_expired_token(client, auth_user):
    from starlette.websockets import WebSocketDisconnect
    from app.services.auth import create_access_token
    import datetime

    # Create an expired token (-1 minute)
    expired_token = create_access_token(
        data={"sub": auth_user["email"], "device_id": auth_user["device_id"]},
        expires_delta=datetime.timedelta(minutes=-1)
    )

    with client.websocket_connect("/ws/v1/sync", headers={"Authorization": f"Bearer {expired_token}"}) as ws:
        # Should be rejected
        msg = ws.receive_json()
        assert msg.get("type") == "error"
        with pytest.raises(WebSocketDisconnect) as exc_info:
            ws.receive_json()
        assert exc_info.value.code == 4001


def test_websocket_rejects_blacklisted_token(client, auth_user):
    from starlette.websockets import WebSocketDisconnect
    token = auth_user["access_token"]
    refresh_token = auth_user["refresh_token"]

    # Logout to blacklist the access token
    res_logout = client.post(
        "/api/v1/logout",
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res_logout.status_code == 200

    # Attempt to connect to WebSocket with the blacklisted token
    with client.websocket_connect("/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}) as ws:
        msg = ws.receive_json()
        assert msg.get("type") == "error"
        assert "Token has been revoked" in msg.get("message", "")
        with pytest.raises(WebSocketDisconnect) as exc_info:
            ws.receive_json()
        assert exc_info.value.code == 1008


def test_websocket_broadcast_on_pin_update(client, user_factory):
    user = user_factory()
    dev2_res = client.post("/api/v1/login", json={
        "email": user["email"],
        "auth_key": user["auth_key"],
        "device_id": "ws_device_pin_2",
        "device_name": "Device 2",
        "os": "Android",
    })
    token_dev2 = dev2_res.json()["access_token"]

    clip_id = "ws_pin_broadcast_item"
    client.post("/api/v1/clipboard", json=make_clipboard_payload(clip_id), headers=user["headers"])

    with client.websocket_connect("/ws/v1/sync", headers={"Authorization": f"Bearer {token_dev2}"}) as ws2:
        # Device 1 pins the clipboard item
        res = client.patch(
            f"/api/v1/clipboard/{clip_id}/pin",
            json={"is_pinned": True},
            headers=user["headers"]
        )
        assert res.status_code == 200

        # Device 2 should receive the clipboard_pin broadcast
        msg = _receive_non_ping(ws2)
        assert msg.get("type") == "clipboard_pin"
        assert msg.get("id") == clip_id
        assert msg.get("is_pinned") is True
        assert msg.get("pinned_at") is not None
        assert msg.get("updated_at") is not None


def test_websocket_broadcast_on_device_rename(client, user_factory):
    user = user_factory()
    dev2_res = client.post("/api/v1/login", json={
        "email": user["email"],
        "auth_key": user["auth_key"],
        "device_id": "ws_device_rename_2",
        "device_name": "Device 2",
        "os": "macOS",
    })
    token_dev2 = dev2_res.json()["access_token"]

    with client.websocket_connect("/ws/v1/sync", headers={"Authorization": f"Bearer {token_dev2}"}) as ws2:
        # Device 1 renames device 2 (or its own device)
        res = client.patch(
            f"/api/v1/devices/{user['device_id']}",
            json={"device_name": "Desktop Beast"},
            headers=user["headers"]
        )
        assert res.status_code == 200

        # Device 2 should receive the device_updated broadcast
        msg = _receive_non_ping(ws2)
        assert msg.get("type") == "device_updated"
        device_info = msg.get("device")
        assert device_info is not None
        assert device_info.get("device_id") == user["device_id"]
        assert device_info.get("device_name") == "Desktop Beast"
        assert device_info.get("os") == user["os"]


@pytest.mark.asyncio
async def test_disconnect_device_distributed_via_redis():
    import json
    from unittest.mock import AsyncMock
    from app.websockets.connection_manager import ConnectionManager

    mgr = ConnectionManager()
    mock_redis = AsyncMock()
    mock_redis.publish = AsyncMock()
    mgr.set_redis(mock_redis)

    await mgr.disconnect_device(user_id="test_user", device_id="test_device")

    mock_redis.publish.assert_awaited_once()
    call_args = mock_redis.publish.call_args[0]
    channel = call_args[0]
    envelope = json.loads(call_args[1])

    assert channel == mgr._channel("test_user")
    assert envelope["action"] == "disconnect_device"
    assert envelope["user_id"] == "test_user"
    assert envelope["device_id"] == "test_device"
    assert envelope["sender"] == mgr._node_id


@pytest.mark.asyncio
async def test_disconnect_device_local_closes_socket():
    from unittest.mock import AsyncMock
    from app.websockets.connection_manager import ConnectionManager

    mgr = ConnectionManager()
    mock_ws = AsyncMock()
    mgr.active_connections["u1"] = {"d1": mock_ws}

    await mgr._disconnect_device_local("u1", "d1")

    mock_ws.send_json.assert_awaited_once_with({
        "type": "device_deleted",
        "message": "This device has been removed from your account",
    })
    mock_ws.close.assert_awaited_once_with(code=4003)
    assert "d1" not in mgr.active_connections.get("u1", {})


def test_device_deletion_closes_websocket_with_4003(client, user_factory):
    user = user_factory()
    dev2_res = client.post("/api/v1/login", json={
        "email": user["email"],
        "auth_key": user["auth_key"],
        "device_id": "ws_device_del_test",
        "device_name": "Device 2",
        "os": "Android",
    })
    token_dev2 = dev2_res.json()["access_token"]

    with client.websocket_connect("/ws/v1/sync", headers={"Authorization": f"Bearer {token_dev2}"}) as ws2:
        res = client.delete(
            "/api/v1/devices/ws_device_del_test",
            headers=user["headers"]
        )
        assert res.status_code == 200

        try:
            msg = ws2.receive_json()
            assert msg.get("type") == "device_deleted"
        except WebSocketDisconnect as exc:
            assert exc.code == 4003


def test_websocket_duplicate_write_noop_suppresses_push(client, auth_user, monkeypatch):
    from unittest.mock import MagicMock
    import app.endpoints.websocket_endpoints as ws_endpoints

    mock_push = MagicMock()
    monkeypatch.setattr(ws_endpoints, "launch_background_push", mock_push)

    token = auth_user["access_token"]
    payload = make_clipboard_payload("ws_noop_test_item")

    with client.websocket_connect("/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}) as ws:
        # First write
        ws.send_json(payload)
        resp1 = _receive_non_ping(ws)
        assert resp1.get("type") == "ack"
        assert mock_push.call_count == 1

        # Duplicate write (same payload & timestamp)
        ws.send_json(payload)
        resp2 = _receive_non_ping(ws)
        assert resp2.get("type") == "ack"
        # Push should NOT be called again
        assert mock_push.call_count == 1


def test_websocket_soft_delete_event(client, auth_user):
    token = auth_user["access_token"]
    clip_id = "ws_delete_clip_item"

    # 1. Create active item via REST
    client.post("/api/v1/clipboard", json=make_clipboard_payload(clip_id, timestamp="2026-09-04T10:00:00Z"), headers=auth_user["headers"])

    # 2. Connect to WebSocket and send soft-delete payload
    del_payload = {
        "id": clip_id,
        "ciphertext": None,
        "nonce": None,
        "blob_version": 1,
        "is_deleted": True,
        "is_pinned": False,
        "timestamp": "2026-09-04T11:00:00Z",
    }
    with client.websocket_connect("/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}) as ws:
        ws.send_json(del_payload)
        ack = _receive_non_ping(ws)
        assert ack.get("type") == "ack"
        assert ack.get("id") == clip_id

    # 3. Verify item is soft-deleted
    res_get = client.get(f"/api/v1/clipboard/{clip_id}", headers=auth_user["headers"])
    assert res_get.status_code == 200
    assert res_get.json()["is_deleted"] is True
    assert res_get.json()["ciphertext"] is None


def test_websocket_conflict_stale_write_rejected(client, auth_user):
    token = auth_user["access_token"]
    clip_id = "ws_conflict_item"

    # 1. Write active item at T2
    client.post("/api/v1/clipboard", json=make_clipboard_payload(clip_id, timestamp="2026-09-04T12:00:00Z"), headers=auth_user["headers"])

    # 2. Connect to WebSocket and attempt stale write at older T1
    stale_payload = make_clipboard_payload(clip_id, timestamp="2026-09-04T11:00:00Z")
    with client.websocket_connect("/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}) as ws:
        ws.send_json(stale_payload)
        resp = _receive_non_ping(ws)
        assert resp.get("type") == "error"
        assert resp.get("code") == "conflict"
        assert resp.get("id") == clip_id
        assert "conflict" in resp.get("message", "").lower()


