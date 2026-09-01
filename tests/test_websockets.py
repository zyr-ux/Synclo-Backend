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
        assert exc_info.value.code in (1008, 4001)


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

