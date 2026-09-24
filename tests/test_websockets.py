# Test Suite: Real-Time WebSocket Synchronization & Event Broadcasting

import time
from datetime import timedelta
import jwt
import pytest
from sqlalchemy import delete, select
from starlette.websockets import WebSocketDisconnect

from app.database.engine import run_in_write_transaction
from app.database.models import Device
from app.services.auth import ALGORITHM, SECRET_KEY, create_access_token
from tests.conftest import make_clipboard_payload


_MAX_WS_RECV_ATTEMPTS = 50


def _receive_non_ping(ws):
    for _ in range(_MAX_WS_RECV_ATTEMPTS):
        msg = ws.receive_json()
        if msg.get("type") == "ping":
            ws.send_json({"type": "pong"})
            continue
        return msg
    raise TimeoutError(f"Did not receive a non-ping message after {_MAX_WS_RECV_ATTEMPTS} attempts")


# 1. WebSocket connection lifecycle and heartbeat ping/pong message exchange.
def test_websocket_connect_and_ping(client, auth_user):
    token = auth_user["access_token"]
    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}
    ) as ws:
        ws.send_json({"type": "ping"})
        response = _receive_non_ping(ws)
        assert response.get("type") == "pong"


# 2. Synchronous clipboard creation via WebSocket receiving server acknowledgment.
def test_websocket_clipboard_sync_event(client, auth_user):
    token = auth_user["access_token"]
    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}
    ) as ws:
        clip_id = "ws_clip_item_01"
        ws.send_json(make_clipboard_payload(clip_id))
        resp = _receive_non_ping(ws)
        assert resp.get("type") == "ack"
        assert resp.get("id") == clip_id


# 3. Live broadcast of display username changes across connected client devices.
def test_websocket_broadcast_on_username_update(client, user_factory):
    user = user_factory(username="orig_name")

    dev2_res = client.post(
        "/api/v1/login",
        json={
            "email": user["email"],
            "auth_key": user["auth_key"],
            "device_id": "ws_device_2",
            "device_name": "Device 2",
            "os": "Android",
        },
    )
    token_dev2 = dev2_res.json()["access_token"]

    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token_dev2}"}
    ) as ws_dev2:
        resp_update = client.put(
            "/api/v1/user/username",
            json={"username": "broadcasted_name"},
            headers=user["headers"],
        )
        assert resp_update.status_code == 200

        msg = _receive_non_ping(ws_dev2)
        assert msg.get("type") == "username_updated"
        assert msg.get("username") == "broadcasted_name"


# 4. Live broadcast of email address updates across connected client devices.
def test_websocket_broadcast_on_email_update(client, user_factory):
    user = user_factory()
    dev2_res = client.post(
        "/api/v1/login",
        json={
            "email": user["email"],
            "auth_key": user["auth_key"],
            "device_id": "ws_device_email_2",
            "device_name": "Device 2",
            "os": "iOS",
        },
    )
    token_dev2 = dev2_res.json()["access_token"]

    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token_dev2}"}
    ) as ws_dev2:
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


# 5. Live multi-device clipboard sync propagation from device 1 to device 2.
def test_websocket_clipboard_broadcast_to_other_devices(client, user_factory):
    user = user_factory()
    dev2_res = client.post(
        "/api/v1/login",
        json={
            "email": user["email"],
            "auth_key": user["auth_key"],
            "device_id": "ws_device_clip_2",
            "device_name": "Device 2",
            "os": "Android",
        },
    )
    token_dev2 = dev2_res.json()["access_token"]

    with client.websocket_connect("/ws/v1/sync", headers=user["headers"]) as ws1:
        with client.websocket_connect(
            "/ws/v1/sync", headers={"Authorization": f"Bearer {token_dev2}"}
        ) as ws2:
            clip_id = "broadcast_item_123"
            ws1.send_json(make_clipboard_payload(clip_id, timestamp="2026-08-20T12:00:00Z"))
            ack = _receive_non_ping(ws1)
            assert ack.get("type") == "ack"

            broadcast_msg = _receive_non_ping(ws2)
            assert broadcast_msg.get("type") == "clipboard_sync"
            assert broadcast_msg.get("id") == clip_id
            assert broadcast_msg.get("is_deleted") is False


# 6. Disconnection of replaced socket does not remove active replacement socket.
def test_replaced_websocket_disconnect_does_not_remove_current_connection():
    from unittest.mock import MagicMock
    from app.websockets.connection_manager import ConnectionManager

    manager = ConnectionManager()
    old_socket = MagicMock()
    new_socket = MagicMock()
    manager.active_connections["user"] = {"device": new_socket}

    manager.disconnect("user", "device", old_socket)

    assert manager.active_connections["user"]["device"] is new_socket


# 7. Connection rejection (close code 1008) when authentication credentials are missing.
def test_websocket_rejects_missing_auth(client):
    from starlette.websockets import WebSocketDisconnect

    with client.websocket_connect("/ws/v1/sync") as ws:
        msg = ws.receive_json()
        assert msg.get("type") == "error"
        assert "Authorization" in msg.get("message", "")
        with pytest.raises(WebSocketDisconnect) as exc_info:
            ws.receive_json()
        assert exc_info.value.code == 1008


# 8. Connection rejection (close code 4001) when access token is expired upon handshake.
def test_websocket_rejects_expired_token(client, auth_user):
    from starlette.websockets import WebSocketDisconnect
    from app.services.auth import create_access_token
    import datetime

    expired_token = create_access_token(
        data={"sub": auth_user["email"], "device_id": auth_user["device_id"]},
        expires_delta=datetime.timedelta(minutes=-1),
    )

    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {expired_token}"}
    ) as ws:
        msg = ws.receive_json()
        assert msg.get("type") == "error"
        with pytest.raises(WebSocketDisconnect) as exc_info:
            ws.receive_json()
        assert exc_info.value.code == 4001


# 9. Connection rejection (close code 1008) when access token is blacklisted.
def test_websocket_rejects_blacklisted_token(client, auth_user):
    from starlette.websockets import WebSocketDisconnect

    token = auth_user["access_token"]
    refresh_token = auth_user["refresh_token"]

    res_logout = client.post(
        "/api/v1/logout",
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res_logout.status_code == 200

    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}
    ) as ws:
        msg = ws.receive_json()
        assert msg.get("type") == "error"
        assert "Token has been revoked" in msg.get("message", "")
        with pytest.raises(WebSocketDisconnect) as exc_info:
            ws.receive_json()
        assert exc_info.value.code == 1008


# 10. Live broadcast of clipboard pin state update across connected client devices.
def test_websocket_broadcast_on_pin_update(client, user_factory):
    user = user_factory()
    dev2_res = client.post(
        "/api/v1/login",
        json={
            "email": user["email"],
            "auth_key": user["auth_key"],
            "device_id": "ws_device_pin_2",
            "device_name": "Device 2",
            "os": "Android",
        },
    )
    token_dev2 = dev2_res.json()["access_token"]

    clip_id = "ws_pin_broadcast_item"
    client.post("/api/v1/clipboard", json=make_clipboard_payload(clip_id), headers=user["headers"])

    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token_dev2}"}
    ) as ws2:
        res = client.patch(
            f"/api/v1/clipboard/{clip_id}/pin", json={"is_pinned": True}, headers=user["headers"]
        )
        assert res.status_code == 200

        msg = _receive_non_ping(ws2)
        assert msg.get("type") == "clipboard_pin"
        assert msg.get("id") == clip_id
        assert msg.get("is_pinned") is True
        assert msg.get("pinned_at") is not None
        assert msg.get("updated_at") is not None


# 11. Live broadcast of device rename across connected client devices.
def test_websocket_broadcast_on_device_rename(client, user_factory):
    user = user_factory()
    dev2_res = client.post(
        "/api/v1/login",
        json={
            "email": user["email"],
            "auth_key": user["auth_key"],
            "device_id": "ws_device_rename_2",
            "device_name": "Device 2",
            "os": "macOS",
        },
    )
    token_dev2 = dev2_res.json()["access_token"]

    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token_dev2}"}
    ) as ws2:
        res = client.patch(
            f"/api/v1/devices/{user['device_id']}",
            json={"device_name": "Desktop Beast"},
            headers=user["headers"],
        )
        assert res.status_code == 200

        msg = _receive_non_ping(ws2)
        assert msg.get("type") == "device_updated"
        device_info = msg.get("device")
        assert device_info is not None
        assert device_info.get("device_id") == user["device_id"]
        assert device_info.get("device_name") == "Desktop Beast"
        assert device_info.get("os") == user["os"]


# 12. Remote device disconnection command publishes to Redis channel.
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


# 13. Local device disconnection sends device_deleted frame and closes socket with code 4003.
@pytest.mark.asyncio
async def test_disconnect_device_local_closes_socket():
    from unittest.mock import AsyncMock
    from app.websockets.connection_manager import ConnectionManager

    mgr = ConnectionManager()
    mock_ws = AsyncMock()
    mgr.active_connections["u1"] = {"d1": mock_ws}

    await mgr._disconnect_device_local("u1", "d1")

    mock_ws.send_json.assert_awaited_once_with(
        {
            "type": "device_deleted",
            "message": "This device has been removed from your account",
        }
    )
    mock_ws.close.assert_awaited_once_with(code=4003)
    assert "d1" not in mgr.active_connections.get("u1", {})


# 14. REST device deletion terminates target device WebSocket with close code 4003.
def test_device_deletion_closes_websocket_with_4003(client, user_factory):
    user = user_factory()
    dev2_res = client.post(
        "/api/v1/login",
        json={
            "email": user["email"],
            "auth_key": user["auth_key"],
            "device_id": "ws_device_del_test",
            "device_name": "Device 2",
            "os": "Android",
        },
    )
    token_dev2 = dev2_res.json()["access_token"]

    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token_dev2}"}
    ) as ws2:
        res = client.delete("/api/v1/devices/ws_device_del_test", headers=user["headers"])
        assert res.status_code == 200

        try:
            msg = ws2.receive_json()
            assert msg.get("type") == "device_deleted"
        except WebSocketDisconnect as exc:
            assert exc.code == 4003


# 15. Duplicate clipboard write over WebSocket returns ack and suppresses push notification.
def test_websocket_duplicate_write_noop_suppresses_push(client, auth_user, monkeypatch):
    from unittest.mock import MagicMock
    import app.websockets.websocket_endpoints as ws_endpoints

    mock_push = MagicMock()
    monkeypatch.setattr(ws_endpoints, "launch_background_push", mock_push)

    token = auth_user["access_token"]
    payload = make_clipboard_payload("ws_noop_test_item")

    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}
    ) as ws:
        ws.send_json(payload)
        resp1 = _receive_non_ping(ws)
        assert resp1.get("type") == "ack"
        assert mock_push.call_count == 1

        ws.send_json(payload)
        resp2 = _receive_non_ping(ws)
        assert resp2.get("type") == "ack"
        assert mock_push.call_count == 1


# 16. Soft-delete tombstone synchronization over WebSocket converts database record.
def test_websocket_soft_delete_event(client, auth_user):
    token = auth_user["access_token"]
    clip_id = "ws_delete_clip_item"

    client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload(clip_id, timestamp="2026-09-04T10:00:00Z"),
        headers=auth_user["headers"],
    )

    del_payload = {
        "id": clip_id,
        "ciphertext": None,
        "nonce": None,
        "blob_version": 1,
        "is_deleted": True,
        "is_pinned": False,
        "timestamp": "2026-09-04T11:00:00Z",
    }
    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}
    ) as ws:
        ws.send_json(del_payload)
        ack = _receive_non_ping(ws)
        assert ack.get("type") == "ack"
        assert ack.get("id") == clip_id

    res_get = client.get(f"/api/v1/clipboard/{clip_id}", headers=auth_user["headers"])
    assert res_get.status_code == 200
    assert res_get.json()["is_deleted"] is True
    assert res_get.json()["ciphertext"] is None


# 17. Stale write rejection over WebSocket returning conflict error when payload timestamp is older.
def test_websocket_conflict_stale_write_rejected(client, auth_user):
    token = auth_user["access_token"]
    clip_id = "ws_conflict_item"

    client.post(
        "/api/v1/clipboard",
        json=make_clipboard_payload(clip_id, timestamp="2026-09-04T12:00:00Z"),
        headers=auth_user["headers"],
    )

    stale_payload = make_clipboard_payload(clip_id, timestamp="2026-09-04T11:00:00Z")
    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}
    ) as ws:
        ws.send_json(stale_payload)
        resp = _receive_non_ping(ws)
        assert resp.get("type") == "error"
        assert resp.get("code") == "conflict"
        assert resp.get("id") == clip_id
        assert "conflict" in resp.get("message", "").lower()


# 18. Handshake rejection with code 1008 when mandatory JWT claims are missing.
def test_ws_auth_missing_required_token_claims(client):
    token = jwt.encode(
        {"sub": "test@synclo.app", "device_id": "dev-1", "exp": int(time.time()) + 300},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )

    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}
    ) as ws:
        msg = ws.receive_json()
        assert msg.get("type") == "error"
        assert "missing required fields" in msg.get("message", "")

        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_json()
        assert exc.value.code == 1008


# 19. WebSocket error response when received clipboard payload lacks required fields.
def test_ws_invalid_clipboard_payload_missing_fields(client, auth_user):
    token = auth_user["access_token"]
    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}
    ) as ws:
        ws.send_json({"type": "clipboard_sync"})
        msg = ws.receive_json()
        assert msg.get("type") == "error"
        assert "Missing required fields" in msg.get("message", "")


# 20. WebSocket error response when received clipboard payload has malformed schema fields.
def test_ws_invalid_clipboard_payload_schema_malformed(client, auth_user):
    token = auth_user["access_token"]
    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}
    ) as ws:
        ws.send_json(
            {
                "type": "clipboard_sync",
                "id": "clip-invalid-schema",
                "timestamp": "not-a-datetime",
                "ciphertext": "invalid base64 !!@#$",
            }
        )
        msg = ws.receive_json()
        assert msg.get("type") == "error"
        assert "Invalid payload:" in msg.get("message", "")


# 21. Device deletion during active WebSocket session terminates socket with code 4003 on next write.
def test_ws_device_deleted_mid_session(client, auth_user, db_session):
    token = auth_user["access_token"]
    device_id = auth_user["device_id"]

    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}
    ) as ws:
        ws.send_json({"type": "ping"})
        pong = ws.receive_json()
        assert pong.get("type") == "pong"

        def mutate():
            dev = db_session.scalars(
                select(Device).where(Device.device_id == device_id)
            ).first()
            if dev:
                db_session.execute(
                    delete(Device).where(Device.device_id == device_id)
                )

        run_in_write_transaction(db_session, mutate)

        ws.send_json(make_clipboard_payload("clip_after_device_delete"))

        del_msg = ws.receive_json()
        assert del_msg.get("type") == "device_deleted"
        assert "removed from your account" in del_msg.get("message", "")

        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_json()
        assert exc.value.code == 4003


# 22. Device deletion between handshake and initial clipboard write aborts session with code 4003.
def test_ws_device_deleted_between_auth_and_first_clipboard_write(client, auth_user, db_session):
    token = auth_user["access_token"]
    device_id = auth_user["device_id"]

    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}
    ) as ws:
        def mutate():
            db_session.execute(delete(Device).where(Device.device_id == device_id))

        run_in_write_transaction(db_session, mutate)

        ws.send_json(make_clipboard_payload("clip_initial_write_deleted_device"))

        del_msg = ws.receive_json()
        assert del_msg.get("type") == "device_deleted"
        assert "removed from your account" in del_msg.get("message", "")

        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_json()
        assert exc.value.code == 4003


# 23. Mid-session token expiration disconnects socket with code 4001 upon next frame.
def test_ws_token_expired_mid_session(client, auth_user):
    short_token = create_access_token(
        {
            "sub": auth_user["email"],
            "device_id": auth_user["device_id"],
            "epoch": 1,
        },
        expires_delta=timedelta(seconds=1),
    )

    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {short_token}"}
    ) as ws:
        time.sleep(1.5)

        ws.send_json({"type": "ping"})

        first_msg = ws.receive_json()
        if first_msg.get("type") == "pong":
            second_msg = ws.receive_json()
            assert second_msg.get("type") == "error"
            assert "Token expired" in second_msg.get("message", "")
        else:
            assert first_msg.get("type") == "error"
            assert "Token expired" in first_msg.get("message", "")

        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_json()
        assert exc.value.code == 4001
