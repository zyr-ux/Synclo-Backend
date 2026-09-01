"""
Test Suite: Push Notification Service (UnifiedPush, PushSubscription, Self-Healing)

Scenarios Targeted:
1. Register push subscription on a device via 'PUT /api/v1/devices/{id}/push'.
2. Remove push subscription from a device via 'DELETE /api/v1/devices/{id}/push'.
3. Enforce URL scheme validation (rejecting non-HTTP/HTTPS and plain HTTP in production).
4. Rejection of empty body on push registration with 422.
5. Cross-tenant isolation (preventing modifying push subscriptions for another user's device).
6. Asynchronous HTTP push delivery with zero-knowledge trigger payload and connection pooling.
7. Automatic self-healing (nullifying push_subscription on 400, 404, or 410 distributor status).
8. Graceful timeout handling on unresponsive distributors.
9. Parallel multi-device push dispatch and exclusion of sending device.
10. Background task retention and trigger dispatch on REST write and WebSocket sync events.
11. PushService startup and shutdown lifecycle management.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock

import httpx
import pytest

from app.models.models import Device, User
from app.services.push_service import (
    PushService,
    push_service,
    send_push_notification,
    dispatch_push_to_user_devices,
    launch_background_push,
)
from tests.conftest import make_clipboard_payload


def test_register_push_subscription_success(client, auth_user):
    device_id = auth_user["device_id"]
    headers = auth_user["headers"]

    push_url = "https://ntfy.sh/up_synclo_test_device_1"
    res = client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": push_url},
        headers=headers
    )
    assert res.status_code == 200
    data = res.json()
    assert data["device_id"] == device_id
    assert data["push_enabled"] is True

    # Verify GET /api/v1/devices reflects push_enabled=True
    res_list = client.get("/api/v1/devices", headers=headers)
    assert res_list.status_code == 200
    devices = res_list.json()
    dev = next(d for d in devices if d["device_id"] == device_id)
    assert dev["push_enabled"] is True


def test_remove_push_subscription(client, auth_user):
    device_id = auth_user["device_id"]
    headers = auth_user["headers"]

    # Register first
    client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": "https://ntfy.sh/up_synclo_test_remove"},
        headers=headers
    )

    # Delete push subscription
    res_del = client.delete(f"/api/v1/devices/{device_id}/push", headers=headers)
    assert res_del.status_code == 200
    assert res_del.json()["push_enabled"] is False

    # Check device list
    res_list = client.get("/api/v1/devices", headers=headers)
    dev = next(d for d in res_list.json() if d["device_id"] == device_id)
    assert dev["push_enabled"] is False


def test_push_subscription_url_validation(client, auth_user, monkeypatch):
    from app.core.config import Settings
    device_id = auth_user["device_id"]
    headers = auth_user["headers"]

    # Invalid URL format
    res_bad = client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": "not-a-valid-url"},
        headers=headers
    )
    assert res_bad.status_code == 422

    # Insecure scheme (ftp://)
    res_ftp = client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": "ftp://files.example.com/push"},
        headers=headers
    )
    assert res_ftp.status_code == 422

    # Plain HTTP for remote non-localhost (when HTTPS_ONLY is True)
    monkeypatch.setattr(Settings, "HTTPS_ONLY", True)
    res_http_remote = client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": "http://external-push.example.com/endpoint"},
        headers=headers
    )
    assert res_http_remote.status_code == 422

    # Plain HTTP on localhost / 127.0.0.1 is accepted even when HTTPS_ONLY is True
    res_http_local = client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": "http://localhost:8080/up_dev_test"},
        headers=headers
    )
    assert res_http_local.status_code == 200
    assert res_http_local.json()["push_enabled"] is True

    # When HTTPS_ONLY is False, plain HTTP remote endpoints are accepted
    monkeypatch.setattr(Settings, "HTTPS_ONLY", False)
    res_http_remote_allowed = client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": "http://192.168.1.100:8080/up_lan_endpoint"},
        headers=headers
    )
    assert res_http_remote_allowed.status_code == 200
    assert res_http_remote_allowed.json()["push_enabled"] is True


def test_cannot_modify_other_user_push_subscription(client, auth_user, user_factory):
    other_user = user_factory()
    res = client.put(
        f"/api/v1/devices/{other_user['device_id']}/push",
        json={"push_subscription": "https://ntfy.sh/up_other"},
        headers=auth_user["headers"]
    )
    assert res.status_code == 404

    res_del = client.delete(
        f"/api/v1/devices/{other_user['device_id']}/push",
        headers=auth_user["headers"]
    )
    assert res_del.status_code == 404


@pytest.mark.asyncio
async def test_send_push_notification_success(mocker):
    mock_response = MagicMock(status_code=200)
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response)

    result = await send_push_notification("dev_123", "https://ntfy.sh/up_test", "user_123")
    assert result is True
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == "https://ntfy.sh/up_test"
    assert kwargs["json"]["type"] == "push"
    assert "timestamp" in kwargs["json"]


def test_empty_body_push_subscription_rejected(client, auth_user):
    device_id = auth_user["device_id"]
    headers = auth_user["headers"]

    # Empty payload {} should be rejected with 422
    res = client.put(
        f"/api/v1/devices/{device_id}/push",
        json={},
        headers=headers
    )
    assert res.status_code == 422


@pytest.mark.parametrize("status_code", [400, 404, 410])
@pytest.mark.asyncio
async def test_send_push_notification_stale_self_healing(client, auth_user, db_session, mocker, status_code):
    device_id = auth_user["device_id"]
    email = auth_user["email"]

    # Register push subscription
    client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": f"https://ntfy.sh/up_stale_{status_code}"},
        headers=auth_user["headers"]
    )

    user = db_session.query(User).filter_by(email=email).first()
    user_id = user.user_id

    # Mock distributor returning stale rejection status
    mock_response = MagicMock(status_code=status_code)
    mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response)

    result = await send_push_notification(device_id, f"https://ntfy.sh/up_stale_{status_code}", user_id)
    assert result is False

    # Check that the device's push_subscription was pruned (self-healed) in DB
    db_session.expire_all()
    device = db_session.query(Device).filter_by(device_id=device_id).first()
    assert device.push_subscription is None

    # Also verify via public API GET /api/v1/devices
    res_list = client.get("/api/v1/devices", headers=auth_user["headers"])
    assert res_list.status_code == 200
    devices = res_list.json()
    matched_dev = next(d for d in devices if d["device_id"] == device_id)
    assert matched_dev["push_enabled"] is False


@pytest.mark.asyncio
async def test_send_push_notification_timeout_handling(mocker):
    mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=httpx.TimeoutException("Timeout"))

    result = await send_push_notification("dev_timeout", "https://ntfy.sh/up_slow", "user_123")
    assert result is False


@pytest.mark.asyncio
async def test_dispatch_push_to_user_devices(client, user_factory, db_session, mocker):
    user = user_factory()
    user_record = db_session.query(User).filter_by(email=user["email"]).first()
    user_id = user_record.user_id

    # Register Device 2 and Device 3
    client.post("/api/v1/devices/register", json={"device_id": "dev_phone", "device_name": "Phone"}, headers=user["headers"])
    client.post("/api/v1/devices/register", json={"device_id": "dev_tablet", "device_name": "Tablet"}, headers=user["headers"])

    # Configure push on Device 1 and Device 2 (leave Device 3 without push)
    client.put(f"/api/v1/devices/{user['device_id']}/push", json={"push_subscription": "https://ntfy.sh/up_dev1"}, headers=user["headers"])
    client.put("/api/v1/devices/dev_phone/push", json={"push_subscription": "https://ntfy.sh/up_dev2"}, headers=user["headers"])

    mock_send = mocker.patch.object(push_service, "send_push_notification", new_callable=AsyncMock, return_value=True)

    # Dispatch excluding Device 1 (the sender)
    await dispatch_push_to_user_devices(user_id=user_id, exclude_device=user["device_id"])

    # Should only dispatch to dev_phone
    assert mock_send.call_count == 1
    called_device_id = mock_send.call_args[0][0]
    assert called_device_id == "dev_phone"


def test_clipboard_write_triggers_push_dispatch(client, auth_user, db_session, mocker):
    mock_launch = mocker.patch("app.endpoints.clipboard_endpoints.launch_background_push")

    user = db_session.query(User).filter_by(email=auth_user["email"]).first()
    user_id = user.user_id

    clip_id = "test_clip_push_trigger"
    res = client.post("/api/v1/clipboard", json=make_clipboard_payload(clip_id), headers=auth_user["headers"])
    assert res.status_code == 200

    mock_launch.assert_called_once_with(
        user_id=user_id,
        exclude_device=auth_user["device_id"]
    )


def test_websocket_sync_triggers_push_dispatch(client, auth_user, db_session, mocker):
    mock_launch = mocker.patch("app.endpoints.websocket_endpoints.launch_background_push")

    user = db_session.query(User).filter_by(email=auth_user["email"]).first()
    user_id = user.user_id

    token = auth_user["access_token"]
    with client.websocket_connect("/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}) as ws:
        clip_id = "ws_push_trigger_item"
        ws.send_json(make_clipboard_payload(clip_id))
        ack = ws.receive_json()
        assert ack.get("type") == "ack"

    mock_launch.assert_called_once_with(
        user_id=user_id,
        exclude_device=auth_user["device_id"]
    )


@pytest.mark.asyncio
async def test_push_service_lifecycle_and_background_retention(mocker):
    svc = PushService(timeout=2.0)
    assert svc._client is None

    await svc.start()
    assert svc._client is not None
    assert not svc._client.is_closed

    # Test background task retention
    mocker.patch.object(svc, "dispatch_push_to_user_devices", new_callable=AsyncMock)
    task = svc.launch_background_push("user_test", "dev_sender")
    assert task in svc._background_tasks

    await task
    assert task not in svc._background_tasks

    await svc.stop()
    assert svc._client is None
