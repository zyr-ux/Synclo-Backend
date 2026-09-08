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
import contextlib
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from app.models.models import Device, User
from app.services.push_service import (
    EndpointValidationResult,
    EndpointValidationStatus,
    PushService,
    push_service,
    send_push_notification,
    dispatch_push_to_user_devices,
)
from tests.conftest import make_clipboard_payload


def test_register_push_subscription_success(client, auth_user, db_session):
    device_id = auth_user["device_id"]
    headers = auth_user["headers"]

    push_url = "https://ntfy.sh/up_synclo_test_device_1"
    res = client.put(
        f"/api/v1/devices/{device_id}/push", json={"push_subscription": push_url}, headers=headers
    )
    assert res.status_code == 200
    data = res.json()
    assert data["device_id"] == device_id
    assert data["push_enabled"] is True

    # The database stores an encrypted subscription, not the bearer URL.
    from app.models.models import Device
    from app.services.push_service import decrypt_push_subscription

    device = db_session.query(Device).filter_by(device_id=device_id).first()
    assert device.push_subscription != push_url
    assert decrypt_push_subscription(device.push_subscription) == push_url

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
        headers=headers,
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
        headers=headers,
    )
    assert res_bad.status_code == 422

    # Insecure scheme (ftp://)
    res_ftp = client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": "ftp://files.example.com/push"},
        headers=headers,
    )
    assert res_ftp.status_code == 422

    # Plain HTTP for remote non-localhost (when HTTPS_ONLY is True)
    monkeypatch.setattr(Settings, "HTTPS_ONLY", True)
    res_http_remote = client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": "http://external-push.example.com/endpoint"},
        headers=headers,
    )
    assert res_http_remote.status_code == 422

    # Plain HTTP on localhost / 127.0.0.1 is accepted even when HTTPS_ONLY is True
    res_http_local = client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": "http://localhost:8080/up_dev_test"},
        headers=headers,
    )
    assert res_http_local.status_code == 200
    assert res_http_local.json()["push_enabled"] is True

    # When HTTPS_ONLY is False, plain HTTP remote endpoints are accepted
    monkeypatch.setattr(Settings, "HTTPS_ONLY", False)
    res_http_remote_allowed = client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": "http://192.168.1.100:8080/up_lan_endpoint"},
        headers=headers,
    )
    assert res_http_remote_allowed.status_code == 200
    assert res_http_remote_allowed.json()["push_enabled"] is True


def test_cannot_modify_other_user_push_subscription(client, auth_user, user_factory):
    other_user = user_factory()
    res = client.put(
        f"/api/v1/devices/{other_user['device_id']}/push",
        json={"push_subscription": "https://ntfy.sh/up_other"},
        headers=auth_user["headers"],
    )
    assert res.status_code == 404

    res_del = client.delete(
        f"/api/v1/devices/{other_user['device_id']}/push", headers=auth_user["headers"]
    )
    assert res_del.status_code == 404


def mock_http_stream(status_code: int = 200, body: bytes = b""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.aclose = AsyncMock()

    async def aiter():
        yield body

    resp.aiter_bytes = aiter

    @contextlib.asynccontextmanager
    async def _stream(*args, **kwargs):
        yield resp

    return _stream, resp


@pytest.mark.asyncio
async def test_send_push_notification_success(mocker):
    mocker.patch(
        "app.services.push_service._validate_endpoint_and_resolve",
        new_callable=AsyncMock,
        return_value=EndpointValidationResult(
            EndpointValidationStatus.VALID, details=("ntfy.sh", "1.2.3.4", 443)
        ),
    )
    stream_mock, mock_resp = mock_http_stream(status_code=200)
    mock_stream = mocker.patch("httpx.AsyncClient.stream", side_effect=stream_mock)

    result = await send_push_notification("dev_123", "https://ntfy.sh/up_test", "user_123")
    assert result is True
    mock_stream.assert_called_once()
    args, kwargs = mock_stream.call_args
    assert args[0] == "POST"
    assert args[1] == "https://ntfy.sh/up_test"
    assert kwargs["json"] == {"type": "push"}
    assert "timestamp" not in kwargs["json"]


def test_empty_body_push_subscription_rejected(client, auth_user):
    device_id = auth_user["device_id"]
    headers = auth_user["headers"]

    # Empty payload {} should be rejected with 422
    res = client.put(f"/api/v1/devices/{device_id}/push", json={}, headers=headers)
    assert res.status_code == 422


@pytest.mark.parametrize("status_code", [400, 404, 410])
@pytest.mark.asyncio
async def test_send_push_notification_stale_self_healing(
    client, auth_user, db_session, mocker, status_code
):
    device_id = auth_user["device_id"]
    email = auth_user["email"]

    # Register push subscription
    client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": f"https://ntfy.sh/up_stale_{status_code}"},
        headers=auth_user["headers"],
    )

    user = db_session.query(User).filter_by(email=email).first()
    user_id = user.user_id

    # Mock distributor returning stale rejection status
    mocker.patch(
        "app.services.push_service._validate_endpoint_and_resolve",
        new_callable=AsyncMock,
        return_value=EndpointValidationResult(
            EndpointValidationStatus.VALID, details=("ntfy.sh", "1.2.3.4", 443)
        ),
    )
    stream_mock, _ = mock_http_stream(status_code=status_code)
    mocker.patch("httpx.AsyncClient.stream", side_effect=stream_mock)

    result = await send_push_notification(
        device_id, f"https://ntfy.sh/up_stale_{status_code}", user_id
    )
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
    mocker.patch(
        "app.services.push_service._validate_endpoint_and_resolve",
        new_callable=AsyncMock,
        return_value=EndpointValidationResult(
            EndpointValidationStatus.VALID, details=("ntfy.sh", "1.2.3.4", 443)
        ),
    )
    mocker.patch("httpx.AsyncClient.stream", side_effect=httpx.TimeoutException("Timeout"))

    result = await send_push_notification("dev_timeout", "https://ntfy.sh/up_slow", "user_123")
    assert result is False


@pytest.mark.asyncio
async def test_push_service_ssrf_and_stream_capping(mocker, monkeypatch):
    from app.core.config import Settings
    monkeypatch.setattr(Settings, "ENVIRONMENT", "production")
    from app.services.push_service import EndpointValidationStatus, _validate_endpoint_and_resolve

    # 1. Embedded credentials rejected
    assert (
        await _validate_endpoint_and_resolve("https://user:pass@ntfy.sh/push")
    ).status == EndpointValidationStatus.SSRF_BLOCKED

    # 2. Non-standard HTTPS port rejected
    assert (
        await _validate_endpoint_and_resolve("https://ntfy.sh:8443/push")
    ).status == EndpointValidationStatus.SSRF_BLOCKED

    # 3. Disallowed scheme (e.g. gopher://)
    assert (
        await _validate_endpoint_and_resolve("gopher://ntfy.sh/push")
    ).status == EndpointValidationStatus.SSRF_BLOCKED

    # 4. Resolved private / loopback / cloud metadata IP blocked
    import socket

    for blocked_ip in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "::1"):
        family = socket.AF_INET if ":" not in blocked_ip else socket.AF_INET6
        sockaddr = (blocked_ip, 443) if family == socket.AF_INET else (blocked_ip, 443, 0, 0)
        mocker.patch(
            "asyncio.BaseEventLoop.getaddrinfo",
            return_value=[(family, socket.SOCK_STREAM, 6, "", sockaddr)],
        )
        res = await _validate_endpoint_and_resolve("https://ntfy.sh/push")
        assert res.status == EndpointValidationStatus.SSRF_BLOCKED
        assert "private or non-global" in res.reason.lower()

    # 5. Stream body capping at 10 KB
    mocker.patch(
        "app.services.push_service._validate_endpoint_and_resolve",
        new_callable=AsyncMock,
        return_value=EndpointValidationResult(
            EndpointValidationStatus.VALID, details=("ntfy.sh", "1.2.3.4", 443)
        ),
    )
    oversized_body = b"X" * 20000  # 20 KB
    stream_mock, response = mock_http_stream(status_code=200, body=oversized_body)
    mocker.patch("httpx.AsyncClient.stream", side_effect=stream_mock)

    result = await send_push_notification("dev_capped", "https://ntfy.sh/up_capped", "user_123")
    assert result is False
    response.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_push_response_cap_aborts_an_oversized_chunk(mocker):
    mocker.patch(
        "app.services.push_service._validate_endpoint_and_resolve",
        new_callable=AsyncMock,
        return_value=EndpointValidationResult(
            EndpointValidationStatus.VALID, details=("ntfy.sh", "1.2.3.4", 443)
        ),
    )
    response = MagicMock()
    response.status_code = 200
    response.aclose = AsyncMock()
    chunks = [b"X" * 10_241, b"should-not-be-consumed"]

    async def aiter():
        while chunks:
            yield chunks.pop(0)

    response.aiter_bytes = aiter

    @contextlib.asynccontextmanager
    async def stream_mock(*args, **kwargs):
        yield response

    mocker.patch("httpx.AsyncClient.stream", side_effect=stream_mock)

    result = await send_push_notification(
        "dev_chunk_capped", "https://ntfy.sh/up_chunk", "user_123"
    )

    assert result is False
    assert chunks == [b"should-not-be-consumed"]
    response.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_pinned_transport_keeps_hostname_and_pins_tcp_destination():
    from app.services.push_service import PinnedAsyncTransport, PinnedNetworkBackend

    pinned = {"push.example.com": "203.0.113.10"}
    transport = PinnedAsyncTransport(pinned, trust_env=False)

    assert isinstance(transport.network_backend, PinnedNetworkBackend)
    assert transport.network_backend.pinned_ips is pinned
    assert transport.ssl_context.check_hostname is True
    assert transport.ssl_context.verify_mode != 0
    await transport.aclose()


@pytest.mark.asyncio
async def test_concurrent_push_ip_pinning_isolation(mocker):
    from app.services.push_service import PinnedNetworkBackend, _current_pinned_ips

    connected_ips = []
    backend = PinnedNetworkBackend(pinned_ips={})

    async def mock_super_connect(target_ip, port, **kwargs):
        # Simulate network latency to ensure tasks interleave
        await asyncio.sleep(0.02)
        connected_ips.append(target_ip)
        return MagicMock()

    mocker.patch("httpcore.AnyIOBackend.connect_tcp", side_effect=mock_super_connect)

    async def task_worker(ip: str):
        token = _current_pinned_ips.set({"ntfy.sh": ip})
        try:
            await backend.connect_tcp("ntfy.sh", 443)
        finally:
            _current_pinned_ips.reset(token)

    # Concurrently connect to the same hostname with different validated IPs
    await asyncio.gather(
        task_worker("198.51.100.1"),
        task_worker("198.51.100.2"),
    )

    assert len(connected_ips) == 2
    assert "198.51.100.1" in connected_ips
    assert "198.51.100.2" in connected_ips
    # Ensure context variable was reset
    assert _current_pinned_ips.get() == {}


@pytest.mark.asyncio
async def test_send_push_notification_context_lifecycle(mocker):
    import app.services.push_service as ps

    mocker.patch(
        "app.services.push_service._validate_endpoint_and_resolve",
        new_callable=AsyncMock,
        return_value=EndpointValidationResult(
            EndpointValidationStatus.VALID, details=("ntfy.sh", "198.51.100.99", 443)
        ),
    )

    observed_pin_during_call = None

    @contextlib.asynccontextmanager
    async def mock_stream(*args, **kwargs):
        nonlocal observed_pin_during_call
        observed_pin_during_call = ps._current_pinned_ips.get().copy()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.aclose = AsyncMock()

        async def aiter():
            yield b""

        mock_resp.aiter_bytes = aiter
        yield mock_resp

    mocker.patch("httpx.AsyncClient.stream", side_effect=mock_stream)

    result = await ps.send_push_notification("dev_test", "https://ntfy.sh/up_ctx", "user_1")
    assert result is True
    # The pin must have been active during the stream call
    assert observed_pin_during_call == {"ntfy.sh": "198.51.100.99"}
    # The pin must be reset after completion
    assert ps._current_pinned_ips.get() == {}


@pytest.mark.asyncio
async def test_dispatch_push_to_user_devices(client, user_factory, db_session, mocker):
    user = user_factory()
    user_record = db_session.query(User).filter_by(email=user["email"]).first()
    user_id = user_record.user_id

    # Register Device 2 and Device 3
    client.post(
        "/api/v1/devices/register",
        json={"device_id": "dev_phone", "device_name": "Phone"},
        headers=user["headers"],
    )
    client.post(
        "/api/v1/devices/register",
        json={"device_id": "dev_tablet", "device_name": "Tablet"},
        headers=user["headers"],
    )

    # Configure push on Device 1 and Device 2 (leave Device 3 without push)
    client.put(
        f"/api/v1/devices/{user['device_id']}/push",
        json={"push_subscription": "https://ntfy.sh/up_dev1"},
        headers=user["headers"],
    )
    client.put(
        "/api/v1/devices/dev_phone/push",
        json={"push_subscription": "https://ntfy.sh/up_dev2"},
        headers=user["headers"],
    )

    mock_send = mocker.patch.object(
        push_service, "send_push_notification", new_callable=AsyncMock, return_value=True
    )

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
    res = client.post(
        "/api/v1/clipboard", json=make_clipboard_payload(clip_id), headers=auth_user["headers"]
    )
    assert res.status_code == 200

    mock_launch.assert_called_once_with(user_id=user_id, exclude_device=auth_user["device_id"])


def test_websocket_sync_triggers_push_dispatch(client, auth_user, db_session, mocker):
    mock_launch = mocker.patch("app.endpoints.websocket_endpoints.launch_background_push")

    user = db_session.query(User).filter_by(email=auth_user["email"]).first()
    user_id = user.user_id

    token = auth_user["access_token"]
    with client.websocket_connect(
        "/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}
    ) as ws:
        clip_id = "ws_push_trigger_item"
        ws.send_json(make_clipboard_payload(clip_id))
        ack = ws.receive_json()
        assert ack.get("type") == "ack"

    mock_launch.assert_called_once_with(user_id=user_id, exclude_device=auth_user["device_id"])


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


@pytest.mark.asyncio
async def test_push_service_transient_dns_failure_does_not_prune(mocker, db_session, auth_user):
    import socket
    from app.services.push_service import encrypt_push_subscription, send_push_notification
    from app.models.models import Device

    device_id = auth_user["device_id"]
    user_id = auth_user["email"]

    device = db_session.query(Device).filter_by(device_id=device_id).first()
    assert device is not None
    device.push_subscription = encrypt_push_subscription("https://ntfy.sh/up_dns_test")
    db_session.commit()

    # Mock getaddrinfo to simulate temporary DNS failure
    mocker.patch(
        "asyncio.BaseEventLoop.getaddrinfo",
        side_effect=socket.gaierror(-3, "Temporary failure in name resolution"),
    )
    prune_spy = mocker.patch("app.services.push_service._prune_stale_endpoint")

    result = await send_push_notification(device_id, "https://ntfy.sh/up_dns_test", user_id)
    assert result is False

    # Ensure device push subscription was NOT pruned!
    prune_spy.assert_not_called()
    db_session.refresh(device)
    assert device.push_subscription is not None
