# Test Suite: Push Notification Service (UnifiedPush, PushSubscription, Self-Healing)

import asyncio
import contextlib
import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from sqlalchemy import select

from app.database.models import Device, User
from app.services.push_service import (
    EndpointValidationResult,
    EndpointValidationStatus,
    PushService,
    push_service,
    send_push_notification,
    dispatch_push_to_user_devices,
)
from tests.conftest import make_clipboard_payload


# 1. Register encrypted push subscription on a device via 'PUT /api/v1/devices/{id}/push'.
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

    from app.database.models import Device
    from app.services.push_service import decrypt_push_subscription

    device = db_session.scalars(select(Device).where(Device.device_id == device_id)).first()
    assert device.push_subscription != push_url
    assert decrypt_push_subscription(device.push_subscription) == push_url

    res_list = client.get("/api/v1/devices", headers=headers)
    assert res_list.status_code == 200
    devices = res_list.json()
    dev = next(d for d in devices if d["device_id"] == device_id)
    assert dev["push_enabled"] is True


# 2. Remove push subscription from a device via 'DELETE /api/v1/devices/{id}/push'.
def test_remove_push_subscription(client, auth_user):
    device_id = auth_user["device_id"]
    headers = auth_user["headers"]

    client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": "https://ntfy.sh/up_synclo_test_remove"},
        headers=headers,
    )

    res_del = client.delete(f"/api/v1/devices/{device_id}/push", headers=headers)
    assert res_del.status_code == 200
    assert res_del.json()["push_enabled"] is False

    res_list = client.get("/api/v1/devices", headers=headers)
    dev = next(d for d in res_list.json() if d["device_id"] == device_id)
    assert dev["push_enabled"] is False


# 3. Push subscription endpoint validates URL schemes and respects HTTPS_ONLY mode.
def test_push_subscription_url_validation(client, auth_user, monkeypatch):
    from app.core.config import Settings

    device_id = auth_user["device_id"]
    headers = auth_user["headers"]

    res_bad = client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": "not-a-valid-url"},
        headers=headers,
    )
    assert res_bad.status_code == 422

    res_ftp = client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": "ftp://files.example.com/push"},
        headers=headers,
    )
    assert res_ftp.status_code == 422

    monkeypatch.setattr(Settings, "HTTPS_ONLY", True)
    res_http_remote = client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": "http://external-push.example.com/endpoint"},
        headers=headers,
    )
    assert res_http_remote.status_code == 422

    res_http_local = client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": "http://localhost:8080/up_dev_test"},
        headers=headers,
    )
    assert res_http_local.status_code == 200
    assert res_http_local.json()["push_enabled"] is True

    monkeypatch.setattr(Settings, "HTTPS_ONLY", False)
    res_http_remote_allowed = client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": "http://192.168.1.100:8080/up_lan_endpoint"},
        headers=headers,
    )
    assert res_http_remote_allowed.status_code == 200
    assert res_http_remote_allowed.json()["push_enabled"] is True


# 4. Cross-tenant isolation preventing modifying push subscriptions for another user's device (404).
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


# 5. Asynchronous HTTP push delivery with zero-knowledge trigger payload and connection pooling.
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


# 6. Push subscription registration rejects empty JSON payload body (422).
def test_empty_body_push_subscription_rejected(client, auth_user):
    device_id = auth_user["device_id"]
    headers = auth_user["headers"]

    res = client.put(f"/api/v1/devices/{device_id}/push", json={}, headers=headers)
    assert res.status_code == 422


# 7. Automatic self-healing nullifies push subscription in database on 400, 404, or 410 distributor status.
@pytest.mark.parametrize("status_code", [400, 404, 410])
@pytest.mark.asyncio
async def test_send_push_notification_stale_self_healing(
    client, auth_user, db_session, mocker, status_code
):
    device_id = auth_user["device_id"]
    email = auth_user["email"]

    client.put(
        f"/api/v1/devices/{device_id}/push",
        json={"push_subscription": f"https://ntfy.sh/up_stale_{status_code}"},
        headers=auth_user["headers"],
    )

    user = db_session.scalars(select(User).where(User.email == email)).first()
    user_id = user.user_id

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

    db_session.expire_all()
    device = db_session.scalars(select(Device).where(Device.device_id == device_id)).first()
    assert device.push_subscription is None

    res_list = client.get("/api/v1/devices", headers=auth_user["headers"])
    assert res_list.status_code == 200
    devices = res_list.json()
    matched_dev = next(d for d in devices if d["device_id"] == device_id)
    assert matched_dev["push_enabled"] is False


# 8. Graceful timeout handling on unresponsive push distributors returning False without crashing.
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


# 9. Push service SSRF defenses block embedded credentials, non-standard ports, private IPs, and cap streams.
@pytest.mark.asyncio
async def test_push_service_ssrf_and_stream_capping(mocker, monkeypatch):
    from app.core.config import Settings
    monkeypatch.setattr(Settings, "ENVIRONMENT", "production")
    from app.services.push_service import EndpointValidationStatus, _validate_endpoint_and_resolve

    assert (
        await _validate_endpoint_and_resolve("https://user:pass@ntfy.sh/push")
    ).status == EndpointValidationStatus.SSRF_BLOCKED

    assert (
        await _validate_endpoint_and_resolve("https://ntfy.sh:8443/push")
    ).status == EndpointValidationStatus.SSRF_BLOCKED

    assert (
        await _validate_endpoint_and_resolve("gopher://ntfy.sh/push")
    ).status == EndpointValidationStatus.SSRF_BLOCKED

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

    mocker.patch(
        "app.services.push_service._validate_endpoint_and_resolve",
        new_callable=AsyncMock,
        return_value=EndpointValidationResult(
            EndpointValidationStatus.VALID, details=("ntfy.sh", "1.2.3.4", 443)
        ),
    )
    oversized_body = b"X" * 20000
    stream_mock, response = mock_http_stream(status_code=200, body=oversized_body)
    mocker.patch("httpx.AsyncClient.stream", side_effect=stream_mock)

    result = await send_push_notification("dev_capped", "https://ntfy.sh/up_capped", "user_123")
    assert result is False
    response.aclose.assert_awaited_once()


# 10. Streaming response body aborts connection immediately when chunk exceeds size cap.
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


# 11. Custom transport validates SNI hostname while pinning destination TCP socket connection.
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


# 12. ContextVar IP pinning isolates concurrent outbound requests to different destination IPs.
@pytest.mark.asyncio
async def test_concurrent_push_ip_pinning_isolation(mocker):
    from app.services.push_service import PinnedNetworkBackend, _current_pinned_ips

    connected_ips = []
    backend = PinnedNetworkBackend(pinned_ips={})

    async def mock_super_connect(target_ip, port, **kwargs):
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

    await asyncio.gather(
        task_worker("198.51.100.1"),
        task_worker("198.51.100.2"),
    )

    assert len(connected_ips) == 2
    assert "198.51.100.1" in connected_ips
    assert "198.51.100.2" in connected_ips
    assert _current_pinned_ips.get() == {}


# 13. IP pin context lifecycle sets pinned destination during stream and cleans up afterwards.
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
    assert observed_pin_during_call == {"ntfy.sh": "198.51.100.99"}
    assert ps._current_pinned_ips.get() == {}


# 14. Multi-device push dispatch sends notifications to all subscribed devices except origin device.
@pytest.mark.asyncio
async def test_dispatch_push_to_user_devices(client, user_factory, db_session, mocker):
    user = user_factory()
    user_record = db_session.scalars(select(User).where(User.email == user["email"])).first()
    user_id = user_record.user_id

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

    await dispatch_push_to_user_devices(user_id=user_id, exclude_device=user["device_id"])

    assert mock_send.call_count == 1
    called_device_id = mock_send.call_args[0][0]
    assert called_device_id == "dev_phone"


# 15. REST clipboard write triggers background push notification dispatch to user devices.
def test_clipboard_write_triggers_push_dispatch(client, auth_user, db_session, mocker):
    mock_launch = mocker.patch("app.endpoints.clipboard_endpoints.launch_background_push")

    user = db_session.scalars(select(User).where(User.email == auth_user["email"])).first()
    user_id = user.user_id

    clip_id = "test_clip_push_trigger"
    res = client.post(
        "/api/v1/clipboard", json=make_clipboard_payload(clip_id), headers=auth_user["headers"]
    )
    assert res.status_code == 200

    mock_launch.assert_called_once_with(user_id=user_id, exclude_device=auth_user["device_id"])


# 16. WebSocket clipboard sync event triggers background push notification dispatch to other devices.
def test_websocket_sync_triggers_push_dispatch(client, auth_user, db_session, mocker):
    mock_launch = mocker.patch("app.websockets.websocket_endpoints.launch_background_push")

    user = db_session.scalars(select(User).where(User.email == auth_user["email"])).first()
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


# 17. PushService start/stop lifecycle manages HTTP client and retains active background tasks.
@pytest.mark.asyncio
async def test_push_service_lifecycle_and_background_retention(mocker):
    svc = PushService(timeout=2.0)
    assert svc._client is None

    await svc.start()
    assert svc._client is not None
    assert not svc._client.is_closed

    mocker.patch.object(svc, "dispatch_push_to_user_devices", new_callable=AsyncMock)
    task = svc.launch_background_push("user_test", "dev_sender")
    assert task in svc._background_tasks

    await task
    assert task not in svc._background_tasks

    await svc.stop()
    assert svc._client is None


# 18. Transient DNS resolution failure preserves push subscription without false self-healing pruning.
@pytest.mark.asyncio
async def test_push_service_transient_dns_failure_does_not_prune(mocker, db_session, auth_user):
    import socket
    from app.services.push_service import encrypt_push_subscription, send_push_notification
    from app.database.models import Device

    device_id = auth_user["device_id"]
    user_id = auth_user["email"]

    device = db_session.scalars(select(Device).where(Device.device_id == device_id)).first()
    assert device is not None
    device.push_subscription = encrypt_push_subscription("https://ntfy.sh/up_dns_test")
    db_session.commit()

    mocker.patch(
        "asyncio.BaseEventLoop.getaddrinfo",
        side_effect=socket.gaierror(-3, "Temporary failure in name resolution"),
    )
    prune_spy = mocker.patch("app.services.push_service._prune_stale_endpoint")

    result = await send_push_notification(device_id, "https://ntfy.sh/up_dns_test", user_id)
    assert result is False

    prune_spy.assert_not_called()
    db_session.refresh(device)
    assert device.push_subscription is not None


# 19. Provider configuration loading parses domains and fails fast on invalid files.
def test_load_allowed_push_domains_success_and_fail_fast(tmp_path):
    from app.core.config import _load_allowed_push_domains

    valid_file = tmp_path / "valid.json"
    valid_file.write_text(
        json.dumps({"allowed_domains": ["ntfy.sh"], "providers": [{"domain": "up.kde.org"}]}),
        encoding="utf-8",
    )
    loaded = _load_allowed_push_domains(valid_file)
    assert loaded == {"ntfy.sh", "up.kde.org"}

    missing_file = tmp_path / "nonexistent.json"
    with pytest.raises(RuntimeError, match="Push providers configuration file not found"):
        _load_allowed_push_domains(missing_file)

    empty_file = tmp_path / "empty.json"
    empty_file.write_text(json.dumps({"allowed_domains": [], "providers": []}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="No allowed push domains configured"):
        _load_allowed_push_domains(empty_file)

    corrupt_file = tmp_path / "corrupt.json"
    corrupt_file.write_text("{invalid json", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Failed to load push providers"):
        _load_allowed_push_domains(corrupt_file)


# 20. Target endpoint resolver decrypts valid push subscriptions and filters out excluded devices.
def test_get_target_push_endpoints_decrypts_and_filters_correctly(db_session, user_factory):
    from app.services.push_service import (
        _get_target_push_endpoints,
        encrypt_push_subscription,
    )

    user_info = user_factory()
    user = db_session.scalars(select(User).where(User.email == user_info["email"])).first()
    assert user is not None
    user_id = user.user_id

    dev1 = Device(
        user_id=user_id,
        device_id="push_target_dev_1",
        device_name="Device 1",
        push_subscription=encrypt_push_subscription("https://ntfy.sh/valid_target_1"),
    )
    dev2 = Device(
        user_id=user_id,
        device_id="push_target_dev_2",
        device_name="Device 2",
        push_subscription=None,
    )
    dev3 = Device(
        user_id=user_id,
        device_id="push_target_dev_3",
        device_name="Device 3",
        push_subscription="v1:corrupt_base64!@@#",
    )
    dev4 = Device(
        user_id=user_id,
        device_id="push_target_dev_4",
        device_name="Device 4",
        push_subscription=encrypt_push_subscription("https://ntfy.sh/valid_target_4"),
    )
    db_session.add_all([dev1, dev2, dev3, dev4])
    db_session.commit()

    targets = _get_target_push_endpoints(user_id, exclude_device="push_target_dev_4")
    assert len(targets) == 1
    assert targets[0] == ("push_target_dev_1", "https://ntfy.sh/valid_target_1")


# 21. Database helper nullifies push subscription and records updated timestamp upon pruning.
def test_prune_stale_endpoint_nullifies_push_subscription(db_session, user_factory):
    from app.services.push_service import (
        _prune_stale_endpoint,
        encrypt_push_subscription,
    )

    user_info = user_factory()
    user = db_session.scalars(select(User).where(User.email == user_info["email"])).first()
    assert user is not None
    user_id = user.user_id

    dev = Device(
        user_id=user_id,
        device_id="prune_test_dev",
        device_name="Prune Device",
        push_subscription=encrypt_push_subscription("https://ntfy.sh/to_be_pruned"),
        push_subscription_updated_at=None,
    )
    db_session.add(dev)
    db_session.commit()

    _prune_stale_endpoint(user_id, "prune_test_dev")

    db_session.expire_all()
    updated_dev = db_session.scalars(
        select(Device).where(Device.user_id == user_id, Device.device_id == "prune_test_dev")
    ).first()
    assert updated_dev is not None
    assert updated_dev.push_subscription is None
    assert updated_dev.push_subscription_updated_at is not None
