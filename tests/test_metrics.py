"""
Test Suite: Telemetry & Prometheus Metrics (/metrics)

Scenarios Targeted:
1. Endpoint accessibility and standard Prometheus/OpenMetrics exposition output format via 'GET /metrics'.
2. Automatic HTTP request latency and throughput instrumentation across endpoints.
3. Real-time active WebSocket client connections gauge tracking on connect and disconnect.
4. Broadcast WebSocket event counter tracking categorized by generic event type.
5. Push notification delivery latency histogram and outcome counter tracking.
6. Zero-Knowledge and anonymity invariant verification (ensuring zero PII, user IDs, or tokens leak).
"""

from unittest.mock import AsyncMock, patch
import httpx
import pytest

from app.websockets.connection_manager import manager
from app.services.push_service import push_service


def test_metrics_endpoint_accessible(client):
    response = client.get("/metrics")
    assert response.status_code == 200

    content_type = response.headers.get("content-type", "")
    assert "text/plain" in content_type or "openmetrics" in content_type
    assert "synclo_active_websockets" in response.text
    assert "synclo_push_dispatches_total" in response.text
    assert "synclo_websocket_events_total" in response.text
    assert "synclo_push_duration_seconds" in response.text


def test_http_request_metrics_recorded(client):
    client.get("/api/health")
    client.get("/api/v1/salt/test@example.com")

    metrics_res = client.get("/metrics")
    assert metrics_res.status_code == 200
    assert (
        "http_requests_total" in metrics_res.text
        or "http_request_duration_seconds" in metrics_res.text
    )


@pytest.mark.asyncio
async def test_websocket_active_connections_and_event_metrics():
    from app.core.metrics import ACTIVE_WEBSOCKETS, WEBSOCKET_EVENTS_TOTAL

    ws_gauge_before = ACTIVE_WEBSOCKETS._value.get()
    events_counter_before = WEBSOCKET_EVENTS_TOTAL.labels(event_type="clipboard_sync")._value.get()

    user_id = "test-user-metrics-1"
    device_id = "device-metrics-1"
    mock_ws = AsyncMock()

    await manager.connect(user_id, device_id, mock_ws)
    assert manager.active_connections[user_id][device_id] == mock_ws
    assert ACTIVE_WEBSOCKETS._value.get() == ws_gauge_before + 1

    await manager.broadcast_to_user(user_id, {"type": "clipboard_sync", "id": "test-sync-1"})
    assert (
        WEBSOCKET_EVENTS_TOTAL.labels(event_type="clipboard_sync")._value.get()
        == events_counter_before + 1
    )

    manager.disconnect(user_id, device_id)
    assert user_id not in manager.active_connections
    assert ACTIVE_WEBSOCKETS._value.get() == ws_gauge_before


@pytest.mark.asyncio
async def test_push_service_metrics_recording():
    import contextlib
    from unittest.mock import MagicMock
    from app.core.metrics import PUSH_DISPATCHES_TOTAL

    # Sample baseline metrics
    success_before = PUSH_DISPATCHES_TOTAL.labels(status="success")._value.get()
    timeout_before = PUSH_DISPATCHES_TOTAL.labels(status="timeout")._value.get()

    @contextlib.asynccontextmanager
    async def mock_stream(*args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200

        async def aiter():
            yield b""

        resp.aiter_bytes = aiter
        yield resp

    from app.services.push_service import EndpointValidationResult, EndpointValidationStatus

    with patch(
        "app.services.push_service._validate_endpoint_and_resolve",
        new_callable=AsyncMock,
        return_value=EndpointValidationResult(
            EndpointValidationStatus.VALID, details=("push.example.com", "1.2.3.4", 443)
        ),
    ):
        with patch.object(httpx.AsyncClient, "stream", side_effect=mock_stream):
            success = await push_service.send_push_notification(
                device_id="dev-push-1",
                endpoint="https://push.example.com/endpoint",
                user_id="user-push-1",
            )
            assert success is True

        success_after = PUSH_DISPATCHES_TOTAL.labels(status="success")._value.get()
        assert success_after == success_before + 1

        with patch.object(
            httpx.AsyncClient, "stream", side_effect=httpx.TimeoutException("Timeout")
        ):
            success = await push_service.send_push_notification(
                device_id="dev-push-2",
                endpoint="https://push.example.com/timeout",
                user_id="user-push-2",
            )
            assert success is False

        timeout_after = PUSH_DISPATCHES_TOTAL.labels(status="timeout")._value.get()
        assert timeout_after == timeout_before + 1


def test_zero_knowledge_anonymity_in_metrics(client, user_factory):
    secret_email = "supersecret_privacy_test@example.com"
    user_factory(email=secret_email)

    metrics_res = client.get("/metrics")
    assert metrics_res.status_code == 200
    assert secret_email not in metrics_res.text
