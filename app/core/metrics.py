from fastapi import FastAPI
from prometheus_client import Counter, Gauge, Histogram
from prometheus_fastapi_instrumentator import Instrumentator

ACTIVE_WEBSOCKETS = Gauge(
    "synclo_active_websockets",
    "Current number of active local WebSocket client connections on this server instance.",
)

WEBSOCKET_EVENTS_TOTAL = Counter(
    "synclo_websocket_events_total",
    "Total WebSocket events broadcasted, labeled only by event type.",
    ["event_type"],
)

WEBSOCKET_BROADCAST_FAILURES_TOTAL = Counter(
    "synclo_websocket_broadcast_failures_total",
    "Best-effort WebSocket publication failures.",
    ["operation"],
)

CLEANUP_FAILURES_TOTAL = Counter(
    "synclo_cleanup_failures_total",
    "Cleanup operation failures.",
    ["operation"],
)

PUSH_DISPATCHES_TOTAL = Counter(
    "synclo_push_dispatches_total",
    "Total background push notifications dispatched, labeled only by generic outcome status.",
    ["status"],
)

PUSH_DURATION_SECONDS = Histogram(
    "synclo_push_duration_seconds",
    "Latency of outbound push notification requests to distributor endpoints in seconds.",
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)


def setup_metrics(app: FastAPI) -> Instrumentator:
    instrumentator = Instrumentator(
        should_group_status_codes=False,
        should_ignore_untemplated=True,
        excluded_handlers=["/metrics", "/api/health"],
    )

    instrumentator.instrument(app)
    instrumentator.expose(
        app,
        endpoint="/metrics",
        include_in_schema=True,
        tags=["Telemetry"],
    )

    return instrumentator
