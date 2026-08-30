# app/core/metrics.py

"""
Synclo Observability & Telemetry Subsystem.

Zero-Knowledge & Privacy Invariant:
- Absolutely NO user-identifying data (user IDs, usernames, emails, device IDs, IP addresses,
  tokens, push distributor URLs, or ciphertext payloads) is tracked or exposed in metrics.
- All metrics are strictly aggregated statistical counters, gauges, and histograms.
"""

from fastapi import FastAPI
from prometheus_client import Counter, Gauge, Histogram
from prometheus_fastapi_instrumentator import Instrumentator

# ---------------------------------------------------------
# Custom Zero-Knowledge Application Metrics
# ---------------------------------------------------------

# Gauge: Tracks the number of active local WebSocket client connections
ACTIVE_WEBSOCKETS = Gauge(
    "synclo_active_websockets",
    "Current number of active local WebSocket client connections on this server instance.",
)

# Counter: Tracks broadcasted WebSocket events categorized solely by generic event type
WEBSOCKET_EVENTS_TOTAL = Counter(
    "synclo_websocket_events_total",
    "Total WebSocket events broadcasted across the cluster, labeled only by event type.",
    ["event_type"],
)

# Counter: Tracks background push notification dispatch outcomes (UnifiedPush / Web Push)
PUSH_DISPATCHES_TOTAL = Counter(
    "synclo_push_dispatches_total",
    "Total background push notifications dispatched, labeled only by generic outcome status.",
    ["status"],
)

# Histogram: Tracks network latency of outbound push notification triggers
PUSH_DURATION_SECONDS = Histogram(
    "synclo_push_duration_seconds",
    "Latency of outbound push notification requests to distributor endpoints in seconds.",
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)


def setup_metrics(app: FastAPI) -> Instrumentator:
    """
    Initializes and attaches Prometheus instrumentation middleware to the FastAPI application,
    and exposes the standard `/metrics` scraping endpoint.
    """
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
