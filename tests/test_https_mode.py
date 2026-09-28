# Test Suite: HTTPS Mode & Transport Security (HTTPS_ONLY)

import pytest
from starlette.websockets import WebSocketDisconnect
from app.core.config import Settings


# 1. Ingress HTTP request redirects (307) to HTTPS when HTTPS_ONLY=True and not on loopback.
def test_https_only_redirects_insecure_remote_http_requests(client, monkeypatch):
    monkeypatch.setattr(Settings, "HTTPS_ONLY", True)

    response = client.get("http://api.synclo.com/api/health", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["Location"] == "https://api.synclo.com/api/health"


# 2. Ingress HTTP request with 'X-Forwarded-Proto: https' succeeds and attaches HSTS header.
def test_https_only_accepts_reverse_proxied_https_requests(client, monkeypatch):
    monkeypatch.setattr(Settings, "HTTPS_ONLY", True)

    response = client.get(
        "http://api.synclo.com/api/health", headers={"x-forwarded-proto": "https"}
    )
    assert response.status_code == 200
    assert "Strict-Transport-Security" in response.headers
    assert "max-age=31536000" in response.headers["Strict-Transport-Security"]


# 3. Ingress HTTP request from untrusted proxy with forwarded proto is ignored and redirected.
def test_https_only_rejects_forwarded_proto_from_untrusted_proxy(client, monkeypatch):
    import app.main as app_main

    monkeypatch.setattr(Settings, "HTTPS_ONLY", True)
    monkeypatch.setattr(app_main, "is_trusted_proxy", lambda ip: False)

    response = client.get(
        "http://api.synclo.com/api/health",
        headers={"x-forwarded-proto": "https"},
        follow_redirects=False,
    )
    assert response.status_code == 307
    assert response.headers["Location"] == "https://api.synclo.com/api/health"


# 4. Loopback / local development traffic over plain HTTP succeeds and omits HSTS header.
def test_https_only_allows_loopback_without_hsts_on_plain_http(client, monkeypatch):
    monkeypatch.setattr(Settings, "HTTPS_ONLY", True)

    response = client.get("/api/health")
    assert response.status_code == 200
    assert "Strict-Transport-Security" not in response.headers


# 5. When HTTPS_ONLY=False, non-HTTPS traffic is accepted without redirect and HSTS header is omitted.
def test_https_disabled_allows_insecure_http_and_omits_hsts(client, monkeypatch):
    monkeypatch.setattr(Settings, "HTTPS_ONLY", False)

    response = client.get("http://192.168.1.50:8000/api/health", follow_redirects=False)
    assert response.status_code == 200
    assert "Strict-Transport-Security" not in response.headers


# 6. Insecure WebSocket connection is rejected (close code 1008) when HTTPS_ONLY=True and non-loopback.
def test_websocket_insecure_rejected_when_https_only(client, monkeypatch, auth_user):
    monkeypatch.setattr(Settings, "HTTPS_ONLY", True)
    token = auth_user["access_token"]

    with client.websocket_connect(
        "ws://remote.synclo.com/ws/v1/sync", headers={"Authorization": f"Bearer {token}"}
    ) as websocket:
        data = websocket.receive_json()
        assert data["type"] == "error"
        assert "WSS required" in data["message"]

        with pytest.raises(WebSocketDisconnect) as exc_info:
            websocket.receive_json()
        assert exc_info.value.code == 1008


# 7. Reverse-proxied WebSocket connection with X-Forwarded-Proto: https succeeds when HTTPS_ONLY=True.
def test_websocket_reverse_proxied_https_accepted(client, monkeypatch, auth_user):
    monkeypatch.setattr(Settings, "HTTPS_ONLY", True)
    token = auth_user["access_token"]

    with client.websocket_connect(
        "ws://remote.synclo.com/ws/v1/sync",
        headers={
            "Authorization": f"Bearer {token}",
            "x-forwarded-proto": "https",
        },
    ) as websocket:
        websocket.send_json({"type": "ping"})
        msg = websocket.receive_json()
        assert msg.get("type") in ("sync_history", "pong")


# 8. is_trusted_proxy correctly identifies loopback and private/Docker subnets vs public IPs.
def test_is_trusted_proxy_recognition():
    from app.core.constants import is_trusted_proxy

    # Loopback
    assert is_trusted_proxy("127.0.0.1") is True
    assert is_trusted_proxy("::1") is True
    assert is_trusted_proxy("localhost") is True
    assert is_trusted_proxy("testserver") is True

    # Private / Docker bridge networks
    assert is_trusted_proxy("172.18.0.1") is True
    assert is_trusted_proxy("172.17.0.1") is True
    assert is_trusted_proxy("10.0.0.1") is True
    assert is_trusted_proxy("192.168.1.1") is True

    # Public / untrusted
    assert is_trusted_proxy("1.1.1.1") is False
    assert is_trusted_proxy("8.8.8.8") is False
    assert is_trusted_proxy("93.184.216.34") is False
    assert is_trusted_proxy("") is False
    assert is_trusted_proxy("invalid-ip") is False


# 9. Global security headers (nosniff, DENY, referrer-policy) are attached to all HTTP responses.
def test_global_security_headers_present_on_all_http_responses(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert response.headers.get("X-XSS-Protection") == "0"
