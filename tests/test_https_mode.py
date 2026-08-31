"""
Test Suite: HTTPS Mode & Transport Security (HTTPS_ONLY)

Scenarios Targeted:
1. Ingress HTTP request redirects (307) to HTTPS when HTTPS_ONLY=True and not on loopback.
2. Ingress HTTP request with 'X-Forwarded-Proto: https' (reverse proxy TLS termination) succeeds and attaches HSTS header.
3. Loopback / local development traffic succeeds and includes HSTS header when HTTPS_ONLY=True.
4. When HTTPS_ONLY=False, non-HTTPS traffic is accepted without redirect and HSTS header is omitted.
5. Insecure WebSocket connection is rejected (close code 1008) when HTTPS_ONLY=True and non-loopback.
"""

import pytest
from app.core.config import Settings


def test_https_only_redirects_insecure_remote_http_requests(client, monkeypatch):
    monkeypatch.setattr(Settings, "HTTPS_ONLY", True)
    
    response = client.get("http://api.synclo.com/api/health", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["Location"] == "https://api.synclo.com/api/health"


def test_https_only_accepts_reverse_proxied_https_requests(client, monkeypatch):
    monkeypatch.setattr(Settings, "HTTPS_ONLY", True)
    
    response = client.get("http://api.synclo.com/api/health", headers={"x-forwarded-proto": "https"})
    assert response.status_code == 200
    assert "Strict-Transport-Security" in response.headers
    assert "max-age=31536000" in response.headers["Strict-Transport-Security"]


def test_https_only_allows_loopback_and_attaches_hsts(client, monkeypatch):
    monkeypatch.setattr(Settings, "HTTPS_ONLY", True)
    
    response = client.get("/api/health")
    assert response.status_code == 200
    assert "Strict-Transport-Security" in response.headers


def test_https_disabled_allows_insecure_http_and_omits_hsts(client, monkeypatch):
    monkeypatch.setattr(Settings, "HTTPS_ONLY", False)
    
    response = client.get("http://192.168.1.50:8000/api/health", follow_redirects=False)
    assert response.status_code == 200
    assert "Strict-Transport-Security" not in response.headers


def test_websocket_insecure_rejected_when_https_only(client, monkeypatch, auth_user):
    monkeypatch.setattr(Settings, "HTTPS_ONLY", True)
    token = auth_user["access_token"]

    # When connecting from a remote non-loopback host over plain ws without x-forwarded-proto
    with client.websocket_connect(
        "ws://remote.synclo.com/ws/v1/sync",
        headers={"Authorization": f"Bearer {token}"}
    ) as websocket:
        data = websocket.receive_json()
        assert data["type"] == "error"
        assert "WSS required" in data["message"]

