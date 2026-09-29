from unittest.mock import patch
from fastapi import APIRouter, Depends
from starlette.testclient import TestClient

from app.core.limiter import create_limiter
from app.main import app


def test_rate_limiter_executes_on_included_router():
    router = APIRouter()

    @router.get("/rate-test-endpoint", dependencies=[Depends(create_limiter(times=2, seconds=60))])
    def sample_endpoint():
        return {"ok": True}

    app.include_router(router, prefix="/api/v1")
    try:
        with TestClient(app) as test_client:
            res1 = test_client.get("/api/v1/rate-test-endpoint")
            assert res1.status_code == 200
            assert res1.json() == {"ok": True}

            res2 = test_client.get("/api/v1/rate-test-endpoint")
            assert res2.status_code == 200

            res3 = test_client.get("/api/v1/rate-test-endpoint")
            assert res3.status_code == 429
            assert res3.json() == {"detail": "Too Many Requests"}
    finally:
        app.routes[:] = [
            r for r in app.routes if getattr(r, "path", None) != "/api/v1/rate-test-endpoint"
        ]


def test_rate_limiter_isolates_different_endpoints():
    router = APIRouter()

    @router.get("/rate-route-a", dependencies=[Depends(create_limiter(times=1, seconds=60))])
    def route_a():
        return {"route": "a"}

    @router.get("/rate-route-b", dependencies=[Depends(create_limiter(times=1, seconds=60))])
    def route_b():
        return {"route": "b"}

    app.include_router(router, prefix="/api/v1")
    try:
        with TestClient(app) as test_client:
            assert test_client.get("/api/v1/rate-route-a").status_code == 200
            assert test_client.get("/api/v1/rate-route-a").status_code == 429
            assert test_client.get("/api/v1/rate-route-b").status_code == 200
            assert test_client.get("/api/v1/rate-route-b").status_code == 429
    finally:
        app.routes[:] = [
            r
            for r in app.routes
            if getattr(r, "path", None) not in ("/api/v1/rate-route-a", "/api/v1/rate-route-b")
        ]


def test_rate_limiter_isolates_different_clients():
    router = APIRouter()

    @router.get("/rate-client-test", dependencies=[Depends(create_limiter(times=1, seconds=60))])
    def client_endpoint():
        return {"status": "ok"}

    app.include_router(router, prefix="/api/v1")
    try:
        with TestClient(app) as test_client:
            res1 = test_client.get(
                "/api/v1/rate-client-test", headers={"x-forwarded-for": "203.0.113.195"}
            )
            assert res1.status_code == 200

            res1_blocked = test_client.get(
                "/api/v1/rate-client-test", headers={"x-forwarded-for": "203.0.113.195"}
            )
            assert res1_blocked.status_code == 429

            res2 = test_client.get(
                "/api/v1/rate-client-test", headers={"x-forwarded-for": "198.51.100.42"}
            )
            assert res2.status_code == 200
    finally:
        app.routes[:] = [
            r for r in app.routes if getattr(r, "path", None) != "/api/v1/rate-client-test"
        ]


def test_rate_limiter_fails_open_on_storage_error():
    router = APIRouter()

    limiter_dep = create_limiter(times=1, seconds=60)

    @router.get("/rate-fail-open-test", dependencies=[Depends(limiter_dep)])
    def fail_open_endpoint():
        return {"status": "survived"}

    app.include_router(router, prefix="/api/v1")
    try:
        with patch.object(
            limiter_dep.limiter,
            "try_acquire_async",
            side_effect=RuntimeError("Redis connection dropped"),
        ):
            with TestClient(app) as test_client:
                res = test_client.get("/api/v1/rate-fail-open-test")
                assert res.status_code == 200
                assert res.json() == {"status": "survived"}
    finally:
        app.routes[:] = [
            r for r in app.routes if getattr(r, "path", None) != "/api/v1/rate-fail-open-test"
        ]
