import asyncio
import sys
import traceback
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi_limiter import FastAPILimiter
from redis.asyncio import Redis

from app.database.engine import SessionLocal
from app.core.logging_config import logger
from app.core.config import Settings
from app.core.constants import LOOPBACK_HOSTS
from app.core.metrics import setup_metrics
from app.utilities.helpers import CleanupResult, run_all_cleanup
from app.websockets.connection_manager import manager
from app.services.push_service import launch_background_push, push_service

from app.endpoints.auth_endpoints import router as auth_router
from app.endpoints.device_endpoints import router as device_router
from app.endpoints.clipboard_endpoints import router as clipboard_router
from app.websockets.websocket_endpoints import router as websocket_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Run Alembic migrations programmatically
    try:
        from alembic.config import Config
        from alembic import command

        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", Settings.DATABASE_URL)
        command.upgrade(alembic_cfg, "head")
        logger.info("Database migrations applied successfully.")
    except Exception as e:
        print(f"CRITICAL STARTUP ERROR: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        logger.error("Failed to apply migrations: %s", e)
        raise RuntimeError(f"Database migration failed: {e}") from e

    redis = Redis.from_url(Settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    app.state.redis = redis
    await FastAPILimiter.init(redis)
    manager.set_redis(redis)
    await manager.start_listener()
    await push_service.start()

    cleanup_task = asyncio.create_task(periodic_cleanup())
    app.state.cleanup_task = cleanup_task

    yield

    await push_service.stop()
    await manager.stop_listener()
    redis_instance = getattr(app.state, "redis", None)
    if redis_instance:
        try:
            await redis_instance.close()
        except Exception as e:
            logger.warning("Redis close failed: %s", e)
    if cleanup_task:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass


is_prod = Settings.ENVIRONMENT.lower() == "production"

app = FastAPI(
    title=Settings.PROJECT_NAME,
    version=Settings.VERSION,
    description=Settings.DESCRIPTION,
    docs_url=None if is_prod else "/docs",
    redoc_url=None if is_prod else "/api/docs",
    openapi_url=None if is_prod else "/api/openapi.json",
    lifespan=lifespan,
)

setup_metrics(app)

app.include_router(auth_router, prefix="/api/v1")
app.include_router(device_router, prefix="/api/v1")
app.include_router(clipboard_router, prefix="/api/v1")
app.include_router(websocket_router, prefix="/ws/v1")


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    is_https = False
    if Settings.HTTPS_ONLY:
        client_ip = request.client.host if request.client else ""
        forwarded_proto = ""
        if client_ip in LOOPBACK_HOSTS:
            forwarded_proto = request.headers.get("x-forwarded-proto", "").lower()
        is_https = request.url.scheme == "https" or forwarded_proto == "https"
        is_loopback = request.url.hostname in LOOPBACK_HOSTS

        if not is_https and not is_loopback:
            https_url = request.url.replace(scheme="https")
            return RedirectResponse(url=str(https_url), status_code=307)

    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "0"

    # Avoid HSTS caching on insecure connections or loopback
    if Settings.HTTPS_ONLY and is_https:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response


def _execute_cleanup() -> CleanupResult:
    db = SessionLocal()
    try:
        return run_all_cleanup(db)
    finally:
        db.close()


async def periodic_cleanup():
    while True:
        lock = None
        acquired = False
        try:
            redis = getattr(app.state, "redis", None)
            if redis:
                lock = redis.lock("synclo:cleanup", timeout=3600, blocking=False)
                acquired = await lock.acquire()
                if not acquired:
                    await asyncio.sleep(86400)
                    continue

            cleanup_result = await asyncio.to_thread(_execute_cleanup)
            if cleanup_result.failures:
                logger.error("Cleanup completed with %d failed operations", cleanup_result.failures)
            affected_users = set()
            for user_id, tombstone in cleanup_result.tombstones:
                await manager.broadcast_to_user(user_id=user_id, message=tombstone)
                affected_users.add(user_id)
            for user_id in affected_users:
                launch_background_push(user_id=user_id)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("Cleanup task failed: %s", exc)
        finally:
            if lock is not None and acquired:
                try:
                    await lock.release()
                except Exception as exc:
                    logger.warning("Cleanup lock release failed: %s", exc)

        await asyncio.sleep(86400)


@app.exception_handler(Exception)
async def internal_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception at %s %s", request.method, request.url.path)
    logger.error("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"},
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.warning(
        f"HTTPException: {exc.status_code} - {exc.detail} at {request.method} {request.url.path}"
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


@app.get("/api/health")
def health_check():
    return JSONResponse(
        content={"status": "ok", "server": "synclo"}, headers={"Synclo-Server": "genuine"}
    )
