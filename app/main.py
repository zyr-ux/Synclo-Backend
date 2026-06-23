# app/main.py

import asyncio
import traceback
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi_limiter import FastAPILimiter
from redis.asyncio import Redis

from app.core.database import SessionLocal
from app.core.logging_config import logger
from app.core.config import Settings
from app.services.utils import run_all_cleanup
from app.websockets.connection_manager import manager

# Import routers
from app.endpoints.auth_endpoints import router as auth_router
from app.endpoints.device_endpoints import router as device_router
from app.endpoints.clipboard_endpoints import router as clipboard_router
from app.endpoints.websocket_endpoints import router as websocket_router

app = FastAPI()

# Include routers
app.include_router(auth_router, prefix="/api/v1")
app.include_router(device_router, prefix="/api/v1")
app.include_router(clipboard_router, prefix="/api/v1")
app.include_router(websocket_router, prefix="/ws/v1")


@app.on_event("startup")
async def startup():
    # Run Alembic migrations programmatically
    try:
        from alembic.config import Config
        from alembic import command
        
        # Create Alembic configuration object
        alembic_cfg = Config("alembic.ini")
        # Run the upgrade command
        command.upgrade(alembic_cfg, "head")
        logger.info("Database migrations applied successfully.")
    except Exception as e:
        import sys
        print(f"CRITICAL STARTUP ERROR: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        logger.error(f"Failed to apply migrations: {e}")
        raise RuntimeError(f"Database migration failed: {e}") from e

    # Use configurable URL
    redis = Redis.from_url(Settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    app.state.redis = redis
    await FastAPILimiter.init(redis)
    manager.set_redis(redis)
    await manager.start_listener()
    
    # Start background cleanup task and keep a handle for shutdown
    app.state.cleanup_task = asyncio.create_task(periodic_cleanup())


@app.on_event("shutdown")
async def shutdown():
    await manager.stop_listener()
    redis = getattr(app.state, "redis", None)
    if redis:
        try:
            await redis.close()
        except Exception as e:
            logger.warning(f"Redis close failed: {e}")
    # Cancel background cleanup task cleanly
    cleanup_task = getattr(app.state, "cleanup_task", None)
    if cleanup_task:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass


# Background task that runs cleanup operations every 24 hours.
async def periodic_cleanup():
    while True:
        try:
            def run_cleanup():
                db = SessionLocal()
                try:
                    run_all_cleanup(db)
                finally:
                    db.close()

            await asyncio.to_thread(run_cleanup)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Cleanup task failed: {e}")
        
        # Wait for 24 hours before next cleanup
        await asyncio.sleep(86400)


@app.exception_handler(Exception)
async def internal_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception at {request.method} {request.url.path}")
    logger.error("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"},
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.warning(f"HTTPException: {exc.status_code} - {exc.detail} at {request.method} {request.url.path}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


@app.get("/health")
def health_check():
    logger.info("Health check pinged")
    return {"status": "ok"}