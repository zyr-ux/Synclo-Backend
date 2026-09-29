from time import time_ns
from typing import Callable, Dict, List, Optional, Union
from fastapi import Request, Response, WebSocket
from fastapi_limiter.depends import RateLimiter, default_callback
from pyrate_limiter import (
    BucketFactory,
    Duration,
    InMemoryStateStore,
    Limiter,
    Rate,
    RateItem,
    RedisStateStore,
    StateBucket,
)
from redis.asyncio import Redis

from app.core.constants import is_trusted_proxy
from app.core.logging_config import logger

_redis_client: Optional[Redis] = None


def set_redis(redis: Optional[Redis]) -> None:
    global _redis_client
    _redis_client = redis


def get_redis() -> Optional[Redis]:
    return _redis_client


async def default_identifier(request: Union[Request, WebSocket]) -> str:
    client_ip = request.client.host if request.client else "127.0.0.1"
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and is_trusted_proxy(client_ip):
        client_ip = forwarded.split(",")[0].strip()
    return client_ip


class SyncloBucketFactory(BucketFactory):
    def __init__(self, rates: List[Rate]):
        super().__init__()
        self.rates = rates
        self.in_memory_buckets: Dict[str, StateBucket] = {}

    def wrap_item(self, name: str, weight: int = 1) -> RateItem:
        return RateItem(name, time_ns() // 1_000_000, weight=weight)

    def get(self, item: RateItem) -> StateBucket:
        key = f"synclo:rate_limit:{item.name}"
        redis = get_redis()
        if redis is not None:
            return StateBucket(self.rates, store=RedisStateStore(redis, key=key))

        bucket = self.in_memory_buckets.get(key)
        if bucket is None:
            if len(self.in_memory_buckets) > 10000:
                self.in_memory_buckets.clear()
            bucket = StateBucket(self.rates, store=InMemoryStateStore())
            self.in_memory_buckets[key] = bucket
        return bucket


async def _patched_rate_limiter_call(self: RateLimiter, request: Request, response: Response):
    route = request.scope.get("route")
    route_key: Union[str, int] = "0"

    if route is None:
        path = request.scope.get("path")
        for i, r in enumerate(request.app.routes):
            if getattr(r, "path", None) == path and request.method in getattr(r, "methods", ()):
                route = r
                route_key = str(i)
                break
    else:
        route_key = getattr(route, "unique_id", None) or getattr(route, "path", "0")

    if route is not None:
        if getattr(getattr(route, "endpoint", None), "_skip_limiter", False):
            return
        dep_index = next(
            (j for j, d in enumerate(getattr(route, "dependencies", [])) if getattr(d, "dependency", None) is self),
            0,
        )
    else:
        dep_index = 0

    rate_key = await self.identifier(request)
    key = f"{rate_key}:{route_key}:{dep_index}"
    try:
        success = await self.limiter.try_acquire_async(key, blocking=self.blocking)
    except Exception as exc:
        # Fail open on storage transport errors to preserve availability
        logger.warning("Rate limiter storage error: %s; allowing request", exc)
        return

    if not success:
        return await self.callback(request, response)


RateLimiter.__call__ = _patched_rate_limiter_call


def create_limiter(
    times: int,
    seconds: int = 60,
    identifier: Optional[Callable] = None,
    callback: Optional[Callable] = None,
) -> RateLimiter:
    rate = Rate(times, Duration.SECOND * seconds)
    factory = SyncloBucketFactory([rate])
    limiter = Limiter(factory)
    return RateLimiter(
        limiter=limiter,
        identifier=identifier or default_identifier,
        callback=callback or default_callback,
    )
