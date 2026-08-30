import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any, List, Optional, Set, Tuple

import httpx

from app.core.database import SessionLocal
from app.core.metrics import PUSH_DISPATCHES_TOTAL, PUSH_DURATION_SECONDS
from app.models.models import Device

logger = logging.getLogger("clipboard_sync")


def _prune_stale_endpoint(user_id: str, device_id: str) -> None:
    """Nullifies push_subscription for a device when distributor responds with 400, 404, or 410."""
    session = SessionLocal()
    try:
        device = session.query(Device).filter_by(user_id=user_id, device_id=device_id).first()
        if device:
            _d: Any = device
            _d.push_subscription = None
            _d.push_subscription_updated_at = datetime.now(timezone.utc)
            session.commit()
            logger.info(f"Pruned stale push subscription for user={user_id} device={device_id}")
    except Exception as e:
        session.rollback()
        logger.warning(f"Failed to prune stale push subscription for device {device_id}: {e}")
    finally:
        session.close()


def _get_target_push_endpoints(user_id: str, exclude_device: Optional[str] = None) -> List[Tuple[str, str]]:
    """Queries database for user devices configured with a push subscription."""
    session = SessionLocal()
    try:
        query = session.query(Device).filter(
            Device.user_id == user_id,
            Device.push_subscription.isnot(None)
        )
        if exclude_device:
            query = query.filter(Device.device_id != exclude_device)
        devices = query.all()
        return [(d.device_id, d.push_subscription) for d in devices if d.push_subscription]
    except Exception as e:
        logger.error(f"Error querying push subscriptions for user={user_id}: {e}")
        return []
    finally:
        session.close()


class PushService:
    """
    Manages push notification dispatch, background task retention,
    and HTTP connection pooling to external push distributors.
    """

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._background_tasks: Set[asyncio.Task] = set()

    async def start(self) -> None:
        """Initializes the shared HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self.timeout)
            logger.info("PushService HTTP client started.")

    async def stop(self) -> None:
        """Closes the shared HTTP client and gracefully awaits pending tasks."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
            logger.info("PushService HTTP client stopped.")

    def _get_or_create_client(self) -> httpx.AsyncClient:
        """Returns the active client, initializing on demand if not started."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self.timeout)
        return self._client

    async def send_push_notification(self, device_id: str, endpoint: str, user_id: str) -> bool:
        """
        Sends a zero-knowledge wake-up push trigger to a UnifiedPush distributor endpoint.
        Automatically self-heals stale endpoints on 400, 404, or 410 responses.
        """
        payload = {
            "type": "push",
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        }

        start_time = time.perf_counter()
        try:
            client = self._get_or_create_client()
            response = await client.post(endpoint, json=payload)
            duration = time.perf_counter() - start_time
            PUSH_DURATION_SECONDS.observe(duration)

            if response.status_code in (200, 201, 202, 204):
                PUSH_DISPATCHES_TOTAL.labels(status="success").inc()
                logger.info(f"Push wake-up delivered to device={device_id} status={response.status_code}")
                return True
            elif response.status_code in (400, 404, 410):
                PUSH_DISPATCHES_TOTAL.labels(status="stale_pruned").inc()
                logger.warning(
                    f"Distributor rejected endpoint ({response.status_code}) for device={device_id}. Pruning stale subscription."
                )
                await asyncio.to_thread(_prune_stale_endpoint, user_id, device_id)
                return False
            else:
                PUSH_DISPATCHES_TOTAL.labels(status="error").inc()
                logger.warning(
                    f"Distributor error ({response.status_code}) for device={device_id}"
                )
                return False
        except httpx.TimeoutException:
            duration = time.perf_counter() - start_time
            PUSH_DURATION_SECONDS.observe(duration)
            PUSH_DISPATCHES_TOTAL.labels(status="timeout").inc()
            logger.warning(f"Push delivery timed out after {self.timeout}s for device={device_id}")
            return False
        except Exception as e:
            duration = time.perf_counter() - start_time
            PUSH_DURATION_SECONDS.observe(duration)
            PUSH_DISPATCHES_TOTAL.labels(status="error").inc()
            logger.warning(f"Push delivery failed for device={device_id}: {e}")
            return False

    async def dispatch_push_to_user_devices(self, user_id: str, exclude_device: Optional[str] = None) -> None:
        """
        Dispatches wake-up push notifications to all registered devices belonging to user_id
        that have a push_subscription configured, excluding the sender device.
        """
        endpoints = await asyncio.to_thread(_get_target_push_endpoints, user_id, exclude_device)
        if not endpoints:
            return

        tasks = [
            self.send_push_notification(device_id, endpoint, user_id)
            for device_id, endpoint in endpoints
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    def launch_background_push(self, user_id: str, exclude_device: Optional[str] = None) -> asyncio.Task:
        """
        Launches a background push dispatch task and maintains a strong reference
        in _background_tasks until completion to prevent premature garbage collection.
        """
        task = asyncio.create_task(self.dispatch_push_to_user_devices(user_id=user_id, exclude_device=exclude_device))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        return task


# Global singleton instance
push_service = PushService()

# Export module-level shortcuts for backward compatibility and clean importing
send_push_notification = push_service.send_push_notification
dispatch_push_to_user_devices = push_service.dispatch_push_to_user_devices
launch_background_push = push_service.launch_background_push
