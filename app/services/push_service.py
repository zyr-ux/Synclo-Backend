import asyncio
import base64
import contextvars
import hashlib
import ipaddress
import logging
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncIterable, List, Optional, Set, Tuple, cast
from urllib.parse import urlparse

import httpcore
import httpx
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import Settings
from app.core.constants import LOOPBACK_HOSTS
from app.core.database import SessionLocal, run_in_write_transaction
from app.core.metrics import PUSH_DISPATCHES_TOTAL, PUSH_DURATION_SECONDS
from app.models.models import Device

logger = logging.getLogger("clipboard_sync")


class EndpointValidationStatus(str, Enum):
    VALID = "valid"
    DNS_ERROR = "dns_error"
    SSRF_BLOCKED = "ssrf_blocked"


@dataclass
class EndpointValidationResult:
    status: EndpointValidationStatus
    details: Optional[Tuple[str, str, int]] = None
    reason: str = ""

    def __iter__(self):
        if self.details:
            return iter(self.details)
        return iter(())

    def __bool__(self):
        return self.status == EndpointValidationStatus.VALID

MAX_PUSH_RESPONSE_BYTES = 10 * 1024
_PUSH_SUBSCRIPTION_PREFIX = "v1:"

_current_pinned_ips: contextvars.ContextVar[dict[str, str]] = contextvars.ContextVar(
    "_current_pinned_ips", default={}
)


def _push_subscription_cipher() -> Fernet:
    secret_key = Settings.SECRET_KEY
    if not secret_key:
        raise RuntimeError("SECRET_KEY is required for push subscription encryption")
    key = base64.urlsafe_b64encode(hashlib.sha256(secret_key.encode("utf-8")).digest())
    return Fernet(key)


def encrypt_push_subscription(endpoint: str) -> str:
    token = _push_subscription_cipher().encrypt(endpoint.encode("utf-8")).decode("ascii")
    return f"{_PUSH_SUBSCRIPTION_PREFIX}{token}"


def decrypt_push_subscription(value: str) -> Optional[str]:
    if not value.startswith(_PUSH_SUBSCRIPTION_PREFIX):
        return None
    try:
        token = value[len(_PUSH_SUBSCRIPTION_PREFIX):].encode("ascii")
        return _push_subscription_cipher().decrypt(token).decode("utf-8")
    except (ValueError, UnicodeError, InvalidToken):
        return None



class PinnedNetworkBackend(httpcore.AnyIOBackend):
    def __init__(self, pinned_ips: dict[str, str]):
        super().__init__()
        self.pinned_ips = pinned_ips

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        ctx_pins = _current_pinned_ips.get()
        target_ip = ctx_pins.get(host) if ctx_pins and host in ctx_pins else self.pinned_ips.get(host, host)
        backend = cast(Any, super())
        return await backend.connect_tcp(
            target_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


class _HttpcoreResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream: AsyncIterable[bytes]) -> None:
        self._stream = cast(AsyncIterable[bytes], stream)

    async def __aiter__(self):
        async for chunk in self._stream:
            yield chunk

    async def aclose(self) -> None:
        await cast(Any, self._stream).aclose()


# Direct transport that preserves validated hostname for TLS and pins TCP DNS
class PinnedAsyncTransport(httpx.AsyncBaseTransport):
    def __init__(
        self,
        pinned_ips: dict[str, str],
        *,
        verify: ssl.SSLContext | str | bool = True,
        cert: Any = None,
        trust_env: bool = True,
        http1: bool = True,
        http2: bool = False,
        limits: Optional[httpx.Limits] = None,
        local_address: Optional[str] = None,
        retries: int = 0,
        socket_options: Any = None,
    ) -> None:
        limits = limits or httpx.Limits()
        self.pinned_ips = pinned_ips
        self.ssl_context = httpx.create_ssl_context(verify=verify, cert=cert, trust_env=trust_env)
        self.network_backend = PinnedNetworkBackend(pinned_ips)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=self.ssl_context,
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            http1=http1,
            http2=http2,
            retries=retries,
            local_address=local_address,
            socket_options=socket_options,
            network_backend=cast(Any, self.network_backend),
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        try:
            core_response = await self._pool.handle_async_request(core_request)
        except httpcore.TimeoutException as exc:
            raise httpx.TimeoutException(str(exc), request=request) from exc
        except httpcore.NetworkError as exc:
            raise httpx.NetworkError(str(exc), request=request) from exc

        return httpx.Response(
            status_code=core_response.status,
            headers=core_response.headers,
            stream=_HttpcoreResponseStream(cast(AsyncIterable[bytes], core_response.stream)),
            extensions=core_response.extensions,
            request=request,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


def _prune_stale_endpoint(user_id: str, device_id: str) -> None:
    session = SessionLocal()
    try:
        def mutate():
            device = session.query(Device).filter_by(user_id=user_id, device_id=device_id).first()
            if device:
                device.push_subscription = None
                device.push_subscription_updated_at = datetime.now(timezone.utc)
        run_in_write_transaction(session, mutate)
        logger.info(f"Pruned stale push subscription for user={user_id} device={device_id}")
    except Exception as e:
        logger.warning(f"Failed to prune stale push subscription for device {device_id}: {e}")
    finally:
        session.close()


def _get_target_push_endpoints(user_id: str, exclude_device: Optional[str] = None) -> List[Tuple[str, str]]:
    session = SessionLocal()
    try:
        query = session.query(Device).filter(
            Device.user_id == user_id,
            Device.push_subscription.isnot(None)
        )
        if exclude_device:
            query = query.filter(Device.device_id != exclude_device)
        devices = query.all()
        endpoints = []
        for device in devices:
            if not device.push_subscription:
                continue
            endpoint = decrypt_push_subscription(device.push_subscription)
            if endpoint:
                endpoints.append((device.device_id, endpoint))
            else:
                logger.warning("Ignoring invalid encrypted push subscription for device=%s", device.device_id)
        return endpoints
    except Exception as e:
        logger.error(f"Error querying push subscriptions for user={user_id}: {e}")
        return []
    finally:
        session.close()


def _is_allowed_domain(hostname: Optional[str]) -> bool:
    if Settings.ALLOW_ARBITRARY_PUSH_ENDPOINTS:
        return True
    if not hostname:
        return False
    host = hostname.lower().strip(".")
    for allowed in Settings.ALLOWED_PUSH_DOMAINS:
        allowed = allowed.lower().strip(".")
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def _is_safe_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if Settings.ALLOW_LOCAL_PUSH_ENDPOINTS:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped.is_global
    return ip.is_global


async def _validate_endpoint_and_resolve(endpoint: str) -> EndpointValidationResult:
    parsed = urlparse(endpoint)
    if not parsed.scheme or not parsed.hostname:
        logger.warning("Invalid push endpoint URL format")
        return EndpointValidationResult(EndpointValidationStatus.SSRF_BLOCKED, reason="Invalid URL format")

    if parsed.username or parsed.password:
        logger.warning("SSRF: Embedded credentials rejected in push endpoint")
        return EndpointValidationResult(EndpointValidationStatus.SSRF_BLOCKED, reason="Embedded credentials rejected")

    hostname = parsed.hostname.lower()

    if parsed.scheme == "http":
        if not (Settings.ALLOW_LOCAL_PUSH_ENDPOINTS or (not Settings.HTTPS_ONLY and hostname in LOOPBACK_HOSTS)):
            logger.warning("SSRF: Plain HTTP rejected for push endpoint")
            return EndpointValidationResult(EndpointValidationStatus.SSRF_BLOCKED, reason="Plain HTTP rejected")
    elif parsed.scheme != "https":
        logger.warning(f"SSRF: Unsupported scheme '{parsed.scheme}' for push endpoint")
        return EndpointValidationResult(EndpointValidationStatus.SSRF_BLOCKED, reason=f"Unsupported scheme '{parsed.scheme}'")

    # Port restriction: HTTPS must use 443; local dev HTTP may use 80 or explicit local port
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme == "https" and port != 443:
        logger.warning(f"SSRF: Non-standard port {port} rejected for HTTPS push endpoint")
        return EndpointValidationResult(EndpointValidationStatus.SSRF_BLOCKED, reason=f"Non-standard HTTPS port {port}")
    if parsed.scheme == "http" and not Settings.ALLOW_LOCAL_PUSH_ENDPOINTS and port != 80:
        logger.warning(f"SSRF: Non-standard port {port} rejected for HTTP push endpoint")
        return EndpointValidationResult(EndpointValidationStatus.SSRF_BLOCKED, reason=f"Non-standard HTTP port {port}")

    if not _is_allowed_domain(hostname):
        logger.warning(f"SSRF: Domain '{hostname}' is not in ALLOWED_PUSH_DOMAINS")
        return EndpointValidationResult(EndpointValidationStatus.SSRF_BLOCKED, reason=f"Domain '{hostname}' not allowed")

    loop = asyncio.get_running_loop()
    try:
        addr_infos = await loop.getaddrinfo(hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except (socket.gaierror, socket.herror, OSError, asyncio.TimeoutError) as e:
        logger.warning(f"DNS resolution failed transiently for {hostname}: {e}")
        return EndpointValidationResult(EndpointValidationStatus.DNS_ERROR, reason=f"DNS resolution failed: {e}")
    except Exception as e:
        logger.warning(f"DNS resolution error for {hostname}: {e}")
        return EndpointValidationResult(EndpointValidationStatus.DNS_ERROR, reason=f"DNS resolution error: {e}")

    if not addr_infos:
        logger.warning(f"DNS resolution returned no records for {hostname}")
        return EndpointValidationResult(EndpointValidationStatus.DNS_ERROR, reason="DNS resolution returned no records")

    for info in addr_infos:
        ip_str = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            logger.warning(f"SSRF: Invalid resolved IP address {ip_str}")
            return EndpointValidationResult(EndpointValidationStatus.SSRF_BLOCKED, reason=f"Invalid resolved IP: {ip_str}")
        if not _is_safe_ip(ip_obj):
            logger.warning(f"SSRF: Resolved IP {ip_str} is private or non-global for {hostname}")
            return EndpointValidationResult(EndpointValidationStatus.SSRF_BLOCKED, reason=f"Resolved IP {ip_str} is private or non-global")

    pinned_ip = addr_infos[0][4][0]
    return EndpointValidationResult(EndpointValidationStatus.VALID, details=(hostname, pinned_ip, port))


class PushService:
    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._transport: Optional[PinnedAsyncTransport] = None
        self._background_tasks: Set[asyncio.Task] = set()

    async def start(self) -> None:
        if self._client is None or self._client.is_closed:
            self._transport = PinnedAsyncTransport(
                {},
                limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            )
            self._client = httpx.AsyncClient(
                transport=self._transport,
                timeout=self.timeout,
                follow_redirects=False,
            )
            logger.info("PushService started.")

    async def stop(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
        self._client = None
        self._transport = None
        logger.info("PushService stopped.")

    async def send_push_notification(self, device_id: str, endpoint: str, user_id: str) -> bool:
        validation = await _validate_endpoint_and_resolve(endpoint)
        if validation.status == EndpointValidationStatus.SSRF_BLOCKED:
            reason = validation.reason or "SSRF violation"
            PUSH_DISPATCHES_TOTAL.labels(status="ssrf_blocked").inc()
            logger.warning(f"Push endpoint failed security validation for device={device_id} ({reason}). Pruning subscription.")
            await asyncio.to_thread(_prune_stale_endpoint, user_id, device_id)
            return False
        elif validation.status == EndpointValidationStatus.DNS_ERROR:
            reason = validation.reason or "DNS error"
            PUSH_DISPATCHES_TOTAL.labels(status="dns_error").inc()
            logger.warning(f"Push endpoint DNS resolution failed transiently for device={device_id}: {reason}. Skipping push.")
            return False
        elif validation.status != EndpointValidationStatus.VALID or not validation.details:
            PUSH_DISPATCHES_TOTAL.labels(status="ssrf_blocked").inc()
            logger.warning(f"Push endpoint failed security validation for device={device_id}. Pruning subscription.")
            await asyncio.to_thread(_prune_stale_endpoint, user_id, device_id)
            return False

        hostname, pinned_ip, port = validation.details
        payload = {"type": "push"}

        start_time = time.perf_counter()
        is_oversized = False
        current_pins = _current_pinned_ips.get().copy()
        current_pins[hostname] = pinned_ip
        token = _current_pinned_ips.set(current_pins)
        try:
            await self.start()
            assert self._client is not None
            assert self._transport is not None
            async with self._client.stream(
                "POST",
                endpoint,
                json=payload,
                headers={"User-Agent": "Synclo-Backend/1.0"},
                follow_redirects=False,
            ) as response:
                total_bytes = 0
                async for chunk in response.aiter_bytes():
                    remaining = MAX_PUSH_RESPONSE_BYTES - total_bytes
                    if len(chunk) > remaining:
                        is_oversized = True
                        logger.warning(
                            f"Push response exceeded {MAX_PUSH_RESPONSE_BYTES} bytes from "
                            f"{hostname}:{port}. Aborting stream."
                        )
                        await response.aclose()
                        break
                    total_bytes += len(chunk)

                status = response.status_code

            # Oversized responses are delivery failures, not stale endpoints and not retries.
            if is_oversized:
                PUSH_DISPATCHES_TOTAL.labels(status="oversized").inc()
                return False

            if status in (200, 201, 202, 204):
                PUSH_DISPATCHES_TOTAL.labels(status="success").inc()
                logger.info(f"Push wake-up delivered to device={device_id} host={hostname}:{port} status={status}")
                return True
            elif status in (400, 404, 410):
                PUSH_DISPATCHES_TOTAL.labels(status="stale_pruned").inc()
                logger.warning(
                    f"Distributor rejected endpoint ({status}) for device={device_id} host={hostname}:{port}. Pruning stale subscription."
                )
                await asyncio.to_thread(_prune_stale_endpoint, user_id, device_id)
                return False
            else:
                PUSH_DISPATCHES_TOTAL.labels(status="error").inc()
                logger.warning(
                    f"Distributor error ({status}) for device={device_id} host={hostname}:{port}"
                )
                return False
        except httpx.TimeoutException:
            PUSH_DISPATCHES_TOTAL.labels(status="timeout").inc()
            logger.warning(f"Push delivery timed out after {self.timeout}s for device={device_id}")
            return False
        except Exception as e:
            PUSH_DISPATCHES_TOTAL.labels(status="error").inc()
            logger.warning(f"Push delivery failed for device={device_id}: {e}")
            return False
        finally:
            _current_pinned_ips.reset(token)
            PUSH_DURATION_SECONDS.observe(time.perf_counter() - start_time)

    async def dispatch_push_to_user_devices(self, user_id: str, exclude_device: Optional[str] = None) -> None:
        endpoints = await asyncio.to_thread(_get_target_push_endpoints, user_id, exclude_device)
        if not endpoints:
            return

        tasks = [
            self.send_push_notification(device_id, endpoint, user_id)
            for device_id, endpoint in endpoints
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    def launch_background_push(self, user_id: str, exclude_device: Optional[str] = None) -> asyncio.Task:
        task = asyncio.create_task(self.dispatch_push_to_user_devices(user_id=user_id, exclude_device=exclude_device))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        return task


push_service = PushService()

send_push_notification = push_service.send_push_notification
dispatch_push_to_user_devices = push_service.dispatch_push_to_user_devices
launch_background_push = push_service.launch_background_push
