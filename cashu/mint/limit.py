import ipaddress
from typing import Optional

from fastapi import WebSocket, status
from fastapi.responses import JSONResponse
from limits import RateLimitItemPerMinute
from loguru import logger
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

from ..core.settings import settings


def _rate_limit_exceeded_handler(request: Request, exc: Exception) -> JSONResponse:
    remote_address = _get_client_ip(request)
    logger.warning(
        f"Rate limit {settings.mint_global_rate_limit_per_minute}/minute exceeded:"
        f" {remote_address}"
    )
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Rate limit exceeded."},
    )


def _is_trusted_proxy(host: Optional[str]) -> bool:
    """Whether `host` is in `mint_forwarded_allow_ips` (IPs, networks or '*')."""
    allowed = [h.strip() for h in settings.mint_forwarded_allow_ips.split(",")]
    if "*" in allowed:
        return True
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host in allowed
    for entry in allowed:
        try:
            if address in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def _client_ip_from_headers(headers, peer: Optional[str]) -> Optional[str]:
    """Client IP from proxy headers, believed only if the connecting peer is a
    trusted proxy. Anyone else could set them to pick their own rate-limit
    bucket."""
    if not settings.mint_rate_limit_proxy_trust or not _is_trusted_proxy(peer):
        return None
    cf_ip = headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip.strip()
    xff = headers.get("x-forwarded-for")
    if xff:
        # proxies append, so the rightmost untrusted entry is the client
        hosts = [h.strip() for h in xff.split(",") if h.strip()]
        for host in reversed(hosts):
            if not _is_trusted_proxy(host):
                return host
        if hosts:
            return hosts[0]
    return None


def _get_client_ip(request: Request) -> str:
    """Extract the client IP from the request, checking proxy headers first
    if configured to trust them and the request comes from a trusted proxy
    (`mint_forwarded_allow_ips`).

    Header priority (when proxy trust is enabled):
      1. CF-Connecting-IP  – set by Cloudflare
      2. X-Forwarded-For   – set by most reverse proxies (rightmost untrusted entry)
      3. request.client     – direct connection IP (fallback)
    """
    peer = request.client.host if request.client else None
    return _client_ip_from_headers(request.headers, peer) or get_remote_address(request)


def get_remote_address_excluding_local(request: Request) -> str:
    remote_address = _get_client_ip(request)
    if remote_address == "127.0.0.1":
        return ""
    return remote_address


limiter_global = Limiter(
    key_func=get_remote_address_excluding_local,
    strategy="fixed-window-elastic-expiry",
    default_limits=[f"{settings.mint_global_rate_limit_per_minute}/minute"],
    enabled=settings.mint_rate_limit,
)

limiter = Limiter(
    key_func=get_remote_address_excluding_local,
    strategy="fixed-window-elastic-expiry",
    default_limits=[f"{settings.mint_transaction_rate_limit_per_minute}/minute"],
    enabled=settings.mint_rate_limit,
)


def assert_limit(identifier: str, limit: Optional[int] = None):
    """Custom rate limit handler that accepts a string identifier
    and raises an exception if the rate limit is exceeded. Uses the
    setting `mint_transaction_rate_limit_per_minute` for the rate limit.

    Args:
        identifier (str): The identifier to use for the rate limit. IP address for example.
        limit (Optional[int], optional): The rate limit per minute to use. Defaults to None

    Raises:
        Exception: If the rate limit is exceeded.
    """
    global limiter
    limit_per_minute = limit or settings.mint_transaction_rate_limit_per_minute
    success = limiter._limiter.hit(
        RateLimitItemPerMinute(limit_per_minute),
        identifier,
    )
    if not success:
        logger.warning(f"Rate limit {limit_per_minute}/minute exceeded: {identifier}")
        raise Exception("Rate limit exceeded")


def get_ws_remote_address(ws: WebSocket) -> str:
    """Returns the ip address for the current websocket (or 127.0.0.1 if none found)

    Args:
        ws (WebSocket): The FastAPI WebSocket object.

    Returns:
        str: The ip address for the current websocket.
    """
    peer = ws.client.host if ws.client else None
    forwarded = _client_ip_from_headers(ws.headers, peer)
    if forwarded:
        return forwarded
    if not ws.client or not ws.client.host:
        return "127.0.0.1"

    return ws.client.host


def limit_websocket(ws: WebSocket):
    """Websocket rate limit handler that accepts a FastAPI WebSocket object.
    This function will raise an exception if the rate limit is exceeded.

    Args:
        ws (WebSocket): The FastAPI WebSocket object.

    Raises:
        Exception: If the rate limit is exceeded.
    """
    remote_address = get_ws_remote_address(ws)
    if remote_address == "127.0.0.1":
        return
    assert_limit(remote_address)
