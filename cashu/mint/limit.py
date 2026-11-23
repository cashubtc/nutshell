from typing import Optional

from fastapi import WebSocket, status
from fastapi.responses import JSONResponse
from limits import RateLimitItemPerMinute
from loguru import logger
from slowapi import Limiter
from starlette.requests import HTTPConnection, Request

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


def _get_client_ip(request: HTTPConnection) -> str:
    """Use the client address resolved by the ASGI server."""
    client = request.client
    return client.host if client and client.host else "unknown"


def get_remote_address_excluding_local(request: HTTPConnection) -> str:
    client = request.client
    # Uvicorn assigns port zero to addresses resolved from forwarding headers.
    if client and client.host == "127.0.0.1" and client.port:
        if not settings.mint_rate_limit_proxy_trust or not any(
            header in request.headers
            for header in ("x-forwarded-for", "x-forwarded-proto", "cf-connecting-ip")
        ):
            return ""
    return _get_client_ip(request)


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
    return _get_client_ip(ws)


def limit_websocket(ws: WebSocket):
    remote_address = get_remote_address_excluding_local(ws)
    if remote_address:
        assert_limit(remote_address)
