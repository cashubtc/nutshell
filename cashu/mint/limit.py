from fastapi import WebSocket, status
from fastapi.responses import JSONResponse
from limits import RateLimitItemPerMinute
from loguru import logger
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

from ..core.settings import settings


def _rate_limit_exceeded_handler(request: Request, exc: Exception) -> JSONResponse:
    remote_address = get_remote_address(request)
    logger.warning(
        f"Rate limit {settings.mint_global_rate_limit_per_minute}/minute exceeded: {remote_address}"
    )
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Rate limit exceeded."},
    )


def get_remote_address_excluding_local(request: Request) -> str:
    remote_address = get_remote_address(request)
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


def assert_limit(identifier: str):
    """Custom rate limit handler that accepts a string identifier
    and raises an exception if the rate limit is exceeded. Uses the
    setting `mint_transaction_rate_limit_per_minute` for the rate limit.

    Args:
        identifier (str): The identifier to use for the rate limit. IP address for example.

    Raises:
        Exception: If the rate limit is exceeded.
    """
    global limiter
    success = limiter._limiter.hit(
        RateLimitItemPerMinute(settings.mint_transaction_rate_limit_per_minute),
        identifier,
    )
    if not success:
        logger.warning(
            f"Rate limit {settings.mint_transaction_rate_limit_per_minute}/minute exceeded: {identifier}"
        )
        raise Exception("Rate limit exceeded")


def get_ws_remote_address(ws: WebSocket) -> str:
    """Returns the ip address for the current websocket (or 127.0.0.1 if none found)

    Args:
        ws (WebSocket): The FastAPI WebSocket object.

    Returns:
        str: The ip address for the current websocket.
    """
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
