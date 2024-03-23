from fastapi import status
from fastapi.responses import JSONResponse
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
