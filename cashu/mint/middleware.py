from fastapi import FastAPI, status
from fastapi.exception_handlers import (
    request_validation_exception_handler as _request_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from loguru import logger
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request

from ..core.settings import settings

if settings.debug_profiling:
    from fastapi_profiler import PyInstrumentProfilerMiddleware

if settings.mint_rate_limit:
    from slowapi import Limiter
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware
    from slowapi.util import get_remote_address


def add_middlewares(app: FastAPI):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )

    if settings.debug_profiling:
        assert PyInstrumentProfilerMiddleware is not None
        app.add_middleware(PyInstrumentProfilerMiddleware)

    if settings.mint_rate_limit:

        def get_remote_address_excluding_local(request: Request) -> str:
            remote_address = get_remote_address(request)
            if remote_address == "127.0.0.1":
                return ""
            return remote_address

        limiter = Limiter(
            key_func=get_remote_address_excluding_local,
            default_limits=[f"{settings.mint_rate_limit_per_minute}/minute"],
        )
        app.state.limiter = limiter

        def _rate_limit_exceeded_handler(
            request: Request, exc: Exception
        ) -> JSONResponse:
            remote_address = get_remote_address(request)
            logger.warning(
                f"Rate limit {settings.mint_rate_limit_per_minute}/minute exceeded: {remote_address}"
            )
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded."},
            )

        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        app.add_middleware(SlowAPIMiddleware)


async def request_validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """
    This is a wrapper to the default RequestValidationException handler of FastAPI.
    This function will be called when client input is not valid.
    """
    query_params = request.query_params._dict
    detail = {
        "errors": exc.errors(),
        "query_params": query_params,
    }
    # log the error
    logger.error(detail)
    # pass on
    return await _request_validation_exception_handler(request, exc)
