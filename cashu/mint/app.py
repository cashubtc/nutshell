import asyncio
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from traceback import print_exception

from fastapi import FastAPI, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi_cache import FastAPICache
from fastapi_cache.backends.inmemory import InMemoryBackend
from loguru import logger
from starlette.requests import Request

from ..core.errors import CashuError
from ..core.logging import configure_logger
from ..core.settings import settings
from .router import router
from .router_deprecated import router_deprecated
from .startup import shutdown_mint as shutdown_mint_init
from .startup import start_mint_init

if settings.debug_profiling:
    pass

if settings.mint_rate_limit:
    pass

from .middleware import add_middlewares, request_validation_exception_handler


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    if settings.mint_cache_activate:
        FastAPICache.init(InMemoryBackend(), prefix="fastapi-cache")
    await start_mint_init()
    try:
        yield
    except asyncio.CancelledError:
        # Handle the cancellation gracefully
        logger.info("Shutdown process interrupted by CancelledError")
    finally:
        try:
            await shutdown_mint_init()
            await FastAPICache.clear()
        except asyncio.CancelledError:
            logger.info("CancelledError during shutdown, shutting down forcefully")


def create_app(config_object="core.settings") -> FastAPI:
    configure_logger()

    app = FastAPI(
        title="Nutshell Mint",
        description="Ecash mint based on the Cashu protocol.",
        version=settings.version,
        license_info={
            "name": "MIT License",
            "url": "https://raw.githubusercontent.com/cashubtc/cashu/main/LICENSE",
        },
        lifespan=lifespan,
    )

    return app


app = create_app()

# Add middlewares
add_middlewares(app)


@app.middleware("http")
async def catch_exceptions(request: Request, call_next):
    CORS_HEADERS = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "*",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Credentials": "true",
    }
    try:
        return await call_next(request)
    except Exception as e:
        try:
            err_message = str(e)
        except Exception:
            err_message = e.args[0] if e.args else "Unknown error"

        if isinstance(e, CashuError) or isinstance(e.args[0], CashuError):
            logger.error(f"CashuError: {err_message}")
            code = e.code if isinstance(e, CashuError) else e.args[0].code
            # return with cors headers
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": err_message, "code": code},
                headers=CORS_HEADERS,
            )
        logger.error(f"Exception: {err_message}")
        if settings.debug:
            print_exception(*sys.exc_info())
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": err_message, "code": 0},
            headers=CORS_HEADERS,
        )


# Add exception handlers
app.add_exception_handler(RequestValidationError, request_validation_exception_handler)

# Add routers
if settings.debug_mint_only_deprecated:
    app.include_router(router=router_deprecated, tags=["Deprecated"], deprecated=True)
else:
    app.include_router(router=router, tags=["Mint"])
    app.include_router(router=router_deprecated, tags=["Deprecated"], deprecated=True)
