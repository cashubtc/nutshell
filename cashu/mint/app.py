import sys
from traceback import print_exception

from fastapi import FastAPI, status
from fastapi.exception_handlers import (
    request_validation_exception_handler as _request_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from loguru import logger
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request

from ..core.errors import CashuError
from ..core.logging import configure_logger
from ..core.settings import settings
from .router import router
from .router_deprecated import router_deprecated
from .startup import start_mint_init

if settings.debug_profiling:
    from fastapi_profiler import PyInstrumentProfilerMiddleware

# from starlette_context import context
# from starlette_context.middleware import RawContextMiddleware


# class CustomHeaderMiddleware(BaseHTTPMiddleware):
#     """
#     Middleware for starlette that can set the context from request headers
#     """

#     async def dispatch(self, request, call_next):
#         context["client-version"] = request.headers.get("Client-version")
#         response = await call_next(request)
#         return response


def create_app(config_object="core.settings") -> FastAPI:
    configure_logger()

    # middleware = [
    #     Middleware(
    #         RawContextMiddleware,
    #     ),
    #     Middleware(CustomHeaderMiddleware),
    # ]

    middleware = [
        Middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
            expose_headers=["*"],
        )
    ]

    app = FastAPI(
        title="Nutshell Cashu Mint",
        description="Ecash wallet and mint based on the Cashu protocol.",
        version=settings.version,
        license_info={
            "name": "MIT License",
            "url": "https://raw.githubusercontent.com/cashubtc/cashu/main/LICENSE",
        },
        middleware=middleware,
    )

    if settings.debug_profiling:
        assert PyInstrumentProfilerMiddleware is not None
        app.add_middleware(PyInstrumentProfilerMiddleware)

    return app


app = create_app()


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

        if isinstance(e, CashuError):
            logger.error(f"CashuError: {err_message}")
            # return with cors headers
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": err_message, "code": e.code},
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


@app.on_event("startup")
async def startup_mint():
    await start_mint_init()


if settings.debug_mint_only_deprecated:
    app.include_router(router=router_deprecated, tags=["Deprecated"], deprecated=True)
else:
    app.include_router(router=router, tags=["Mint"])
    app.include_router(router=router_deprecated, tags=["Deprecated"], deprecated=True)

app.add_exception_handler(RequestValidationError, request_validation_exception_handler)
