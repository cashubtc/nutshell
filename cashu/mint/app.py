import logging
import sys
from traceback import print_exception

from fastapi import FastAPI, status
from fastapi.responses import JSONResponse

# from fastapi_profiler import PyInstrumentProfilerMiddleware
from loguru import logger
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..core.errors import CashuError
from ..core.settings import settings
from .router import router
from .startup import start_mint_init

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
    def configure_logger() -> None:
        class Formatter:
            def __init__(self):
                self.padding = 0
                self.minimal_fmt: str = "<green>{time:YYYY-MM-DD HH:mm:ss.SS}</green> | <level>{level}</level> | <level>{message}</level>\n"
                if settings.debug:
                    self.fmt: str = (
                        "<green>{time:YYYY-MM-DD HH:mm:ss.SS}</green> | <level>{level: <4}</level> | <cyan>{name}</cyan>:<cyan>"
                        "{function}</cyan>:<cyan>{line}</cyan> | <level>{message}</level>\n"
                    )
                else:
                    self.fmt: str = self.minimal_fmt

            def format(self, record):
                function = "{function}".format(**record)
                if function == "emit":  # uvicorn logs
                    return self.minimal_fmt
                return self.fmt

        class InterceptHandler(logging.Handler):
            def emit(self, record):
                try:
                    level = logger.level(record.levelname).name
                except ValueError:
                    level = record.levelno
                logger.log(level, record.getMessage())

        logger.remove()
        log_level = settings.log_level
        if settings.debug and log_level == "INFO":
            log_level = "DEBUG"
        formatter = Formatter()
        logger.add(sys.stderr, level=log_level, format=formatter.format)

        logging.getLogger("uvicorn").handlers = [InterceptHandler()]
        logging.getLogger("uvicorn.access").handlers = [InterceptHandler()]

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
        title="Cashu Python Mint",
        description="Ecash wallet and mint for Bitcoin",
        version=settings.version,
        license_info={
            "name": "MIT License",
            "url": "https://raw.githubusercontent.com/cashubtc/cashu/main/LICENSE",
        },
        middleware=middleware,
    )

    # app.add_middleware(PyInstrumentProfilerMiddleware)

    return app


app = create_app()


@app.middleware("http")
async def catch_exceptions(request: Request, call_next):
    try:
        return await call_next(request)
    except Exception as e:
        try:
            err_message = str(e)
        except:
            err_message = e.args[0] if e.args else "Unknown error"

        if isinstance(e, CashuError):
            logger.error(f"CashuError: {err_message}")
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": err_message, "code": e.code},
            )
        logger.error(f"Exception: {err_message}")
        if settings.debug:
            print_exception(*sys.exc_info())
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": err_message, "code": 0},
        )


@app.on_event("startup")
async def startup_mint():
    await start_mint_init()


app.include_router(router=router)
