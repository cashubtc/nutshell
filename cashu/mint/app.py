import asyncio
import logging
import sys

from fastapi import FastAPI
from loguru import logger

from cashu.core.settings import DEBUG, VERSION
from cashu.lightning import WALLET
from cashu.mint.migrations import m001_initial

from . import ledger
from .router import router
from .startup import load_ledger


def create_app(config_object="core.settings") -> FastAPI:
    def configure_logger() -> None:
        class Formatter:
            def __init__(self):
                self.padding = 0
                self.minimal_fmt: str = "<green>{time:YYYY-MM-DD HH:mm:ss.SS}</green> | <level>{level}</level> | <level>{message}</level>\n"
                if DEBUG:
                    self.fmt: str = "<green>{time:YYYY-MM-DD HH:mm:ss.SS}</green> | <level>{level: <4}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | <level>{message}</level>\n"
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
        log_level: str = "DEBUG" if DEBUG else "INFO"
        formatter = Formatter()
        logger.add(sys.stderr, level=log_level, format=formatter.format)

        logging.getLogger("uvicorn").handlers = [InterceptHandler()]
        logging.getLogger("uvicorn.access").handlers = [InterceptHandler()]

    configure_logger()

    app = FastAPI(
        title="Cashu Mint",
        description="Ecash wallet and mint with Bitcoin Lightning support.",
        version=VERSION,
        license_info={
            "name": "MIT License",
            "url": "https://raw.githubusercontent.com/callebtc/cashu/main/LICENSE",
        },
    )

    return app


app = create_app()

app.include_router(router=router)


@app.on_event("startup")
async def startup_load_ledger():
    await load_ledger()
