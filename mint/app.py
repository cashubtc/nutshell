import asyncio
import logging
import sys
from typing import Union


from fastapi import FastAPI
from loguru import logger
from secp256k1 import PublicKey

import core.settings as settings
from core.settings import (
    CASHU_DIR,
)
from lightning import WALLET
from mint.ledger import Ledger
from mint.migrations import m001_initial

from . import ledger


def startup(app: FastAPI):
    @app.on_event("startup")
    async def load_ledger():
        await asyncio.wait([m001_initial(ledger.db)])
        await ledger.load_used_proofs()

        error_message, balance = await WALLET.status()
        if error_message:
            logger.warning(
                f"The backend for {WALLET.__class__.__name__} isn't working properly: '{error_message}'",
                RuntimeWarning,
            )

        logger.info(f"Lightning balance: {balance} sat")
        logger.info(f"Data dir: {CASHU_DIR}")
        logger.info("Mint started.")


def create_app(config_object="core.settings") -> FastAPI:
    def configure_logger() -> None:
        class Formatter:
            def __init__(self):
                self.padding = 0
                self.minimal_fmt: str = "<green>{time:YYYY-MM-DD HH:mm:ss.SS}</green> | <level>{level}</level> | <level>{message}</level>\n"
                if settings.DEBUG:
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
        log_level: str = "INFO"
        formatter = Formatter()
        logger.add(sys.stderr, level=log_level, format=formatter.format)

        logging.getLogger("uvicorn").handlers = [InterceptHandler()]
        logging.getLogger("uvicorn.access").handlers = [InterceptHandler()]

    configure_logger()

    app = FastAPI(
        title="Cashu Mint",
        description="Ecash wallet and mint.",
        license_info={
            "name": "MIT License",
            "url": "https://raw.githubusercontent.com/callebtc/cashu/main/LICENSE",
        },
    )

    startup(app)
    return app


# if __name__ == "__main__":
#     main()
