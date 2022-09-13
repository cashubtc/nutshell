from ecc.curve import secp256k1, Point
from fastapi import FastAPI
from fastapi.routing import APIRouter
from fastapi.params import Depends, Query, Body

import sys
import asyncio
import logging
import uvicorn
from loguru import logger

from mint.ledger import Ledger
from mint.migrations import m001_initial
from lightning import WALLET
import core.settings as settings

from core.base import MintPayload, MintPayloads, SplitPayload

# from .app import create_app


# Ledger pubkey
ledger = Ledger("supersecretprivatekey", "data/mint")


# class MyFlaskApp(Flask):
#     """
#     We overload the Flask class so we can run a startup script (migration).
#     Stupid Flask.
#     """

#     def __init__(self, *args, **kwargs):
#         async def create_tasks_func():
#             await asyncio.wait([m001_initial(ledger.db)])
#             await ledger.load_used_proofs()

#             error_message, balance = await WALLET.status()
#             if error_message:
#                 print(
#                     f"The backend for {WALLET.__class__.__name__} isn't working properly: '{error_message}'",
#                     RuntimeWarning,
#                 )

#             print(f"Lightning balance: {balance} sat")

#             print("Mint started.")

#         loop = asyncio.get_event_loop()
#         loop.run_until_complete(create_tasks_func())
#         loop.close()

#         return super().__init__(*args, **kwargs)

#     def run(self, *args, **options):
#         super(MyFlaskApp, self).run(*args, **options)


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


app = create_app()


@app.get("/")
async def root():
    return {"Hello": "world"}


@app.get("/keys")
def keys():
    return ledger.get_pubkeys()


@app.post("/mint")
async def mint(payloads: MintPayloads):
    amounts = []
    B_s = []
    for payload in payloads.payloads:
        v = payload.dict()
        amounts.append(v["amount"])
        x = int(v["B_"]["x"])
        y = int(v["B_"]["y"])
        B_ = Point(x, y, secp256k1)
        B_s.append(B_)
    try:
        promises = await ledger.mint(B_s, amounts)
        return promises
    except Exception as exc:
        return {"error": str(exc)}


@app.post("/split")
async def split(payload: SplitPayload):
    v = payload.dict()
    proofs = v["proofs"]
    amount = v["amount"]
    output_data = v["output_data"]["payloads"]
    try:
        fst_promises, snd_promises = await ledger.split(proofs, amount, output_data)
        return {"fst": fst_promises, "snd": snd_promises}
    except Exception as exc:
        return {"error": str(exc)}


# if __name__ == "__main__":
#     uvicorn.run(app, host="127.0.0.1", port=5049)
