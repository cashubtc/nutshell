import asyncio
import logging
import sys
from ast import Param
from typing import Union

from ecc.curve import Point, secp256k1
from fastapi import FastAPI
from fastapi.params import Body, Depends, Query
from fastapi.routing import APIRouter
from loguru import logger

import core.settings as settings
from core.base import MintPayloads, SplitPayload
from core.settings import MINT_PRIVATE_KEY
from lightning import WALLET
from mint.ledger import Ledger
from mint.migrations import m001_initial

ledger = Ledger(MINT_PRIVATE_KEY, "data/mint")


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


@app.get("/keys")
def keys():
    """Get the public keys of the mint"""
    return ledger.get_pubkeys()


@app.get("/mint")
async def request_mint(amount: int = 0):
    """Request minting of tokens. Server responds with a Lightning invoice."""
    payment_request, payment_hash = await ledger.request_mint(amount)
    print(f"Lightning invoice: {payment_request}")
    return {"pr": payment_request, "hash": payment_hash}


@app.post("/mint")
async def mint(payloads: MintPayloads, payment_hash: Union[str, None] = None):
    """
    Requests the minting of tokens belonging to a paid payment request.

    Parameters:
    pr: payment_request of the Lightning paid invoice.

    Body (JSON):
    payloads: contains a list of blinded messages waiting to be signed.

    NOTE:
    - This needs to be replaced by the preimage otherwise someone knowing
        the payment_request can request the tokens instead of the rightful
        owner.
    - The blinded message should ideally be provided to the server *before* payment
        in the GET /mint endpoint so that the server knows to sign only these tokens
        when the invoice is paid.
    """
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
        promises = await ledger.mint(B_s, amounts, payment_hash=payment_hash)
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
