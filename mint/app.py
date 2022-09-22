import asyncio
import logging
import sys
from typing import Union

import click
import uvicorn
from fastapi import FastAPI
from loguru import logger
from secp256k1 import PublicKey

import core.settings as settings
from core.base import CheckPayload, MeltPayload, MintPayloads, SplitPayload
from core.settings import (CASHU_DIR, MINT_PRIVATE_KEY, MINT_SERVER_HOST,
                           MINT_SERVER_PORT)
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
    for payload in payloads.blinded_messages:
        amounts.append(payload.amount)
        B_s.append(PublicKey(bytes.fromhex(payload.B_), raw=True))
    try:
        promises = await ledger.mint(B_s, amounts, payment_hash=payment_hash)
        return promises
    except Exception as exc:
        return {"error": str(exc)}


@app.post("/melt")
async def melt(payload: MeltPayload):
    """
    Requests tokens to be destroyed and sent out via Lightning.
    """
    ok, preimage = await ledger.melt(payload.proofs, payload.amount, payload.invoice)
    return {"paid": ok, "preimage": preimage}


@app.post("/check")
async def check_spendable(payload: CheckPayload):
    return await ledger.check_spendable(payload.proofs)


@app.post("/split")
async def split(payload: SplitPayload):
    """
    Requetst a set of tokens with amount "total" to be split into two
    newly minted sets with amount "split" and "total-split".
    """
    proofs = payload.proofs
    amount = payload.amount
    output_data = payload.output_data.blinded_messages
    try:
        split_return = await ledger.split(proofs, amount, output_data)
    except Exception as exc:
        return {"error": str(exc)}
    if not split_return:
        """There was a problem with the split"""
        raise Exception("could not split tokens.")
    fst_promises, snd_promises = split_return
    return {"fst": fst_promises, "snd": snd_promises}


@click.command(
    context_settings=dict(
        ignore_unknown_options=True,
        allow_extra_args=True,
    )
)
@click.option("--port", default=MINT_SERVER_PORT, help="Port to listen on")
@click.option("--host", default=MINT_SERVER_HOST, help="Host to run mint on")
@click.option("--ssl-keyfile", default=None, help="Path to SSL keyfile")
@click.option("--ssl-certfile", default=None, help="Path to SSL certificate")
@click.pass_context
def main(
    ctx,
    port: int = MINT_SERVER_PORT,
    host: str = MINT_SERVER_HOST,
    ssl_keyfile: str = None,
    ssl_certfile: str = None,
):
    """Launched with `poetry run mint` at root level"""
    # this beautiful beast parses all command line arguments and passes them to the uvicorn server
    d = dict()
    for a in ctx.args:
        item = a.split("=")
        if len(item) > 1:  # argument like --key=value
            print(a, item)
            d[item[0].strip("--").replace("-", "_")] = (
                int(item[1])  # need to convert to int if it's a number
                if item[1].isdigit()
                else item[1]
            )
        else:
            d[a.strip("--")] = True  # argument like --key

    config = uvicorn.Config(
        "mint.app:app",
        port=port,
        host=host,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
        **d,
    )
    server = uvicorn.Server(config)
    server.run()


if __name__ == "__main__":
    main()
