#!/usr/bin/env python

import asyncio
import base64
import json
from functools import wraps

import click
from bech32 import bech32_decode, bech32_encode, convertbits

from core.settings import MINT_URL
from wallet.migrations import m001_initial
from wallet.wallet import Wallet as Wallet


async def init_wallet(wallet: Wallet):
    """Performs migrations and loads proofs from db."""
    await m001_initial(db=wallet.db)
    await wallet.load_proofs()


class NaturalOrderGroup(click.Group):
    """For listing commands in help in order of definition"""

    def list_commands(self, ctx):
        return self.commands.keys()


@click.group(cls=NaturalOrderGroup)
@click.option("--host", "-h", default=MINT_URL, help="Mint address.")
@click.option("--wallet", "-w", "walletname", default="wallet", help="Wallet to use.")
@click.pass_context
def cli(
    ctx,
    host: str,
    walletname: str,
):
    ctx.ensure_object(dict)
    ctx.obj["HOST"] = host
    ctx.obj["WALLET_NAME"] = walletname
    ctx.obj["WALLET"] = Wallet(ctx.obj["HOST"], f"data/{walletname}", walletname)
    pass


# https://github.com/pallets/click/issues/85#issuecomment-503464628
def coro(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper


@cli.command("mint", help="Mint tokens.")
@click.argument("amount", type=int)
@click.option("--hash", default="", help="Hash of the paid invoice.", type=str)
@click.pass_context
@coro
async def mint(ctx, amount: int, hash: str):
    wallet: Wallet = ctx.obj["WALLET"]
    await m001_initial(db=wallet.db)
    await wallet.load_proofs()
    if amount and not hash:
        print(f"Balance: {wallet.balance}")
        r = await wallet.request_mint(amount)
        print(r)

    if amount and hash:
        print(f"Balance: {wallet.balance}")
        await wallet.mint(amount, hash)
        print(f"Balance: {wallet.balance}")


@cli.command("balance", help="See balance.")
@click.pass_context
@coro
async def receive(ctx):
    wallet: Wallet = ctx.obj["WALLET"]
    await init_wallet(wallet)
    wallet.status()


@cli.command("send", help="Send tokens.")
@click.argument("amount", type=int)
@click.pass_context
@coro
async def send(ctx, amount: int):
    wallet: Wallet = ctx.obj["WALLET"]
    await init_wallet(wallet)
    wallet.status()
    _, send_proofs = await wallet.split(wallet.proofs, amount)
    print(base64.urlsafe_b64encode(json.dumps(send_proofs).encode()).decode())


@cli.command("receive", help="Receive tokens.")
@click.argument("token", type=str)
@click.pass_context
@coro
async def receive(ctx, token: str):
    wallet: Wallet = ctx.obj["WALLET"]
    await init_wallet(wallet)
    wallet.status()
    proofs = json.loads(base64.urlsafe_b64decode(token))
    _, _ = await wallet.redeem(proofs)
    wallet.status()


@cli.command("burn", help="Burn spent tokens.")
@click.argument("token", type=str)
@click.pass_context
@coro
async def receive(ctx, token: str):
    wallet: Wallet = ctx.obj["WALLET"]
    await init_wallet(wallet)
    wallet.status()
    proofs = json.loads(base64.urlsafe_b64decode(token))
    await wallet.invalidate(proofs)
    wallet.status()
