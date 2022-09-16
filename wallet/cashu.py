#!/usr/bin/env python

import asyncio
import base64
import json
import math
from functools import wraps

import click
from bech32 import bech32_decode, bech32_encode, convertbits

from core.settings import MINT_URL, LIGHTNING, LIGHTNING_FEE
from core.migrations import migrate_databases
from core.base import Proof
import core.bolt11 as bolt11
from core.bolt11 import Invoice
from wallet.wallet import Wallet as Wallet
from wallet import migrations


async def init_wallet(wallet: Wallet):
    """Performs migrations and loads proofs from db."""
    await migrate_databases(wallet.db, migrations)
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
    await init_wallet(wallet)
    wallet.status()
    if not LIGHTNING:
        r = await wallet.mint(amount)
    elif amount and not hash:
        r = await wallet.request_mint(amount)
        if "pr" in r:
            print(f"Pay this invoice to mint {amount} sat:")
            print(f"Invoice: {r['pr']}")
            print("")
            print(
                f"After paying the invoice, run this command:\ncashu mint {amount} --hash {r['hash']}"
            )
    elif amount and hash:
        await wallet.mint(amount, hash)
    wallet.status()
    return


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
    _, send_proofs = await wallet.split_to_send(wallet.proofs, amount)
    await wallet.set_reserved(send_proofs, reserved=True)
    proofs_serialized = [p.dict() for p in send_proofs]
    print(base64.urlsafe_b64encode(json.dumps(proofs_serialized).encode()).decode())
    wallet.status()


@cli.command("receive", help="Receive tokens.")
@click.argument("token", type=str)
@click.pass_context
@coro
async def receive(ctx, token: str):
    wallet: Wallet = ctx.obj["WALLET"]
    await init_wallet(wallet)
    wallet.status()
    proofs = [Proof.from_dict(p) for p in json.loads(base64.urlsafe_b64decode(token))]
    _, _ = await wallet.redeem(proofs)
    wallet.status()


@cli.command("burn", help="Burn spent tokens.")
@click.argument("token", type=str)
@click.pass_context
@coro
async def burn(ctx, token: str):
    wallet: Wallet = ctx.obj["WALLET"]
    await init_wallet(wallet)
    wallet.status()
    proofs = [Proof.from_dict(p) for p in json.loads(base64.urlsafe_b64decode(token))]
    await wallet.invalidate(proofs)
    wallet.status()


@cli.command("pay", help="Pay lightning invoice.")
@click.argument("invoice", type=str)
@click.pass_context
@coro
async def pay(ctx, invoice: str):
    wallet: Wallet = ctx.obj["WALLET"]
    await init_wallet(wallet)
    wallet.status()
    decoded_invoice: Invoice = bolt11.decode(invoice)
    amount = math.ceil(
        decoded_invoice.amount_msat / 1000 * LIGHTNING_FEE
    )  # 1% fee for Lightning
    print(
        f"Paying Lightning invoice of {decoded_invoice.amount_msat // 1000} sat ({amount} sat incl. fees)"
    )
    assert amount > 0, "amount is not positive"
    if wallet.available_balance < amount:
        print("Error: Balance too low.")
        return
    _, send_proofs = await wallet.split_to_send(wallet.proofs, amount)
    await wallet.pay_lightning(send_proofs, amount, invoice)
    print("Invoice paid.")
    wallet.status()
