#!/usr/bin/env python

import asyncio
import base64
import json
import math
from datetime import datetime
from functools import wraps
from itertools import groupby
from operator import itemgetter

import click
from bech32 import bech32_decode, bech32_encode, convertbits

import core.bolt11 as bolt11
from core.base import Proof
from core.bolt11 import Invoice
from core.helpers import fee_reserve
from core.migrations import migrate_databases
from core.settings import CASHU_DIR, DEBUG, LIGHTNING, MINT_URL
from wallet import migrations
from wallet.crud import get_reserved_proofs
from wallet.wallet import Wallet as Wallet


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
def cli(ctx, host: str, walletname: str):
    ctx.ensure_object(dict)
    ctx.obj["HOST"] = host
    ctx.obj["WALLET_NAME"] = walletname
    ctx.obj["WALLET"] = Wallet(ctx.obj["HOST"], f"{CASHU_DIR}/{walletname}", walletname)
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
async def balance(ctx):
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
    token = await wallet.serialize_proofs(send_proofs)
    print(token)
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
@click.argument("token", required=False, type=str)
@click.option("--all", "-a", default=False, is_flag=True, help="Burn all spent tokens.")
@click.option(
    "--force", "-f", default=False, is_flag=True, help="Force check on all tokens."
)
@click.pass_context
@coro
async def burn(ctx, token: str, all: bool, force: bool):
    wallet: Wallet = ctx.obj["WALLET"]
    await init_wallet(wallet)
    if not (all or token or force) or (token and all):
        print(
            "Error: enter a token or use --all to burn all pending tokens or --force to check all tokens."
        )
        return
    if all:
        # check only those who are flagged as reserved
        proofs = await get_reserved_proofs(wallet.db)
    elif force:
        # check all proofs in db
        proofs = wallet.proofs
    else:
        # check only the specified ones
        proofs = [
            Proof.from_dict(p) for p in json.loads(base64.urlsafe_b64decode(token))
        ]
    wallet.status()
    await wallet.invalidate(proofs)
    wallet.status()


@cli.command("pending", help="Show pending tokens.")
@click.pass_context
@coro
async def pending(ctx):
    wallet: Wallet = ctx.obj["WALLET"]
    await init_wallet(wallet)
    reserved_proofs = await get_reserved_proofs(wallet.db)
    if len(reserved_proofs):
        sorted_proofs = sorted(reserved_proofs, key=itemgetter("send_id"))
        for key, value in groupby(sorted_proofs, key=itemgetter("send_id")):
            grouped_proofs = list(value)
            token = await wallet.serialize_proofs(grouped_proofs)
            reserved_date = datetime.utcfromtimestamp(
                int(grouped_proofs[0].time_reserved)
            ).strftime("%Y-%m-%d %H:%M:%S")
            print(
                f"Amount: {sum([p['amount'] for p in grouped_proofs])} sat Sent: {reserved_date} ID: {key}\n"
            )
            print(token)
            print("")
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
        (decoded_invoice.amount_msat + fee_reserve(decoded_invoice.amount_msat)) / 1000
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
    wallet.status()


@cli.command("info", help="Information about Cashu wallet.")
@click.pass_context
@coro
async def info(ctx):
    wallet: Wallet = ctx.obj["WALLET"]
    await init_wallet(wallet)
    wallet.status()
    print(f"Debug: {DEBUG}")
    print(f"Cashu dir: {CASHU_DIR}")
    print(f"Mint URL: {MINT_URL}")
    return
