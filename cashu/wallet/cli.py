#!/usr/bin/env python

import asyncio
import base64
import json
import math
import sys
from datetime import datetime
from functools import wraps
from itertools import groupby
from operator import itemgetter

import click
from bech32 import bech32_decode, bech32_encode, convertbits
from loguru import logger

import cashu.core.bolt11 as bolt11
from cashu.core.base import Proof
from cashu.core.bolt11 import Invoice
from cashu.core.helpers import fee_reserve
from cashu.core.migrations import migrate_databases
from cashu.core.script import *
from cashu.core.settings import CASHU_DIR, DEBUG, LIGHTNING, MINT_URL, VERSION, ENV_FILE
from cashu.wallet import migrations
from cashu.wallet.crud import get_reserved_proofs
from cashu.wallet.wallet import Wallet as Wallet


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
    # configure logger
    logger.remove()
    logger.add(sys.stderr, level="DEBUG" if DEBUG else "INFO")
    ctx.ensure_object(dict)
    ctx.obj["HOST"] = host
    ctx.obj["WALLET_NAME"] = walletname
    wallet = Wallet(ctx.obj["HOST"], f"{CASHU_DIR}/{walletname}", walletname)
    ctx.obj["WALLET"] = wallet
    asyncio.run(init_wallet(wallet))
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
    wallet.load_mint()
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
    wallet.status()


@cli.command("send", help="Send tokens.")
@click.argument("amount", type=int)
@click.option("--lock", "-l", default=None, help="Token lock (P2SH address).", type=str)
@click.pass_context
@coro
async def send(ctx, amount: int, lock: str):
    if lock and len(lock) < 22:
        print("Error: lock has to be at least 22 characters long.")
        return
    p2sh = False
    if lock and len(lock.split("P2SH:")) == 2:
        p2sh = True
    wallet: Wallet = ctx.obj["WALLET"]
    wallet.load_mint()
    wallet.status()
    _, send_proofs = await wallet.split_to_send(wallet.proofs, amount, lock)
    await wallet.set_reserved(send_proofs, reserved=True)
    token = await wallet.serialize_proofs(
        send_proofs, hide_secrets=True if lock and not p2sh else False
    )
    print(token)
    wallet.status()


@cli.command("receive", help="Receive tokens.")
@click.argument("token", type=str)
# @click.option("--secret", "-s", default=None, help="Token secret.", type=str)
@click.option("--unlock", "-u", default=None, help="Unlock script.", type=str)
# @click.option("--signature", default=None, help="Script signature.", type=str)
@click.pass_context
@coro
async def receive(ctx, token: str, unlock: str):
    wallet: Wallet = ctx.obj["WALLET"]
    wallet.load_mint()
    wallet.status()
    if unlock:
        assert (
            len(unlock.split(":")) == 2
        ), "unlock format wrong, expected <script>:<signature>"
        script = unlock.split(":")[0]
        signature = unlock.split(":")[1]
    proofs = [Proof.from_dict(p) for p in json.loads(base64.urlsafe_b64decode(token))]
    _, _ = await wallet.redeem(proofs, snd_script=script, snd_siganture=signature)
    wallet.status()


@cli.command("address", help="Generate receiving address.")
@click.pass_context
@coro
async def address(ctx):
    alice_privkey = step0_carol_privkey()
    txin_redeemScript = step0_carol_checksig_redeemscrip(alice_privkey.pub)
    txin_p2sh_address = step1_carol_create_p2sh_address(txin_redeemScript)
    # print("Redeem script:", txin_redeemScript.__repr__())
    print("---- Pay to script hash (P2SH) ----\n")
    print("You can use this address to receive tokens that only you can redeem.")
    print("")
    print(f"Public receiving address: P2SH:{txin_p2sh_address}")
    print("")
    print(
        f"To send to this address:\n\ncashu send <amount> --lock P2SH:{txin_p2sh_address}"
    )
    print("")

    txin_signature = step2_carol_sign_tx(txin_redeemScript, alice_privkey).scriptSig
    txin_redeemScript_b64 = base64.urlsafe_b64encode(txin_redeemScript).decode()
    txin_signature_b64 = base64.urlsafe_b64encode(txin_signature).decode()
    print("!!! The command below is private. Do not share. Back it up. !!!")
    print(
        "If you lose this command (script and signature), you will not\nbe able to redeem tokens sent to this address!\n\n"
    )
    print(
        f"To receive:\n\ncashu receive <token> --unlock {txin_redeemScript_b64}:{txin_signature_b64}\n"
    )


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
    wallet.load_mint()
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
    wallet.load_mint()
    reserved_proofs = await get_reserved_proofs(wallet.db)
    if len(reserved_proofs):
        print(f"--------------------------\n")
        sorted_proofs = sorted(reserved_proofs, key=itemgetter("send_id"))
        for i, (key, value) in enumerate(
            groupby(sorted_proofs, key=itemgetter("send_id"))
        ):
            grouped_proofs = list(value)
            token = await wallet.serialize_proofs(grouped_proofs)
            token_hidden_secret = await wallet.serialize_proofs(
                grouped_proofs, hide_secrets=True
            )
            reserved_date = datetime.utcfromtimestamp(
                int(grouped_proofs[0].time_reserved)
            ).strftime("%Y-%m-%d %H:%M:%S")
            print(
                f"#{i} Amount: {sum([p['amount'] for p in grouped_proofs])} sat Time: {reserved_date} ID: {key}\n"
            )
            print(f"With secret: {token}\n\nSecretless: {token_hidden_secret}\n")
            print(f"--------------------------\n")
    wallet.status()


@cli.command("pay", help="Pay lightning invoice.")
@click.argument("invoice", type=str)
@click.pass_context
@coro
async def pay(ctx, invoice: str):
    wallet: Wallet = ctx.obj["WALLET"]
    wallet.load_mint()
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
    print(f"Version: {VERSION}")
    print(f"Debug: {DEBUG}")
    print(f"Cashu dir: {CASHU_DIR}")
    if ENV_FILE:
        print(f"Settings: {ENV_FILE}")
    print(f"Wallet: {ctx.obj['WALLET_NAME']}")
    print(f"Mint URL: {MINT_URL}")
    return
