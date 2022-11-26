#!/usr/bin/env python

import asyncio
import base64
import json
import os
import sys
import time
from datetime import datetime
from functools import wraps
from itertools import groupby
from operator import itemgetter
from os import listdir
from os.path import isdir, join

import click
from loguru import logger

from cashu.core.base import Proof
from cashu.core.helpers import sum_proofs
from cashu.core.migrations import migrate_databases
from cashu.core.settings import (
    CASHU_DIR,
    DEBUG,
    ENV_FILE,
    LIGHTNING,
    MINT_URL,
    SOCKS_HOST,
    SOCKS_PORT,
    TOR,
    VERSION,
)
from cashu.tor.tor import TorProxy
from cashu.wallet import migrations
from cashu.wallet.crud import (
    get_lightning_invoices,
    get_reserved_proofs,
    get_unused_locks,
)
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
@click.option("--host", "-h", default=MINT_URL, help=f"Mint URL (default: {MINT_URL}).")
@click.option(
    "--wallet",
    "-w",
    "walletname",
    default="wallet",
    help="Wallet name (default: wallet).",
)
@click.pass_context
def cli(ctx, host: str, walletname: str):
    # configure logger
    logger.remove()
    logger.add(sys.stderr, level="DEBUG" if DEBUG else "INFO")
    ctx.ensure_object(dict)
    ctx.obj["HOST"] = host
    ctx.obj["WALLET_NAME"] = walletname
    wallet = Wallet(ctx.obj["HOST"], os.path.join(CASHU_DIR, walletname))

    if TOR and not TorProxy().check_platform():
        error_str = "Your settings say TOR=true but the built-in Tor bundle is not supported on your system. Please install Tor manually and set TOR=false and SOCKS_HOST=localhost and SOCKS_PORT=9050 in your Cashu config (recommended) or turn off Tor by setting TOR=false (not recommended). Cashu will not work until you edit your config file accordingly."
        error_str += "\n\n"
        if ENV_FILE:
            error_str += f"Edit your Cashu config file here: {ENV_FILE}"
        else:
            error_str += (
                f"Ceate a new Cashu config file here: {os.path.join(CASHU_DIR, '.env')}"
            )
        raise Exception(error_str)

    ctx.obj["WALLET"] = wallet
    asyncio.run(init_wallet(wallet))
    pass


# https://github.com/pallets/click/issues/85#issuecomment-503464628
def coro(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper


@cli.command("pay", help="Pay Lightning invoice.")
@click.argument("invoice", type=str)
@click.option(
    "--yes", "-y", default=False, is_flag=True, help="Skip confirmation.", type=bool
)
@click.pass_context
@coro
async def pay(ctx, invoice: str, yes: bool):
    wallet: Wallet = ctx.obj["WALLET"]
    await wallet.load_mint()
    wallet.status()
    amount, fees = await wallet.get_pay_amount_with_fees(invoice)
    if not yes:
        click.confirm(
            f"Pay {amount - fees} sat ({amount} sat incl. fees)?",
            abort=True,
            default=True,
        )

    print(f"Paying Lightning invoice ...")
    assert amount > 0, "amount is not positive"
    if wallet.available_balance < amount:
        print("Error: Balance too low.")
        return
    _, send_proofs = await wallet.split_to_send(wallet.proofs, amount)
    await wallet.pay_lightning(send_proofs, invoice)
    wallet.status()


@cli.command("invoice", help="Create Lighting invoice.")
@click.argument("amount", type=int)
@click.option("--hash", default="", help="Hash of the paid invoice.", type=str)
@click.pass_context
@coro
async def invoice(ctx, amount: int, hash: str):
    wallet: Wallet = ctx.obj["WALLET"]
    await wallet.load_mint()
    wallet.status()
    if not LIGHTNING:
        r = await wallet.mint(amount)
    elif amount and not hash:
        invoice = await wallet.request_mint(amount)
        if invoice.pr:
            print(f"Pay invoice to mint {amount} sat:")
            print("")
            print(f"Invoice: {invoice.pr}")
            print("")
            print(
                f"Execute this command if you abort the check:\ncashu invoice {amount} --hash {invoice.hash}"
            )
            check_until = time.time() + 5 * 60  # check for five minutes
            print("")
            print(
                f"Checking invoice ...",
                end="",
                flush=True,
            )
            paid = False
            while time.time() < check_until and not paid:
                time.sleep(3)
                try:
                    await wallet.mint(amount, invoice.hash)
                    paid = True
                    print(" Invoice paid.")
                except Exception as e:
                    # TODO: user error codes!
                    if str(e) == "Error: Lightning invoice not paid yet.":
                        print(".", end="", flush=True)
                        continue
    elif amount and hash:
        await wallet.mint(amount, hash)
    wallet.status()
    return


@cli.command("balance", help="Balance.")
@click.option(
    "--verbose",
    "-v",
    default=False,
    is_flag=True,
    help="Show pending tokens as well.",
    type=bool,
)
@click.pass_context
@coro
async def balance(ctx, verbose):
    wallet: Wallet = ctx.obj["WALLET"]
    keyset_balances = wallet.balance_per_keyset()
    if len(keyset_balances) > 1:
        print(f"You have balances in {len(keyset_balances)} keysets:")
        print("")
        for k, v in keyset_balances.items():
            print(
                f"Keyset: {k or 'undefined'} Balance: {v['balance']} sat (available: {v['available']} sat)"
            )
        print("")
    if verbose:
        print(
            f"Balance: {wallet.balance} sat (available: {wallet.available_balance} sat in {len([p for p in wallet.proofs if not p.reserved])} tokens)"
        )
    else:
        print(f"Balance: {wallet.available_balance} sat")


@cli.command("send", help="Send tokens.")
@click.argument("amount", type=int)
@click.option("--lock", "-l", default=None, help="Lock tokens (P2SH).", type=str)
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
    await wallet.load_mint()
    wallet.status()
    _, send_proofs = await wallet.split_to_send(
        wallet.proofs, amount, lock, set_reserved=True
    )
    token = await wallet.serialize_proofs(
        send_proofs, hide_secrets=True if lock and not p2sh else False
    )
    print(token)
    wallet.status()


@cli.command("receive", help="Receive tokens.")
@click.argument("token", type=str)
@click.option("--lock", "-l", default=None, help="Unlock tokens.", type=str)
@click.pass_context
@coro
async def receive(ctx, token: str, lock: str):
    wallet: Wallet = ctx.obj["WALLET"]
    await wallet.load_mint()
    wallet.status()
    if lock:
        # load the script and signature of this address from the database
        assert len(lock.split("P2SH:")) == 2, Exception(
            "lock has wrong format. Expected P2SH:<address>."
        )
        address_split = lock.split("P2SH:")[1]

        p2shscripts = await get_unused_locks(address_split, db=wallet.db)
        assert len(p2shscripts) == 1, Exception("lock not found.")
        script = p2shscripts[0].script
        signature = p2shscripts[0].signature
    else:
        script, signature = None, None
    proofs = [Proof(**p) for p in json.loads(base64.urlsafe_b64decode(token))]
    _, _ = await wallet.redeem(proofs, scnd_script=script, scnd_siganture=signature)
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
    await wallet.load_mint()
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
        proofs = [Proof(**p) for p in json.loads(base64.urlsafe_b64decode(token))]
    wallet.status()
    await wallet.invalidate(proofs)
    wallet.status()


@cli.command("pending", help="Show pending tokens.")
@click.pass_context
@coro
async def pending(ctx):
    wallet: Wallet = ctx.obj["WALLET"]
    await wallet.load_mint()
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
                f"#{i} Amount: {sum_proofs(grouped_proofs)} sat Time: {reserved_date} ID: {key}\n"
            )
            print(f"With secret: {token}\n\nSecretless: {token_hidden_secret}\n")
            print(f"--------------------------\n")
    wallet.status()


@cli.command("lock", help="Generate receiving lock.")
@click.pass_context
@coro
async def lock(ctx):
    wallet: Wallet = ctx.obj["WALLET"]
    p2shscript = await wallet.create_p2sh_lock()
    txin_p2sh_address = p2shscript.address
    print("---- Pay to script hash (P2SH) ----\n")
    print("Use a lock to receive tokens that only you can unlock.")
    print("")
    print(f"Public receiving lock: P2SH:{txin_p2sh_address}")
    print("")
    print(
        f"Anyone can send tokens to this lock:\n\ncashu send <amount> --lock P2SH:{txin_p2sh_address}"
    )
    print("")
    print(
        f"Only you can receive tokens from this lock:\n\ncashu receive <token> --lock P2SH:{txin_p2sh_address}\n"
    )


@cli.command("locks", help="Show unused receiving locks.")
@click.pass_context
@coro
async def locks(ctx):
    wallet: Wallet = ctx.obj["WALLET"]
    locks = await get_unused_locks(db=wallet.db)
    if len(locks):
        print("")
        print(f"--------------------------\n")
        for l in locks:
            print(f"Address: {l.address}")
            print(f"Script: {l.script}")
            print(f"Signature: {l.signature}")
            print("")
            print(f"Receive: cashu receive <token> --lock P2SH:{l.address}")
            print("")
            print(f"--------------------------\n")
    else:
        print("No locks found. Create one using: cashu lock")
    return True


@cli.command("invoices", help="List of all pending invoices.")
@click.pass_context
@coro
async def invoices(ctx):
    wallet: Wallet = ctx.obj["WALLET"]
    invoices = await get_lightning_invoices(db=wallet.db)
    if len(invoices):
        print("")
        print(f"--------------------------\n")
        for invoice in invoices:
            print(f"Paid: {invoice.paid}")
            print(f"Incoming: {invoice.amount > 0}")
            print(f"Amount: {abs(invoice.amount)}")
            if invoice.hash:
                print(f"Hash: {invoice.hash}")
            if invoice.preimage:
                print(f"Preimage: {invoice.preimage}")
            if invoice.time_created:
                d = datetime.utcfromtimestamp(
                    int(float(invoice.time_created))
                ).strftime("%Y-%m-%d %H:%M:%S")
                print(f"Created: {d}")
            if invoice.time_paid:
                d = datetime.utcfromtimestamp(int(float(invoice.time_paid))).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                print(f"Paid: {d}")
            print("")
            print(f"Payment request: {invoice.pr}")
            print("")
            print(f"--------------------------\n")
    else:
        print("No invoices found.")


@cli.command("wallets", help="List of all available wallets.")
@click.pass_context
@coro
async def wallets(ctx):
    # list all directories
    wallets = [d for d in listdir(CASHU_DIR) if isdir(join(CASHU_DIR, d))]
    try:
        wallets.remove("mint")
    except ValueError:
        pass
    for w in wallets:
        wallet = Wallet(ctx.obj["HOST"], os.path.join(CASHU_DIR, w))
        try:
            await init_wallet(wallet)
            if wallet.proofs and len(wallet.proofs):
                active_wallet = False
                if w == ctx.obj["WALLET_NAME"]:
                    active_wallet = True
                print(
                    f"Wallet: {w}\tBalance: {sum_proofs(wallet.proofs)} sat (available: {sum_proofs([p for p in wallet.proofs if not p.reserved])} sat){' *' if active_wallet else ''}"
                )
        except:
            pass


@cli.command("info", help="Information about Cashu wallet.")
@click.pass_context
@coro
async def info(ctx):
    print(f"Version: {VERSION}")
    print(f"Wallet: {ctx.obj['WALLET_NAME']}")
    if DEBUG:
        print(f"Debug: {DEBUG}")
    print(f"Cashu dir: {CASHU_DIR}")
    if ENV_FILE:
        print(f"Settings: {ENV_FILE}")
    if TOR:
        print(f"Tor enabled: {TOR}")
    if SOCKS_HOST:
        print(f"Socks proxy: {SOCKS_HOST}:{SOCKS_PORT}")
    print(f"Mint URL: {MINT_URL}")
    return
