#!/usr/bin/env python

import asyncio
import os
import time
from datetime import datetime
from functools import wraps
from itertools import groupby, islice
from operator import itemgetter
from os import listdir
from os.path import isdir, join

import click
from click import Context
from loguru import logger

from ...core.base import TokenV3
from ...core.helpers import sum_proofs
from ...core.settings import settings
from ...nostr.nostr.client.client import NostrClient
from ...tor.tor import TorProxy
from ...wallet.crud import get_lightning_invoices, get_reserved_proofs, get_unused_locks
from ...wallet.wallet import Wallet as Wallet
from ..api.api_server import start_api_server
from ..cli.cli_helpers import get_mint_wallet, print_mint_balances, verify_mint
from ..helpers import deserialize_token_from_string, init_wallet, receive, send
from ..nostr import receive_nostr, send_nostr


class NaturalOrderGroup(click.Group):
    """For listing commands in help in order of definition"""

    def list_commands(self, ctx):
        return self.commands.keys()


def run_api_server(ctx, param, daemon):
    if not daemon:
        return
    start_api_server()
    ctx.exit()


@click.group(cls=NaturalOrderGroup)
@click.option(
    "--host",
    "-h",
    default=None,
    help=f"Mint URL (default: {settings.mint_url}).",
)
@click.option(
    "--wallet",
    "-w",
    "walletname",
    default=settings.wallet_name,
    help=f"Wallet name (default: {settings.wallet_name}).",
)
@click.option(
    "--daemon",
    "-d",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=run_api_server,
    help="Start server for wallet REST API",
)
@click.pass_context
def cli(ctx: Context, host: str, walletname: str):
    if settings.tor and not TorProxy().check_platform():
        error_str = "Your settings say TOR=true but the built-in Tor bundle is not supported on your system. You have two options: Either install Tor manually and set TOR=FALSE and SOCKS_HOST=localhost and SOCKS_PORT=9050 in your Cashu config (recommended). Or turn off Tor by setting TOR=false (not recommended). Cashu will not work until you edit your config file accordingly."
        error_str += "\n\n"
        if settings.env_file:
            error_str += f"Edit your Cashu config file here: {settings.env_file}"
            env_path = settings.env_file
        else:
            error_str += f"Ceate a new Cashu config file here: {os.path.join(settings.cashu_dir, '.env')}"
            env_path = os.path.join(settings.cashu_dir, ".env")
        error_str += f'\n\nYou can turn off Tor with this command: echo "TOR=FALSE" >> {env_path}'
        raise Exception(error_str)

    ctx.ensure_object(dict)
    ctx.obj["HOST"] = host or settings.mint_url
    ctx.obj["WALLET_NAME"] = walletname
    wallet = Wallet(
        ctx.obj["HOST"], os.path.join(settings.cashu_dir, walletname), name=walletname
    )
    ctx.obj["WALLET"] = wallet
    asyncio.run(init_wallet(ctx.obj["WALLET"], load_proofs=False))

    # MUTLIMINT: Select a wallet
    # only if a command is one of a subset that needs to specify a mint host
    # if a mint host is already specified as an argument `host`, use it
    if ctx.invoked_subcommand not in ["send", "invoice", "pay"] or host:
        return
    # else: we ask the user to select one
    ctx.obj["WALLET"] = asyncio.run(
        get_mint_wallet(ctx)
    )  # select a specific wallet by CLI input
    asyncio.run(init_wallet(ctx.obj["WALLET"], load_proofs=False))


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
async def pay(ctx: Context, invoice: str, yes: bool):
    wallet: Wallet = ctx.obj["WALLET"]
    await wallet.load_mint()
    wallet.status()
    total_amount, fee_reserve_sat = await wallet.get_pay_amount_with_fees(invoice)
    if not yes:
        click.confirm(
            f"Pay {total_amount - fee_reserve_sat} sat ({total_amount} sat with potential fees)?",
            abort=True,
            default=True,
        )

    print(f"Paying Lightning invoice ...")
    assert total_amount > 0, "amount is not positive"
    if wallet.available_balance < total_amount:
        print("Error: Balance too low.")
        return
    _, send_proofs = await wallet.split_to_send(wallet.proofs, total_amount)
    await wallet.pay_lightning(send_proofs, invoice, fee_reserve_sat)
    wallet.status()


@cli.command("invoice", help="Create Lighting invoice.")
@click.argument("amount", type=int)
@click.option("--hash", default="", help="Hash of the paid invoice.", type=str)
@click.option(
    "--split",
    "-s",
    default=None,
    help="Split minted tokens with a specific amount.",
    type=int,
)
@click.pass_context
@coro
async def invoice(ctx: Context, amount: int, hash: str, split: int):
    wallet: Wallet = ctx.obj["WALLET"]
    await wallet.load_mint()
    wallet.status()
    # in case the user wants a specific split, we create a list of amounts
    optional_split = None
    if split:
        assert amount % split == 0, "split must be divisor or amount"
        assert amount >= split, "split must smaller or equal amount"
        n_splits = amount // split
        optional_split = [split] * n_splits
        logger.debug(f"Requesting split with {n_splits} * {split} sat tokens.")

    if not settings.lightning:
        r = await wallet.mint(amount, split=optional_split)
    # user requests an invoice
    elif amount and not hash:
        invoice = await wallet.request_mint(amount)
        if invoice.pr:
            print(f"Pay invoice to mint {amount} sat:")
            print("")
            print(f"Invoice: {invoice.pr}")
            print("")
            print(
                f"If you abort this you can use this command to recheck the invoice:\ncashu invoice {amount} --hash {invoice.hash}"
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
                    await wallet.mint(amount, split=optional_split, hash=invoice.hash)
                    paid = True
                    print(" Invoice paid.")
                except Exception as e:
                    # TODO: user error codes!
                    if "invoice not paid" in str(e):
                        print(".", end="", flush=True)
                        continue
                    else:
                        print(f"Error: {str(e)}")
            if not paid:
                print("\n")
                print(
                    "Invoice is not paid yet, stopping check. Use the command above to recheck after the invoice has been paid."
                )

    # user paid invoice and want to check it
    elif amount and hash:
        await wallet.mint(amount, split=optional_split, hash=hash)
    wallet.status()
    return


@cli.command("swap", help="Swap funds between mints.")
@click.pass_context
@coro
async def swap(ctx: Context):
    if not settings.lightning:
        raise Exception("lightning not supported.")
    print("Select the mint to swap from:")
    outgoing_wallet = await get_mint_wallet(ctx, force_select=True)

    print("Select the mint to swap to:")
    incoming_wallet = await get_mint_wallet(ctx, force_select=True)

    await incoming_wallet.load_mint()
    await outgoing_wallet.load_mint()

    if incoming_wallet.url == outgoing_wallet.url:
        raise Exception("mints for swap have to be different")

    amount = int(input("Enter amount to swap in sats: "))
    assert amount > 0, "amount is not positive"

    # request invoice from incoming mint
    invoice = await incoming_wallet.request_mint(amount)

    # pay invoice from outgoing mint
    total_amount, fee_reserve_sat = await outgoing_wallet.get_pay_amount_with_fees(
        invoice.pr
    )
    if outgoing_wallet.available_balance < total_amount:
        raise Exception("balance too low")
    _, send_proofs = await outgoing_wallet.split_to_send(
        outgoing_wallet.proofs, total_amount, set_reserved=True
    )
    await outgoing_wallet.pay_lightning(send_proofs, invoice.pr, fee_reserve_sat)

    # mint token in incoming mint
    await incoming_wallet.mint(amount, hash=invoice.hash)

    await incoming_wallet.load_proofs(reload=True)
    await print_mint_balances(incoming_wallet, show_mints=True)


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
async def balance(ctx: Context, verbose):
    wallet: Wallet = ctx.obj["WALLET"]
    await wallet.load_proofs()
    if verbose:
        # show balances per keyset
        keyset_balances = wallet.balance_per_keyset()
        if len(keyset_balances) > 1:
            print(f"You have balances in {len(keyset_balances)} keysets:")
            print("")
            for k, v in keyset_balances.items():
                print(
                    f"Keyset: {k} - Balance: {v['available']} sat (pending: {v['balance']-v['available']} sat)"
                )
            print("")

    await print_mint_balances(wallet)

    if verbose:
        print(
            f"Balance: {wallet.available_balance} sat (pending: {wallet.balance-wallet.available_balance} sat) in {len([p for p in wallet.proofs if not p.reserved])} tokens"
        )
    else:
        print(f"Balance: {wallet.available_balance} sat")


@cli.command("send", help="Send tokens.")
@click.argument("amount", type=int)
@click.argument("nostr", type=str, required=False)
@click.option(
    "--nostr",
    "-n",
    "nopt",
    help="Send to nostr pubkey.",
    type=str,
)
@click.option("--lock", "-l", default=None, help="Lock tokens (P2SH).", type=str)
@click.option(
    "--legacy",
    "-l",
    default=False,
    is_flag=True,
    help="Print legacy token without mint information.",
    type=bool,
)
@click.option(
    "--verbose",
    "-v",
    default=False,
    is_flag=True,
    help="Show more information.",
    type=bool,
)
@click.option(
    "--yes", "-y", default=False, is_flag=True, help="Skip confirmation.", type=bool
)
@click.option(
    "--nosplit",
    "-s",
    default=False,
    is_flag=True,
    help="Do not split tokens before sending.",
    type=bool,
)
@click.pass_context
@coro
async def send_command(
    ctx,
    amount: int,
    nostr: str,
    nopt: str,
    lock: str,
    legacy: bool,
    verbose: bool,
    yes: bool,
    nosplit: bool,
):
    wallet: Wallet = ctx.obj["WALLET"]
    if not nostr and not nopt:
        await send(wallet, amount, lock, legacy, split=not nosplit)
    else:
        await send_nostr(wallet, amount, nostr or nopt, verbose, yes)


@cli.command("receive", help="Receive tokens.")
@click.argument("token", type=str, default="")
@click.option("--lock", "-l", default=None, help="Unlock tokens.", type=str)
@click.option(
    "--nostr", "-n", default=False, is_flag=True, help="Receive tokens via nostr."
)
@click.option(
    "--all", "-a", default=False, is_flag=True, help="Receive all pending tokens."
)
@click.option(
    "--verbose",
    "-v",
    help="Display more information.",
    is_flag=True,
    default=False,
    type=bool,
)
@click.pass_context
@coro
async def receive_cli(
    ctx: Context,
    token: str,
    lock: str,
    nostr: bool,
    all: bool,
    verbose: bool,
):
    wallet: Wallet = ctx.obj["WALLET"]
    wallet.status()

    if token:
        tokenObj = deserialize_token_from_string(token)
        # verify that we trust all mints in these tokens
        # ask the user if they want to trust the new mints
        for mint_url in set([t.mint for t in tokenObj.token if t.mint]):
            mint_wallet = Wallet(
                mint_url, os.path.join(settings.cashu_dir, wallet.name)
            )
            await verify_mint(mint_wallet, mint_url)

        await receive(wallet, tokenObj, lock)
    elif nostr:
        await receive_nostr(wallet, verbose)
    elif all:
        reserved_proofs = await get_reserved_proofs(wallet.db)
        if len(reserved_proofs):
            for key, value in groupby(reserved_proofs, key=itemgetter("send_id")):  # type: ignore
                proofs = list(value)
                token = await wallet.serialize_proofs(proofs)
                tokenObj = TokenV3.deserialize(token)
                # verify that we trust all mints in these tokens
                # ask the user if they want to trust the new mints
                for mint_url in set([t.mint for t in tokenObj.token if t.mint]):
                    mint_wallet = Wallet(
                        mint_url, os.path.join(settings.cashu_dir, wallet.name)
                    )
                    await verify_mint(mint_wallet, mint_url)
                await receive(wallet, tokenObj, lock)
    else:
        print("Error: enter token or use either flag --nostr or --all.")


@cli.command("burn", help="Burn spent tokens.")
@click.argument("token", required=False, type=str)
@click.option("--all", "-a", default=False, is_flag=True, help="Burn all spent tokens.")
@click.option(
    "--delete",
    "-d",
    default=None,
    help="Forcefully delete pending token by send ID if mint is unavailable.",
)
@click.option(
    "--force", "-f", default=False, is_flag=True, help="Force check on all tokens."
)
@click.pass_context
@coro
async def burn(ctx: Context, token: str, all: bool, force: bool, delete: str):
    wallet: Wallet = ctx.obj["WALLET"]
    if not delete:
        await wallet.load_mint()
    if not (all or token or force or delete) or (token and all):
        print(
            "Error: enter a token or use --all to burn all pending tokens, --force to check all tokens "
            "or --delete with send ID to force-delete pending token from list if mint is unavailable."
        )
        return
    if all:
        # check only those who are flagged as reserved
        proofs = await get_reserved_proofs(wallet.db)
    elif force:
        # check all proofs in db
        proofs = wallet.proofs
    elif delete:
        reserved_proofs = await get_reserved_proofs(wallet.db)
        proofs = [proof for proof in reserved_proofs if proof["send_id"] == delete]
    else:
        # check only the specified ones
        tokenObj = TokenV3.deserialize(token)
        proofs = tokenObj.get_proofs()

    if delete:
        await wallet.invalidate(proofs, check_spendable=False)
    else:
        await wallet.invalidate(proofs)
    wallet.status()


@cli.command("pending", help="Show pending tokens.")
@click.option(
    "--legacy",
    "-l",
    default=False,
    is_flag=True,
    help="Print legacy token without mint information.",
    type=bool,
)
@click.option(
    "--number", "-n", default=None, help="Show only n pending tokens.", type=int
)
@click.option(
    "--offset",
    default=0,
    help="Show pending tokens only starting from offset.",
    type=int,
)
@click.pass_context
@coro
async def pending(ctx: Context, legacy, number: int, offset: int):
    wallet: Wallet = ctx.obj["WALLET"]
    reserved_proofs = await get_reserved_proofs(wallet.db)
    if len(reserved_proofs):
        print(f"--------------------------\n")
        sorted_proofs = sorted(reserved_proofs, key=itemgetter("send_id"))  # type: ignore
        if number:
            number += offset
        for i, (key, value) in islice(
            enumerate(
                groupby(
                    sorted_proofs,
                    key=itemgetter("send_id"),
                )
            ),
            offset,
            number,
        ):
            grouped_proofs = list(value)
            token = await wallet.serialize_proofs(grouped_proofs)
            tokenObj = deserialize_token_from_string(token)
            mint = [t.mint for t in tokenObj.token][0]
            # token_hidden_secret = await wallet.serialize_proofs(grouped_proofs)
            assert grouped_proofs[0].time_reserved
            reserved_date = datetime.utcfromtimestamp(
                int(grouped_proofs[0].time_reserved)
            ).strftime("%Y-%m-%d %H:%M:%S")
            print(
                f"#{i} Amount: {sum_proofs(grouped_proofs)} sat Time: {reserved_date} ID: {key}  Mint: {mint}\n"
            )
            print(f"{token}\n")

            if legacy:
                token_legacy = await wallet.serialize_proofs(
                    grouped_proofs,
                    legacy=True,
                )
                print(f"{token_legacy}\n")
            print(f"--------------------------\n")
        print("To remove all spent tokens use: cashu burn -a")


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
    wallets = [
        d for d in listdir(settings.cashu_dir) if isdir(join(settings.cashu_dir, d))
    ]
    try:
        wallets.remove("mint")
    except ValueError:
        pass
    for w in wallets:
        wallet = Wallet(ctx.obj["HOST"], os.path.join(settings.cashu_dir, w))
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
async def info(ctx: Context):
    print(f"Version: {settings.version}")
    print(f"Wallet: {ctx.obj['WALLET_NAME']}")
    if settings.debug:
        print(f"Debug: {settings.debug}")
    print(f"Cashu dir: {settings.cashu_dir}")
    if settings.env_file:
        print(f"Settings: {settings.env_file}")
    if settings.tor:
        print(f"Tor enabled: {settings.tor}")
    if settings.nostr_private_key:
        try:
            client = NostrClient(private_key=settings.nostr_private_key, connect=False)
            print(f"Nostr public key: {client.public_key.bech32()}")
            print(f"Nostr relays: {settings.nostr_relays}")
        except:
            print(f"Nostr: Error. Invalid key.")
    if settings.socks_host:
        print(f"Socks proxy: {settings.socks_host}:{settings.socks_port}")
    print(f"Mint URL: {ctx.obj['HOST']}")
    return
