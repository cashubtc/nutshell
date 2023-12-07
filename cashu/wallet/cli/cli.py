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

from cashu.core.logging import configure_logger

from ...core.base import TokenV3, Unit
from ...core.helpers import sum_proofs
from ...core.settings import settings
from ...nostr.client.client import NostrClient
from ...tor.tor import TorProxy
from ...wallet.crud import (
    get_lightning_invoices,
    get_reserved_proofs,
    get_seed_and_mnemonic,
)
from ...wallet.wallet import Wallet as Wallet
from ..api.api_server import start_api_server
from ..cli.cli_helpers import (
    get_mint_wallet,
    get_unit_wallet,
    print_balance,
    print_mint_balances,
    verify_mint,
)
from ..helpers import (
    deserialize_token_from_string,
    init_wallet,
    list_mints,
    receive,
    send,
)
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


# https://github.com/pallets/click/issues/85#issuecomment-503464628
def coro(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper


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
    "--unit",
    "-u",
    "unit",
    default=None,
    help=f"Wallet unit (default: {settings.wallet_unit}).",
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
@click.option(
    "--tests",
    "-t",
    is_flag=True,
    default=False,
    help="Run in test mode (don't ask for CLI inputs)",
)
@click.pass_context
@coro
async def cli(ctx: Context, host: str, walletname: str, unit: str, tests: bool):
    if settings.debug:
        configure_logger()
    if settings.tor and not TorProxy().check_platform():
        error_str = (
            "Your settings say TOR=true but the built-in Tor bundle is not supported on"
            " your system. You have two options: Either install Tor manually and set"
            " TOR=FALSE and SOCKS_HOST=localhost and SOCKS_PORT=9050 in your Cashu"
            " config (recommended). Or turn off Tor by setting TOR=false (not"
            " recommended). Cashu will not work until you edit your config file"
            " accordingly."
        )
        error_str += "\n\n"
        if settings.env_file:
            error_str += f"Edit your Cashu config file here: {settings.env_file}"
            env_path = settings.env_file
        else:
            error_str += (
                "Ceate a new Cashu config file here:"
                f" {os.path.join(settings.cashu_dir, '.env')}"
            )
            env_path = os.path.join(settings.cashu_dir, ".env")
        error_str += (
            '\n\nYou can turn off Tor with this command: echo "TOR=FALSE" >>'
            f" {env_path}"
        )
        raise Exception(error_str)

    ctx.ensure_object(dict)
    ctx.obj["HOST"] = host or settings.mint_url
    ctx.obj["UNIT"] = unit
    ctx.obj["WALLET_NAME"] = walletname
    settings.wallet_name = walletname

    db_path = os.path.join(settings.cashu_dir, walletname)
    # if the command is "restore" we don't want to ask the user for a mnemonic
    # otherwise it will create a mnemonic and store it in the database
    if ctx.invoked_subcommand == "restore":
        wallet = await Wallet.with_db(
            ctx.obj["HOST"], db_path, name=walletname, skip_db_read=True
        )
    else:
        # # we need to run the migrations before we load the wallet for the first time
        # # otherwise the wallet will not be able to generate a new private key and store it
        wallet = await Wallet.with_db(
            ctx.obj["HOST"], db_path, name=walletname, skip_db_read=True
        )
        # now with the migrations done, we can load the wallet and generate a new mnemonic if needed
        wallet = await Wallet.with_db(ctx.obj["HOST"], db_path, name=walletname)

    assert wallet, "Wallet not found."
    ctx.obj["WALLET"] = wallet
    # await init_wallet(ctx.obj["WALLET"], load_proofs=False)

    # only if a command is one of a subset that needs to specify a mint host
    # if a mint host is already specified as an argument `host`, use it
    if ctx.invoked_subcommand not in ["send", "invoice", "pay"] or host:
        return
    # ------ MULTIUNIT ------- : Select a unit
    ctx.obj["WALLET"] = await get_unit_wallet(ctx)
    # ------ MUTLIMINT ------- : Select a wallet
    # else: we ask the user to select one
    ctx.obj["WALLET"] = await get_mint_wallet(
        ctx
    )  # select a specific wallet by CLI input
    await init_wallet(ctx.obj["WALLET"], load_proofs=False)


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
    print_balance(ctx)
    quote = await wallet.get_pay_amount_with_fees(invoice)
    logger.debug(f"Quote: {quote}")
    total_amount = quote.amount + quote.fee_reserve
    if not yes:
        potential = (
            f" ({wallet.unit.str(total_amount)} with potential fees)"
            if quote.fee_reserve
            else ""
        )
        message = f"Pay {wallet.unit.str(quote.amount)}{potential}?"
        click.confirm(
            message,
            abort=True,
            default=True,
        )

    print("Paying Lightning invoice ...", end="", flush=True)
    assert total_amount > 0, "amount is not positive"
    if wallet.available_balance < total_amount:
        print(" Error: Balance too low.")
        return
    _, send_proofs = await wallet.split_to_send(wallet.proofs, total_amount)
    try:
        melt_response = await wallet.pay_lightning(
            send_proofs, invoice, quote.fee_reserve, quote.quote
        )
    except Exception as e:
        print(f" Error paying invoice: {str(e)}")
        return
    print(" Invoice paid", end="", flush=True)
    if melt_response.payment_preimage and melt_response.payment_preimage != "0" * 64:
        print(f" (Preimage: {melt_response.payment_preimage}).")
    else:
        print(".")
    print_balance(ctx)


@cli.command("invoice", help="Create Lighting invoice.")
@click.argument("amount", type=float)
@click.option("--id", default="", help="Id of the paid invoice.", type=str)
@click.option(
    "--split",
    "-s",
    default=None,
    help="Split minted tokens with a specific amount.",
    type=int,
)
@click.option(
    "--no-check",
    "-n",
    default=False,
    is_flag=True,
    help="Do not check if invoice is paid.",
    type=bool,
)
@click.pass_context
@coro
async def invoice(ctx: Context, amount: int, id: str, split: int, no_check: bool):
    wallet: Wallet = ctx.obj["WALLET"]
    await wallet.load_mint()
    print_balance(ctx)
    amount = int(amount * 100) if wallet.unit == Unit.usd else int(amount)
    # in case the user wants a specific split, we create a list of amounts
    optional_split = None
    if split:
        assert amount % split == 0, "split must be divisor or amount"
        assert amount >= split, "split must smaller or equal amount"
        n_splits = amount // split
        optional_split = [split] * n_splits
        logger.debug(
            f"Requesting split with {n_splits} * {wallet.unit.str(split)} tokens."
        )

    # user requests an invoice
    if amount and not id:
        invoice = await wallet.request_mint(amount)
        if invoice.bolt11:
            print("")
            print(f"Pay invoice to mint {wallet.unit.str(amount)}:")
            print("")
            print(f"Invoice: {invoice.bolt11}")
            print("")
            print(
                "You can use this command to check the invoice: cashu invoice"
                f" {amount} --id {invoice.id}"
            )
            if no_check:
                return
            check_until = time.time() + 5 * 60  # check for five minutes
            print("")
            print(
                "Checking invoice ...",
                end="",
                flush=True,
            )
            paid = False
            while time.time() < check_until and not paid:
                time.sleep(3)
                try:
                    await wallet.mint(amount, split=optional_split, id=invoice.id)
                    paid = True
                    print(" Invoice paid.")
                except Exception as e:
                    # TODO: user error codes!
                    if "not paid" in str(e):
                        print(".", end="", flush=True)
                        continue
                    else:
                        print(f"Error: {str(e)}")
            if not paid:
                print("\n")
                print(
                    "Invoice is not paid yet, stopping check. Use the command above to"
                    " recheck after the invoice has been paid."
                )

    # user paid invoice and want to check it
    elif amount and id:
        await wallet.mint(amount, split=optional_split, id=id)
    print("")
    print_balance(ctx)
    return


@cli.command("swap", help="Swap funds between mints.")
@click.pass_context
@coro
async def swap(ctx: Context):
    print("Select the mint to swap from:")
    outgoing_wallet = await get_mint_wallet(ctx, force_select=True)

    print("Select the mint to swap to:")
    incoming_wallet = await get_mint_wallet(ctx, force_select=True)

    await incoming_wallet.load_mint()
    await outgoing_wallet.load_mint()

    if incoming_wallet.url == outgoing_wallet.url:
        raise Exception("mints for swap have to be different")

    amount = int(input(f"Enter amount to swap in {incoming_wallet.unit.name}: "))
    assert amount > 0, "amount is not positive"

    # request invoice from incoming mint
    invoice = await incoming_wallet.request_mint(amount)

    # pay invoice from outgoing mint
    quote = await outgoing_wallet.get_pay_amount_with_fees(invoice.bolt11)
    total_amount = quote.amount + quote.fee_reserve
    if outgoing_wallet.available_balance < total_amount:
        raise Exception("balance too low")
    _, send_proofs = await outgoing_wallet.split_to_send(
        outgoing_wallet.proofs, total_amount, set_reserved=True
    )
    await outgoing_wallet.pay_lightning(
        send_proofs, invoice.bolt11, quote.fee_reserve, quote.quote
    )

    # mint token in incoming mint
    await incoming_wallet.mint(amount, id=invoice.id)

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
    await wallet.load_proofs(unit=False)
    unit_balances = wallet.balance_per_unit()
    if len(unit_balances) > 1 and not ctx.obj["UNIT"]:
        print(f"You have balances in {len(unit_balances)} units:")
        print("")
        for i, (k, v) in enumerate(unit_balances.items()):
            unit = k
            print(f"Unit {i+1} ({unit}) – Balance: {unit.str(int(v['available']))}")
        print("")
    if verbose:
        # show balances per keyset
        keyset_balances = wallet.balance_per_keyset()
        if len(keyset_balances):
            print(f"You have balances in {len(keyset_balances)} keysets:")
            print("")
            for k, v in keyset_balances.items():  # type: ignore
                unit = Unit[str(v["unit"])]
                print(
                    f"Keyset: {k} - Balance: {unit.str(int(v['available']))} (pending:"
                    f" {unit.str(int(v['balance'])-int(v['available']))})"
                )
            print("")

    await print_mint_balances(wallet)

    await wallet.load_proofs(reload=True)
    if verbose:
        print(
            f"Balance: {wallet.unit.str(wallet.available_balance)} (pending:"
            f" {wallet.unit.str(wallet.balance-wallet.available_balance)}) in"
            f" {len([p for p in wallet.proofs if not p.reserved])} tokens"
        )
    else:
        print(f"Balance: {wallet.unit.str(wallet.available_balance)}")


@cli.command("send", help="Send tokens.")
@click.argument("amount", type=float)
@click.argument("nostr", type=str, required=False)
@click.option(
    "--nostr",
    "-n",
    "nopt",
    help="Send to nostr pubkey.",
    type=str,
)
@click.option("--lock", "-l", default=None, help="Lock tokens (P2PK).", type=str)
@click.option(
    "--dleq",
    "-d",
    default=False,
    is_flag=True,
    help="Send with DLEQ proof.",
    type=bool,
)
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
    dleq: bool,
    legacy: bool,
    verbose: bool,
    yes: bool,
    nosplit: bool,
):
    wallet: Wallet = ctx.obj["WALLET"]
    amount = int(amount * 100) if wallet.unit == Unit.usd else int(amount)
    if not nostr and not nopt:
        await send(
            wallet,
            amount=amount,
            lock=lock,
            legacy=legacy,
            split=not nosplit,
            include_dleq=dleq,
        )
    else:
        await send_nostr(
            wallet, amount=amount, pubkey=nostr or nopt, verbose=verbose, yes=yes
        )
    print_balance(ctx)


@cli.command("receive", help="Receive tokens.")
@click.argument("token", type=str, default="")
@click.option(
    "--nostr",
    "-n",
    default=False,
    is_flag=True,
    help="Receive tokens via nostr.receive",
)
@click.option(
    "--all", "-a", default=False, is_flag=True, help="Receive all pending tokens."
)
@click.pass_context
@coro
async def receive_cli(
    ctx: Context,
    token: str,
    nostr: bool,
    all: bool,
):
    wallet: Wallet = ctx.obj["WALLET"]

    if token:
        tokenObj = deserialize_token_from_string(token)
        # verify that we trust all mints in these tokens
        # ask the user if they want to trust the new mints
        for mint_url in set([t.mint for t in tokenObj.token if t.mint]):
            mint_wallet = Wallet(
                mint_url, os.path.join(settings.cashu_dir, wallet.name)
            )
            await verify_mint(mint_wallet, mint_url)

        await receive(wallet, tokenObj)
    elif nostr:
        await receive_nostr(wallet)
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
                await receive(wallet, tokenObj)
    else:
        print("Error: enter token or use either flag --nostr or --all.")
        return
    print_balance(ctx)


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
    await wallet.load_proofs()
    if not delete:
        await wallet.load_mint()
    if not (all or token or force or delete) or (token and all):
        print(
            "Error: enter a token or use --all to burn all pending tokens, --force to"
            " check all tokens or --delete with send ID to force-delete pending token"
            " from list if mint is unavailable."
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
        await wallet.invalidate(proofs)
    else:
        await wallet.invalidate(proofs, check_spendable=True)
    print_balance(ctx)


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
        print("--------------------------\n")
        sorted_proofs = sorted(reserved_proofs, key=itemgetter("send_id"))  # type: ignore
        if number:
            number += offset
        for i, (key, value) in islice(
            enumerate(
                groupby(
                    sorted_proofs,
                    key=itemgetter("send_id"),  # type: ignore
                )
            ),
            offset,
            number,
        ):
            grouped_proofs = list(value)
            # TODO: we can't return DLEQ because we don't store it
            token = await wallet.serialize_proofs(grouped_proofs, include_dleq=False)
            tokenObj = deserialize_token_from_string(token)
            mint = [t.mint for t in tokenObj.token][0]
            # token_hidden_secret = await wallet.serialize_proofs(grouped_proofs)
            assert grouped_proofs[0].time_reserved
            reserved_date = datetime.utcfromtimestamp(
                int(grouped_proofs[0].time_reserved)
            ).strftime("%Y-%m-%d %H:%M:%S")
            print(
                f"#{i} Amount:"
                f" {wallet.unit.str(sum_proofs(grouped_proofs))} Time:"
                f" {reserved_date} ID: {key}  Mint: {mint}\n"
            )
            print(f"{token}\n")

            if legacy:
                token_legacy = await wallet.serialize_proofs(
                    grouped_proofs,
                    legacy=True,
                )
                print(f"{token_legacy}\n")
            print("--------------------------\n")
        print("To remove all spent tokens use: cashu burn -a")


@cli.command("lock", help="Generate receiving lock.")
@click.pass_context
@coro
async def lock(ctx):
    wallet: Wallet = ctx.obj["WALLET"]

    pubkey = await wallet.create_p2pk_pubkey()
    lock_str = f"P2PK:{pubkey}"
    print("---- Pay to public key (P2PK) ----\n")

    print("Use a lock to receive tokens that only you can unlock.")
    print("")
    print(f"Public receiving lock: {lock_str}")
    print("")
    print(
        f"Anyone can send tokens to this lock:\n\ncashu send <amount> --lock {lock_str}"
    )
    print("")
    print("Only you can receive tokens from this lock: cashu receive <token>")


@cli.command("locks", help="Show unused receiving locks.")
@click.pass_context
@coro
async def locks(ctx):
    wallet: Wallet = ctx.obj["WALLET"]
    # P2PK lock
    pubkey = await wallet.create_p2pk_pubkey()
    lock_str = f"P2PK:{pubkey}"
    print("---- Pay to public key (P2PK) lock ----\n")
    print(f"Lock: {lock_str}")
    print("")
    return True


@cli.command("invoices", help="List of all pending invoices.")
@click.pass_context
@coro
async def invoices(ctx):
    wallet: Wallet = ctx.obj["WALLET"]
    invoices = await get_lightning_invoices(db=wallet.db)
    if len(invoices):
        print("")
        print("--------------------------\n")
        for invoice in invoices:
            print(f"Paid: {invoice.paid}")
            print(f"Incoming: {invoice.amount > 0}")
            print(f"Amount: {abs(invoice.amount)}")
            if invoice.id:
                print(f"ID: {invoice.id}")
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
            print(f"Payment request: {invoice.bolt11}")
            print("")
            print("--------------------------\n")
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
            await wallet.load_proofs()
            if wallet.proofs and len(wallet.proofs):
                active_wallet = False
                if w == ctx.obj["WALLET_NAME"]:
                    active_wallet = True
                print(
                    f"Wallet: {w}\tBalance:"
                    f" {wallet.unit.str(sum_proofs(wallet.proofs))}"
                    " (available: "
                    f"{wallet.unit.str(sum_proofs([p for p in wallet.proofs if not p.reserved]))}){' *' if active_wallet else ''}"
                )
        except Exception:
            pass


@cli.command("info", help="Information about Cashu wallet.")
@click.option("--mint", default=False, is_flag=True, help="Fetch mint information.")
@click.option("--mnemonic", default=False, is_flag=True, help="Show your mnemonic.")
@click.pass_context
@coro
async def info(ctx: Context, mint: bool, mnemonic: bool):
    wallet: Wallet = ctx.obj["WALLET"]
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
        except Exception:
            print("Nostr: Error. Invalid key.")
    if settings.socks_proxy:
        print(f"Socks proxy: {settings.socks_proxy}")
    if settings.http_proxy:
        print(f"HTTP proxy: {settings.http_proxy}")
    mint_list = await list_mints(wallet)
    print(f"Mint URLs: {mint_list}")
    if mint:
        for mint_url in mint_list:
            wallet.url = mint_url
            try:
                mint_info: dict = (await wallet._load_mint_info()).dict()
                print("")
                print("---- Mint information ----")
                print("")
                print(f"Mint URL: {mint_url}")
                if mint_info:
                    print(f"Mint name: {mint_info['name']}")
                    if mint_info.get("description"):
                        print(f"Description: {mint_info['description']}")
                    if mint_info.get("description_long"):
                        print(f"Long description: {mint_info['description_long']}")
                    if mint_info.get("contact"):
                        print(f"Contact: {mint_info['contact']}")
                    if mint_info.get("version"):
                        print(f"Version: {mint_info['version']}")
                    if mint_info.get("motd"):
                        print(f"Message of the day: {mint_info['motd']}")
                    if mint_info.get("nuts"):
                        print(
                            "Supported NUTS:"
                            f" {', '.join(['NUT-'+str(k) for k in mint_info['nuts'].keys()])}"
                        )
            except Exception as e:
                print("")
                print(f"Error fetching mint information for {mint_url}: {e}")

    if mnemonic:
        assert wallet.mnemonic
        print(f"Mnemonic: {wallet.mnemonic}")
    return


@cli.command("restore", help="Restore backups.")
@click.option(
    "--batch",
    "-b",
    default=25,
    help="Batch size. Specifies how many proofs are restored in one batch.",
    type=int,
)
@click.option(
    "--to",
    "-t",
    default=2,
    help="Number of empty batches to complete the restore process.",
    type=int,
)
@click.pass_context
@coro
async def restore(ctx: Context, to: int, batch: int):
    wallet: Wallet = ctx.obj["WALLET"]
    # check if there is already a mnemonic in the database
    ret = await get_seed_and_mnemonic(wallet.db)
    if ret:
        print(
            "Wallet already has a mnemonic. You can't restore an already initialized"
            " wallet."
        )
        print("To restore a wallet, please delete the wallet directory and try again.")
        print("")
        print(
            "The wallet directory is:"
            f" {os.path.join(settings.cashu_dir, ctx.obj['WALLET_NAME'])}"
        )
        return
    # ask the user for a mnemonic but allow also no input
    print("Please enter your mnemonic to restore your balance.")
    mnemonic = input(
        "Enter mnemonic: ",
    )
    if not mnemonic:
        print("No mnemonic entered. Exiting.")
        return

    await wallet.restore_wallet_from_mnemonic(mnemonic, to=to, batch=batch)
    await wallet.load_proofs()
    print_balance(ctx)


@cli.command("selfpay", help="Refresh tokens.")
# @click.option("--all", default=False, is_flag=True, help="Execute on all available mints.")
@click.pass_context
@coro
async def selfpay(ctx: Context, all: bool = False):
    wallet = await get_mint_wallet(ctx, force_select=True)
    await wallet.load_mint()

    # get balance on this mint
    mint_balance_dict = await wallet.balance_per_minturl()
    mint_balance = int(mint_balance_dict[wallet.url]["available"])
    # send balance once to mark as reserved
    await wallet.split_to_send(wallet.proofs, mint_balance, None, set_reserved=True)
    # load all reserved proofs (including the one we just sent)
    reserved_proofs = await get_reserved_proofs(wallet.db)
    if not len(reserved_proofs):
        print("No balance on this mint.")
        return

    token = await wallet.serialize_proofs(reserved_proofs)
    print(f"Selfpay token for mint {wallet.url}:")
    print("")
    print(token)
    tokenObj = TokenV3.deserialize(token)
    await receive(wallet, tokenObj)
