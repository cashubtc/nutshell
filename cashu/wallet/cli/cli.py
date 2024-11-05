#!/usr/bin/env python

import asyncio
import os
import time
from datetime import datetime, timezone
from functools import wraps
from itertools import groupby, islice
from operator import itemgetter
from os import listdir
from os.path import isdir, join
from typing import Optional, Union

import bolt11
import click
from click import Context
from loguru import logger

from ...core.base import (
    MeltQuote,
    MeltQuoteState,
    Method,
    MintQuote,
    MintQuoteState,
    TokenV4,
    Unit,
)
from ...core.helpers import sum_proofs
from ...core.json_rpc.base import JSONRPCNotficationParams
from ...core.logging import configure_logger
from ...core.models import PostMintQuoteResponse
from ...core.settings import settings
from ...nostr.client.client import NostrClient
from ...tor.tor import TorProxy
from ...wallet.crud import (
    get_bolt11_melt_quotes,
    get_bolt11_mint_quote,
    get_bolt11_mint_quotes,
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
    receive_all_pending,
    verify_mint,
)
from ..helpers import (
    check_payment_preimage,
    deserialize_token_from_string,
    init_wallet,
    list_mints,
    receive,
    send,
)
from ..nostr import receive_nostr, send_nostr
from ..subscriptions import SubscriptionManager


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
                "Create a new Cashu config file here:"
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
    ctx.obj["UNIT"] = unit or settings.wallet_unit
    unit = ctx.obj["UNIT"]
    ctx.obj["WALLET_NAME"] = walletname
    settings.wallet_name = walletname

    db_path = os.path.join(settings.cashu_dir, walletname)
    # if the command is "restore" we don't want to ask the user for a mnemonic
    # otherwise it will create a mnemonic and store it in the database
    if ctx.invoked_subcommand == "restore":
        wallet = await Wallet.with_db(
            ctx.obj["HOST"], db_path, name=walletname, skip_db_read=True, unit=unit
        )
    else:
        # # we need to run the migrations before we load the wallet for the first time
        # # otherwise the wallet will not be able to generate a new private key and store it
        wallet = await Wallet.with_db(
            ctx.obj["HOST"], db_path, name=walletname, skip_db_read=True, unit=unit
        )
        # now with the migrations done, we can load the wallet and generate a new mnemonic if needed
        wallet = await Wallet.with_db(
            ctx.obj["HOST"], db_path, name=walletname, unit=unit
        )

    assert wallet, "Wallet not found."
    ctx.obj["WALLET"] = wallet

    # only if a command is one of a subset that needs to specify a mint host
    # if a mint host is already specified as an argument `host`, use it
    if ctx.invoked_subcommand not in ["send", "invoice", "pay"] or host:
        return
    # ------ MULTIUNIT ------- : Select a unit
    ctx.obj["WALLET"] = await get_unit_wallet(ctx)
    # ------ MULTIMINT ------- : Select a wallet
    # else: we ask the user to select one
    ctx.obj["WALLET"] = await get_mint_wallet(
        ctx
    )  # select a specific wallet by CLI input
    await init_wallet(ctx.obj["WALLET"], load_proofs=False)


@cli.command("pay", help="Pay Lightning invoice.")
@click.argument("invoice", type=str)
@click.argument(
    "amount",
    type=int,
    required=False,
)
@click.option(
    "--yes", "-y", default=False, is_flag=True, help="Skip confirmation.", type=bool
)
@click.pass_context
@coro
async def pay(
    ctx: Context, invoice: str, amount: Optional[int] = None, yes: bool = False
):
    wallet: Wallet = ctx.obj["WALLET"]
    await wallet.load_mint()
    await print_balance(ctx)
    payment_hash = bolt11.decode(invoice).payment_hash
    quote = await wallet.melt_quote(invoice, amount)
    logger.debug(f"Quote: {quote}")
    total_amount = quote.amount + quote.fee_reserve
    # estimate ecash fee for the coinselected proofs
    ecash_fees = wallet.coinselect_fee(wallet.proofs, total_amount)
    if not yes:
        potential = (
            f" ({wallet.unit.str(total_amount + ecash_fees)} with potential fees)"
            if quote.fee_reserve or ecash_fees
            else ""
        )
        message = f"Pay {wallet.unit.str(quote.amount)}{potential}?"
        click.confirm(
            message,
            abort=True,
            default=True,
        )
    # we need to include fees so we can use the proofs for melting the `total_amount`
    send_proofs, _ = await wallet.select_to_send(
        wallet.proofs, total_amount, include_fees=True, set_reserved=True
    )
    print("Paying Lightning invoice ...", end="", flush=True)
    assert total_amount > 0, "amount is not positive"
    if wallet.available_balance < total_amount:
        print(" Error: Balance too low.")
        return

    try:
        melt_response = await wallet.melt(
            send_proofs, invoice, quote.fee_reserve, quote.quote
        )
    except Exception as e:
        print(f" Error paying invoice: {e}")
        return
    if (
        melt_response.state
        and MintQuoteState(melt_response.state) == MintQuoteState.paid
    ):
        print(" Invoice paid", end="", flush=True)
        if (
            melt_response.payment_preimage
            and melt_response.payment_preimage != "0" * 64
        ):
            if not check_payment_preimage(payment_hash, melt_response.payment_preimage):
                print(" Error: Invalid preimage!", end="", flush=True)
            print(f" (Preimage: {melt_response.payment_preimage}).")
        else:
            print(" Mint did not provide a preimage.")
    elif MintQuoteState(melt_response.state) == MintQuoteState.pending:
        print(" Invoice pending.")
    elif MintQuoteState(melt_response.state) == MintQuoteState.unpaid:
        print(" Invoice unpaid.")
    else:
        print(" Error paying invoice.")

    await print_balance(ctx)


@cli.command("invoice", help="Create Lighting invoice.")
@click.argument("amount", type=float)
@click.option("memo", "-m", default="", help="Memo for the invoice.", type=str)
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
async def invoice(
    ctx: Context,
    amount: float,
    memo: str,
    id: str,
    split: int,
    no_check: bool,
):
    wallet: Wallet = ctx.obj["WALLET"]
    await wallet.load_mint()
    await print_balance(ctx)
    amount = int(amount * 100) if wallet.unit in [Unit.usd, Unit.eur] else int(amount)
    print(f"Requesting invoice for {wallet.unit.str(amount)}.")
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

    paid = False
    invoice_nonlocal: Union[None, MintQuote] = None
    subscription_nonlocal: Union[None, SubscriptionManager] = None

    def mint_invoice_callback(msg: JSONRPCNotficationParams):
        nonlocal \
            ctx, \
            wallet, \
            amount, \
            optional_split, \
            paid, \
            invoice_nonlocal, \
            subscription_nonlocal
        logger.trace(f"Received callback: {msg}")
        if paid:
            return
        try:
            ws_quote_resp = PostMintQuoteResponse.parse_obj(msg.payload)
        except Exception:
            return
        logger.debug(
            f"Received callback for quote: {ws_quote_resp.quote}: state {ws_quote_resp.state}"
        )
        # we need to sleep to give the callback map some time to be populated
        time.sleep(0.1)
        if (
            (ws_quote_resp.state == MintQuoteState.paid.value)
            and ws_quote_resp.request == mint_quote.request
            and msg.subId in subscription.callback_map.keys()
        ):
            try:
                asyncio.run(
                    wallet.mint(
                        int(amount), split=optional_split, quote_id=mint_quote.quote
                    )
                )
                # set paid so we won't react to any more callbacks
                paid = True
            except Exception as e:
                print(f"Error during mint: {e}")
                return
        else:
            logger.debug("Quote not paid yet.")
            return

    # user requests an invoice
    if amount and not id:
        mint_supports_websockets = wallet.mint_info.supports_websocket_mint_quote(
            Method["bolt11"], wallet.unit
        )
        if mint_supports_websockets and not no_check:
            mint_quote, subscription = await wallet.request_mint_with_callback(
                amount, callback=mint_invoice_callback, memo=memo
            )
            invoice_nonlocal, subscription_nonlocal = mint_quote, subscription
        else:
            mint_quote = await wallet.request_mint(amount, memo=memo)
        if mint_quote.request:
            print("")
            print(f"Pay invoice to mint {wallet.unit.str(amount)}:")
            print("")
            print(f"Invoice: {mint_quote.request}")
            print("")
            print(
                "You can use this command to check the invoice: cashu invoice"
                f" {amount} --id {mint_quote.quote}"
            )
            if no_check:
                return
            print("")
            print(
                "Checking invoice ...",
                end="",
                flush=True,
            )
        if mint_supports_websockets:
            while not paid:
                await asyncio.sleep(0.1)

        # we still check manually every 10 seconds
        check_until = time.time() + 5 * 60  # check for five minutes
        while time.time() < check_until and not paid:
            await asyncio.sleep(5)
            try:
                mint_quote_resp = await wallet.get_mint_quote(mint_quote.quote)
                if mint_quote_resp.state == MintQuoteState.paid.value:
                    await wallet.mint(
                        amount, split=optional_split, quote_id=mint_quote.quote
                    )
                    paid = True
                else:
                    print(".", end="", flush=True)
            except Exception as e:
                # TODO: user error codes!
                if "not paid" in str(e):
                    print(".", end="", flush=True)
                    continue
                else:
                    print(f"Error: {e}")
        if not paid:
            print("\n")
            print(
                "Invoice is not paid yet, stopping check. Use the command above to"
                " recheck after the invoice has been paid."
            )

    # user paid invoice before and wants to check the quote id
    elif amount and id:
        await wallet.mint(amount, split=optional_split, quote_id=id)

    # close open subscriptions so we can exit
    try:
        subscription.close()
    except Exception:
        pass
    print(" Invoice paid.")

    print("")
    await print_balance(ctx)
    return


@cli.command("swap", help="Swap funds between mints.")
@click.pass_context
@coro
async def swap(ctx: Context):
    print("Select the mint to swap from:")
    outgoing_wallet: Wallet = await get_mint_wallet(ctx, force_select=True)

    print("Select the mint to swap to:")
    incoming_wallet: Wallet = await get_mint_wallet(ctx, force_select=True)

    await incoming_wallet.load_mint()
    await outgoing_wallet.load_mint()

    if incoming_wallet.url == outgoing_wallet.url:
        raise Exception("mints for swap have to be different")

    amount = int(input(f"Enter amount to swap in {incoming_wallet.unit.name}: "))
    assert amount > 0, "amount is not positive"

    # request invoice from incoming mint
    mint_quote = await incoming_wallet.request_mint(amount)

    # pay invoice from outgoing mint
    melt_quote_resp = await outgoing_wallet.melt_quote(mint_quote.request)
    total_amount = melt_quote_resp.amount + melt_quote_resp.fee_reserve
    if outgoing_wallet.available_balance < total_amount:
        raise Exception("balance too low")
    send_proofs, fees = await outgoing_wallet.select_to_send(
        outgoing_wallet.proofs, total_amount, set_reserved=True
    )
    await outgoing_wallet.melt(
        send_proofs,
        mint_quote.request,
        melt_quote_resp.fee_reserve,
        melt_quote_resp.quote,
    )

    # mint token in incoming mint
    await incoming_wallet.mint(amount, quote_id=mint_quote.quote)

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
    if verbose:
        wallet = await wallet.with_db(
            url=wallet.url,
            db=wallet.db.db_location,
            name=wallet.name,
            skip_db_read=False,
            unit=wallet.unit.name,
            load_all_keysets=True,
        )

    unit_balances = wallet.balance_per_unit()
    await wallet.load_proofs(reload=True)

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
@click.option(
    "--memo",
    "-m",
    default=None,
    help="Memo for the token.",
    type=str,
)
@click.option(
    "--nostr",
    "-n",
    default=None,
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
    help="Print legacy TokenV3 format.",
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
    "--offline",
    "-o",
    default=False,
    is_flag=True,
    help="Force offline send.",
    type=bool,
)
@click.option(
    "--include-fees",
    "-f",
    default=False,
    is_flag=True,
    help="Include fees for receiving token.",
    type=bool,
)
@click.option(
    "--force-swap",
    "-s",
    default=False,
    is_flag=True,
    help="Force swap token.",
    type=bool,
)
@click.pass_context
@coro
async def send_command(
    ctx,
    amount: int,
    memo: str,
    nostr: str,
    lock: str,
    dleq: bool,
    legacy: bool,
    verbose: bool,
    yes: bool,
    offline: bool,
    include_fees: bool,
    force_swap: bool,
):
    wallet: Wallet = ctx.obj["WALLET"]
    amount = int(amount * 100) if wallet.unit in [Unit.usd, Unit.eur] else int(amount)
    if not nostr:
        await send(
            wallet,
            amount=amount,
            lock=lock,
            legacy=legacy,
            offline=offline,
            include_dleq=dleq,
            include_fees=include_fees,
            memo=memo,
            force_swap=force_swap,
        )
    else:
        await send_nostr(wallet, amount=amount, pubkey=nostr, verbose=verbose, yes=yes)
    await print_balance(ctx)


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
    # receive a specific token
    if token:
        token_obj = deserialize_token_from_string(token)
        # verify that we trust the mint in this tokens
        # ask the user if they want to trust the new mint
        mint_url = token_obj.mint
        mint_wallet = await Wallet.with_db(
            mint_url,
            os.path.join(settings.cashu_dir, wallet.name),
            unit=token_obj.unit,
        )
        await verify_mint(mint_wallet, mint_url)
        receive_wallet = await receive(mint_wallet, token_obj)
        ctx.obj["WALLET"] = receive_wallet
    # receive tokens via nostr
    elif nostr:
        await receive_nostr(wallet)
        # exit on keypress
        input("Enter any text to exit.")
        print("Exiting.")
        os._exit(0)
    # receive all pending outgoing tokens back to the wallet
    elif all:
        await receive_all_pending(ctx, wallet)
    else:
        print("Error: enter token or use either flag --nostr or --all.")
        return
    await print_balance(ctx)


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
        tokenObj = deserialize_token_from_string(token)
        proofs = tokenObj.proofs

    if delete:
        await wallet.invalidate(proofs)
    else:
        await wallet.invalidate(proofs, check_spendable=True)
    await print_balance(ctx)


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
    wallet = await Wallet.with_db(
        url=wallet.url,
        db=wallet.db.db_location,
        name=wallet.name,
        skip_db_read=False,
        unit=wallet.unit.name,
        load_all_keysets=True,
    )
    reserved_proofs = await get_reserved_proofs(wallet.db)
    if len(reserved_proofs):
        print("--------------------------\n")
        sorted_proofs = sorted(reserved_proofs, key=itemgetter("send_id"), reverse=True)  # type: ignore
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
            token_obj = deserialize_token_from_string(token)
            mint = token_obj.mint
            # token_hidden_secret = await wallet.serialize_proofs(grouped_proofs)
            assert grouped_proofs[0].time_reserved
            reserved_date = datetime.fromtimestamp(
                int(grouped_proofs[0].time_reserved), timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S")
            print(
                f"#{i} Amount:"
                f" {Unit[token_obj.unit].str(sum_proofs(grouped_proofs))} Time:"
                f" {reserved_date} ID: {key}  Mint: {mint}\n"
            )
            print(f"{token}\n")

            if legacy:
                token_legacy = await wallet.serialize_proofs(
                    grouped_proofs,
                    legacy=True,
                )
                print(f"Legacy token: {token_legacy}\n")
            print("--------------------------\n")
        print("To remove all pending tokens that are already spent use: cashu burn -a")
        print("To remove a specific pending token use: cashu burn <token>")
        print("To receive all pending tokens use: cashu receive -a")


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


@cli.command("invoices", help="List of all invoices.")
@click.option(
    "-op",
    "--only-paid",
    "paid",
    default=False,
    is_flag=True,
    help="Show only paid invoices.",
    type=bool,
)
@click.option(
    "-ou",
    "--only-unpaid",
    "unpaid",
    default=False,
    is_flag=True,
    help="Show only unpaid invoices.",
    type=bool,
)
@click.option(
    "-p",
    "--pending",
    "pending",
    default=False,
    is_flag=True,
    help="Show all pending invoices",
    type=bool,
)
@click.option(
    "--mint",
    "-m",
    is_flag=True,
    default=False,
    help="Try to mint pending invoices",
)
@click.pass_context
@coro
async def invoices(ctx, paid: bool, unpaid: bool, pending: bool, mint: bool):
    wallet: Wallet = ctx.obj["WALLET"]

    if paid and unpaid:
        print("You should only choose one option: either --only-paid or --only-unpaid")
        return

    if mint:
        await wallet.load_mint()

    melt_state: MeltQuoteState | None = None
    mint_state: MintQuoteState | None = None
    if unpaid:
        melt_state = MeltQuoteState.unpaid
        mint_state = MintQuoteState.unpaid
    elif paid:
        melt_state = MeltQuoteState.paid
        mint_state = MintQuoteState.paid

    melt_quotes = await get_bolt11_melt_quotes(
        db=wallet.db,
        state=melt_state,
    )

    mint_quotes = await get_bolt11_mint_quotes(
        db=wallet.db,
        state=mint_state,
    )

    if len(melt_quotes) == 0 and len(mint_quotes) == 0:
        print("No invoices found.")
        return

    async def _try_to_mint_pending_invoice(amount: int, id: str) -> Optional[MintQuote]:
        try:
            proofs = await wallet.mint(amount, id)
            print(f"Received {wallet.unit.str(sum_proofs(proofs))}")
            return await get_bolt11_mint_quote(db=wallet.db, quote=id)
        except Exception as e:
            logger.error(f"Could not mint pending invoice: {e}")
            return None

    def _print_quote_info(
        quote: MintQuote | MeltQuote | None, counter: int | None = None
    ):
        print("\n--------------------------\n")
        if counter:
            print(f"#{counter}", end=" ")
        if isinstance(quote, MintQuote):
            print("Mint quote (incoming invoice)")
        elif isinstance(quote, MeltQuote):
            print("Melt quote (outgoing invoice)")
        else:
            return
        print(f"Amount: {abs(quote.amount)}")
        print(f"Mint: {quote.mint}")
        print(f"ID: {quote.quote}")
        print(f"State: {quote.state}")

        if isinstance(quote, MeltQuote):
            if quote.payment_preimage:
                print(f"Preimage: {quote.payment_preimage}")
        if quote.created_time:
            d = datetime.fromtimestamp(
                int(float(quote.created_time)), timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S")
            print(f"Created at: {d}")
        if quote.paid_time:
            d = datetime.fromtimestamp(
                (int(float(quote.paid_time))), timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S")
            print(f"Paid at: {d}")
        print(f"\nPayment request: {quote.request}")

    invoices_printed_count = 0
    for melt_quote in melt_quotes:
        _print_quote_info(melt_quote, invoices_printed_count + 1)
        invoices_printed_count += 1

    for mint_quote in mint_quotes:
        if mint_quote.state == MintQuoteState.unpaid and mint:
            # Tries to mint pending invoice
            mint_quote_pay = await _try_to_mint_pending_invoice(
                mint_quote.amount, mint_quote.quote
            )
            # If minting was successful, we don't need to print this invoice
            if mint_quote_pay:
                continue
        _print_quote_info(mint_quote, invoices_printed_count + 1)
        invoices_printed_count += 1

    if invoices_printed_count == 0:
        print("No invoices found.")
    else:
        print("\n--------------------------\n")


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
    await wallet.load_keysets_from_db(unit=None)

    print(f"Version: {settings.version}")
    print(f"Wallet: {ctx.obj['WALLET_NAME']}")
    if settings.debug:
        print(f"Debug: {settings.debug}")
    print(f"Cashu dir: {settings.cashu_dir}")
    mint_list = await list_mints(wallet)
    print("Mints:")
    for mint_url in mint_list:
        print(f"    - URL: {mint_url}")
        keysets_strs = [
            f"ID: {k.id}  unit: {k.unit.name}  active: {str(bool(k.active)) + ' ' if k.active else str(bool(k.active))}  fee (ppk): {k.input_fee_ppk}"
            for k in wallet.keysets.values()
        ]
        if keysets_strs:
            print("        - Keysets:")
            for k in keysets_strs:
                print(f"            - {k}")
        if mint:
            wallet.url = mint_url
            try:
                mint_info: dict = (await wallet.load_mint_info()).dict()
                if mint_info:
                    print(f"        - Mint name: {mint_info['name']}")
                    if mint_info.get("description"):
                        print(f"        - Description: {mint_info['description']}")
                    if mint_info.get("description_long"):
                        print(
                            f"        - Long description: {mint_info['description_long']}"
                        )
                    if mint_info.get("contact") and mint_info.get("contact") != [
                        ["", ""]
                    ]:
                        print(f"        - Contact: {mint_info['contact']}")
                    if mint_info.get("version"):
                        print(f"        - Version: {mint_info['version']}")
                    if mint_info.get("motd"):
                        print(f"        - Message of the day: {mint_info['motd']}")
                    if mint_info.get("time"):
                        print(f"        - Server time: {mint_info['time']}")
                    if mint_info.get("nuts"):
                        nuts_str = ", ".join(
                            [f"NUT-{k}" for k in mint_info["nuts"].keys()]
                        )
                        print(f"        - Supported NUTS: {nuts_str}")
                        print("")
            except Exception as e:
                print("")
                print(f"Error fetching mint information for {mint_url}: {e}")

    if mnemonic:
        assert wallet.mnemonic
        print(f"Mnemonic:\n - {wallet.mnemonic}")
    if settings.env_file:
        print("Settings:")
        print(f"    - File: {settings.env_file}")
    if settings.tor:
        print(f"Tor enabled: {settings.tor}")
    if settings.nostr_private_key:
        try:
            client = NostrClient(private_key=settings.nostr_private_key, connect=False)
            print("Nostr:")
            print(f"    - Public key: {client.public_key.bech32()}")
            print(f"    - Relays: {', '.join(settings.nostr_relays)}")
        except Exception:
            print("Nostr: Error. Invalid key.")
    if settings.socks_proxy:
        print(f"Socks proxy: {settings.socks_proxy}")
    if settings.http_proxy:
        print(f"HTTP proxy: {settings.http_proxy}")
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
    await print_balance(ctx)


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
    await wallet.select_to_send(
        wallet.proofs, mint_balance, set_reserved=True, include_fees=False
    )
    # load all reserved proofs (including the one we just sent)
    reserved_proofs = await get_reserved_proofs(wallet.db)
    if not len(reserved_proofs):
        print("No balance on this mint.")
        return

    token = await wallet.serialize_proofs(reserved_proofs)
    print(f"Selfpay token for mint {wallet.url}:")
    print("")
    print(token)
    token_obj = TokenV4.deserialize(token)
    await receive(wallet, token_obj)
