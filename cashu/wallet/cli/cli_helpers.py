#!/usr/bin/env python
import os
from itertools import groupby
from operator import itemgetter

import click
from click import Context
from loguru import logger

from ...core.base import Unit
from ...core.settings import settings
from ...wallet.crud import (
    get_keysets,
    get_reserved_proofs,
)
from ...wallet.wallet import Wallet as Wallet
from ..helpers import (
    deserialize_token_from_string,
    receive,
)


async def print_balance(ctx: Context):
    wallet: Wallet = ctx.obj["WALLET"]
    await wallet.load_proofs(reload=True)
    print(f"Balance: {wallet.available_balance}")


async def get_unit_wallet(ctx: Context, force_select: bool = False):
    """Helper function that asks the user for an input to select which unit they want to load.

    Args:
        ctx (Context): Context
        force_select (bool, optional): Force the user to select a unit. Defaults to False.
    """
    wallet: Wallet = ctx.obj["WALLET"]
    await wallet.load_proofs(reload=False)
    # show balances per unit
    unit_balances = wallet.balance_per_unit()

    logger.debug(f"Wallet URL: {wallet.url}")
    logger.debug(f"Wallet unit: {wallet.unit}")
    logger.debug(f"mint_balances: {unit_balances}")
    logger.debug(f"ctx.obj['UNIT']: {ctx.obj['UNIT']}")

    if len(unit_balances) > 1 and not ctx.obj["UNIT"]:
        print(f"You have balances in {len(unit_balances)} units:")
        print("")
        for i, (k, v) in enumerate(unit_balances.items()):
            unit = k
            print(f"Unit {i+1} ({unit}) – Balance: {unit.str(int(v['available']))}")
        print("")
        unit_nr_str = input(
            f"Select unit [1-{len(unit_balances)}] or "
            f"press enter for your default '{Unit[settings.wallet_unit]}': "
        )
        if not unit_nr_str:  # default unit
            unit = Unit[settings.wallet_unit]
        elif unit_nr_str.isdigit() and int(unit_nr_str) <= len(
            unit_balances
        ):  # specific unit
            unit = list(unit_balances.keys())[int(unit_nr_str) - 1]
        else:
            raise Exception("invalid input.")

        print(f"Selected unit: {unit}")
        print("")
        # load this unit into a wallet
        wallet.unit = unit
    elif len(unit_balances) == 1 and not ctx.obj["UNIT"]:
        wallet.unit = list(unit_balances.keys())[0]
    elif ctx.obj["UNIT"]:
        wallet.unit = Unit[ctx.obj["UNIT"]]
    settings.wallet_unit = wallet.unit.name
    return wallet


async def get_mint_wallet(ctx: Context, force_select: bool = False):
    """
    Helper function that asks the user for an input to select which mint they want to load.
    Useful for selecting the mint that the user wants to send tokens from.
    """
    # we load a dummy wallet so we can check the balance per mint
    wallet: Wallet = ctx.obj["WALLET"]
    await wallet.load_proofs(reload=True, all_keysets=True)
    mint_balances = await wallet.balance_per_minturl(unit=wallet.unit)
    logger.debug(f"Wallet URL: {wallet.url}")
    logger.debug(f"Wallet unit: {wallet.unit}")
    logger.debug(f"mint_balances: {mint_balances}")
    logger.debug(f"ctx.obj['HOST']: {ctx.obj['HOST']}")
    if len(mint_balances) > 1:
        # if we have balances on more than one mint, we ask the user to select one
        await print_mint_balances(wallet, show_mints=True, mint_balances=mint_balances)

        url_max = max(mint_balances, key=lambda v: mint_balances[v]["available"])
        nr_max = list(mint_balances).index(url_max) + 1

        mint_nr_str = input(
            f"Select mint [1-{len(mint_balances)}] or "
            f"press enter for mint with largest balance (Mint {nr_max}): "
        )
        if not mint_nr_str:  # largest balance
            mint_url = url_max
        elif mint_nr_str.isdigit() and int(mint_nr_str) <= len(
            mint_balances
        ):  # specific mint
            mint_url = list(mint_balances.keys())[int(mint_nr_str) - 1]
        else:
            raise Exception("invalid input.")
    elif ctx.obj["HOST"] and ctx.obj["HOST"] not in mint_balances.keys():
        mint_url = ctx.obj["HOST"]
    elif len(mint_balances) == 1:
        mint_url = list(mint_balances.keys())[0]

    # load this mint_url into a wallet
    mint_wallet = await Wallet.with_db(
        mint_url,
        os.path.join(settings.cashu_dir, ctx.obj["WALLET_NAME"]),
        name=wallet.name,
        unit=wallet.unit.name,
    )
    await mint_wallet.load_proofs(reload=True)

    return mint_wallet


async def print_mint_balances(
    wallet: Wallet, show_mints: bool = False, mint_balances=None
):
    """
    Helper function that prints the balances for each mint URL that we have tokens from.
    """
    # get balances per mint
    mint_balances = mint_balances or await wallet.balance_per_minturl(unit=wallet.unit)
    logger.trace(mint_balances)
    # if we have a balance on a non-default mint, we show its URL
    keysets = [k for k, v in wallet.balance_per_keyset().items()]
    for k in keysets:
        keysets_local = await get_keysets(id=str(k), db=wallet.db)
        for kl in keysets_local:
            if kl and kl.mint_url != wallet.url:
                show_mints = True

    # or we have a balance on more than one mint
    # show balances per mint
    if len(mint_balances) > 1 or show_mints:
        print(f"You have balances in {len(mint_balances)} mints:")
        print("")
        for i, (k, v) in enumerate(mint_balances.items()):
            unit = Unit[str(v["unit"])]
            print(
                f"Mint {i+1}: Balance: {unit.str(int(v['available']))} (pending:"
                f" {unit.str(int(v['balance'])-int(v['available']))}) URL: {k}"
            )
        print("")


async def verify_mint(mint_wallet: Wallet, url: str):
    """A helper function that asks the user if they trust the mint if the user
    has not encountered the mint before (there is no entry in the database).

    Throws an Exception if the user chooses to not trust the mint.
    """
    logger.debug(f"Verifying mint {url}")
    # dummy Wallet to check the database later
    # mint_wallet = Wallet(url, os.path.join(settings.cashu_dir, ctx.obj["WALLET_NAME"]))
    # we check the db whether we know this mint already and ask the user if not
    mint_keysets = await get_keysets(mint_url=url, db=mint_wallet.db)
    if mint_keysets is None:
        # we encountered a new mint and ask for a user confirmation
        print("")
        print("Warning: Tokens are from a mint you don't know yet.")
        print("\n")
        print(f"Mint URL: {url}")
        print("\n")
        click.confirm(
            "Do you trust this mint and want to receive the tokens?",
            abort=True,
            default=True,
        )
    else:
        logger.debug(f"We know mint {url} already")


async def receive_all_pending(ctx: Context, wallet: Wallet):
    reserved_proofs = await get_reserved_proofs(wallet.db)
    if not len(reserved_proofs):
        print("No pending proofs to receive.")
        return
    for key, value in groupby(reserved_proofs, key=itemgetter("send_id")):  # type: ignore
        mint_url = None
        token_obj = None
        try:
            proofs = list(value)
            mint_url, unit = await wallet._get_proofs_mint_unit(proofs)
            mint_wallet = await Wallet.with_db(
                url=mint_url,
                db=os.path.join(settings.cashu_dir, wallet.name),
                name=wallet.name,
                unit=unit.name,
            )
            # verify that we trust the mint of this token
            # ask the user if they want to trust the mint
            await verify_mint(mint_wallet, mint_url)

            token = await mint_wallet.serialize_proofs(proofs)
            token_obj = deserialize_token_from_string(token)
            mint_url = token_obj.mint
            receive_wallet = await receive(mint_wallet, token_obj)
            ctx.obj["WALLET"] = receive_wallet
        except Exception as e:
            if mint_url and token_obj:
                unit = Unit[token_obj.unit]
                print(
                    f"Could not receive {unit.str(token_obj.amount)} from mint {mint_url}: {e}"
                )
            else:
                print(f"Could not receive token: {e}")
            continue
