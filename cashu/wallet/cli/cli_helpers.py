import os
import urllib.parse
from typing import List

import click
from click import Context
from loguru import logger

from ...core.base import (
    Proof,
    TokenV1,
    TokenV2,
    TokenV2Mint,
    TokenV3,
    TokenV3Token,
    WalletKeyset,
)
from ...core.helpers import sum_proofs
from ...core.settings import settings
from ...wallet.crud import get_keyset
from ...wallet.wallet import Wallet as Wallet


async def get_mint_wallet(ctx: Context, force_select: bool = False):
    """
    Helper function that asks the user for an input to select which mint they want to load.
    Useful for selecting the mint that the user wants to send tokens from.
    """
    # we load a dummy wallet so we can check the balance per mint
    wallet: Wallet = ctx.obj["WALLET"]
    await wallet.load_proofs(reload=True)
    mint_balances = await wallet.balance_per_minturl()

    if ctx.obj["HOST"] not in mint_balances and not force_select:
        mint_url = wallet.url
    elif len(mint_balances) > 1:
        # if we have balances on more than one mint, we ask the user to select one
        await print_mint_balances(wallet, show_mints=True)

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
    elif len(mint_balances) == 1:
        mint_url = list(mint_balances.keys())[0]
    else:
        mint_url = wallet.url

    # load this mint_url into a wallet
    mint_wallet = Wallet(
        mint_url,
        os.path.join(settings.cashu_dir, ctx.obj["WALLET_NAME"]),
        name=wallet.name,
    )
    # await mint_wallet.load_mint()
    await mint_wallet.load_proofs(reload=True)

    return mint_wallet


async def print_mint_balances(wallet, show_mints=False):
    """
    Helper function that prints the balances for each mint URL that we have tokens from.
    """
    # get balances per mint
    mint_balances = await wallet.balance_per_minturl()

    # if we have a balance on a non-default mint, we show its URL
    keysets = [k for k, v in wallet.balance_per_keyset().items()]
    for k in keysets:
        ks = await get_keyset(id=str(k), db=wallet.db)
        if ks and ks.mint_url != wallet.url:
            show_mints = True

    # or we have a balance on more than one mint
    # show balances per mint
    if len(mint_balances) > 1 or show_mints:
        print(f"You have balances in {len(mint_balances)} mints:")
        print("")
        for i, (k, v) in enumerate(mint_balances.items()):
            print(
                f"Mint {i+1}: Balance: {v['available']} sat (pending: {v['balance']-v['available']} sat) URL: {k}"
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
    mint_keysets = await get_keyset(mint_url=url, db=mint_wallet.db)
    if mint_keysets is None:
        # we encountered a new mint and ask for a user confirmation
        print("")
        print("Warning: Tokens are from a mint you don't know yet.")
        print("\n")
        print(f"Mint URL: {url}")
        print("\n")
        click.confirm(
            f"Do you trust this mint and want to receive the tokens?",
            abort=True,
            default=True,
        )
    else:
        logger.debug(f"We know keyset {mint_keysets.id} already")
