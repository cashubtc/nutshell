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


async def verify_mints_tokenv2(ctx: Context, token: TokenV2):
    """
    A helper function that iterates through all mints in the token and if it has
    not been encountered before, asks the user to confirm.

    It will instantiate a Wallet with each keyset and check whether the mint supports it.
    It will then get the keys for that keyset from the mint and check whether the keyset id is correct.
    """

    if token.mints is None:
        return
    proofs_keysets = set([p.id for p in token.proofs])

    logger.debug(f"Verifying mints")
    trust_token_mints = True
    for mint in token.mints:
        for keyset in set([id for id in mint.ids if id in proofs_keysets]):
            # init a temporary wallet object
            keyset_wallet = Wallet(
                mint.url, os.path.join(settings.cashu_dir, ctx.obj["WALLET_NAME"])
            )
            # make sure that this mint supports this keyset
            mint_keysets = await keyset_wallet._get_keyset_ids(mint.url)
            assert keyset in mint_keysets, "mint does not have this keyset."

            # we validate the keyset id by fetching the keys from the mint and computing the id locally
            mint_keyset = await keyset_wallet._get_keys_of_keyset(mint.url, keyset)
            assert keyset == mint_keyset.id, Exception("keyset not valid.")

            # we check the db whether we know this mint already and ask the user if not
            mint_keysets = await get_keyset(mint_url=mint.url, db=keyset_wallet.db)
            if mint_keysets is None:
                # we encountered a new mint and ask for a user confirmation
                trust_token_mints = False
                print("")
                print("Warning: Tokens are from a mint you don't know yet.")
                print("\n")
                print(f"Mint URL: {mint.url}")
                print(f"Mint keyset: {keyset}")
                print("\n")
                click.confirm(
                    f"Do you trust this mint and want to receive the tokens?",
                    abort=True,
                    default=True,
                )
                trust_token_mints = True
            else:
                logger.debug(f"We know keyset {mint_keysets.id} already")
    assert trust_token_mints, Exception("Aborted!")


async def redeem_TokenV2_multimint(ctx: Context, token: TokenV2, script, signature):
    """
    Helper function to iterate thruogh a token with multiple mints and redeem them from
    these mints one keyset at a time.
    """
    # we get the mint information in the token and load the keys of each mint
    # we then redeem the tokens for each keyset individually
    if token.mints is None:
        return

    proofs_keysets = set([p.id for p in token.proofs])

    for mint in token.mints:
        for keyset in set([id for id in mint.ids if id in proofs_keysets]):
            logger.debug(f"Redeeming tokens from keyset {keyset}")
            # init a temporary wallet object
            keyset_wallet = Wallet(
                mint.url, os.path.join(settings.cashu_dir, ctx.obj["WALLET_NAME"])
            )

            await keyset_wallet.load_mint()

            # redeem proofs of this keyset
            redeem_proofs = [p for p in token.proofs if p.id == keyset]
            _, _ = await keyset_wallet.redeem(
                redeem_proofs, scnd_script=script, scnd_siganture=signature
            )
            print(f"Received {sum_proofs(redeem_proofs)} sats")


async def redeem_TokenV3_multimint(ctx: Context, token: TokenV3, script, signature):
    """
    Helper function to iterate thruogh a token with multiple mints and redeem them from
    these mints one keyset at a time.
    """
    for t in token.token:
        assert t.mint, Exception("Multimint redeem without URL")
        mint_wallet = Wallet(
            t.mint, os.path.join(settings.cashu_dir, ctx.obj["WALLET_NAME"])
        )
        await verify_mint(mint_wallet, t.mint)
        keysets = mint_wallet._get_proofs_keysets(t.proofs)
        logger.debug(f"Keysets in tokens: {keysets}")
        # loop over all keysets
        for keyset in set(keysets):
            await mint_wallet.load_mint()
            # redeem proofs of this keyset
            redeem_proofs = [p for p in t.proofs if p.id == keyset]
            _, _ = await mint_wallet.redeem(
                redeem_proofs, scnd_script=script, scnd_siganture=signature
            )
            print(f"Received {sum_proofs(redeem_proofs)} sats")


async def print_mint_balances(ctx: Context, wallet, show_mints=False):
    """
    Helper function that prints the balances for each mint URL that we have tokens from.
    """
    # get balances per mint
    mint_balances = await wallet.balance_per_minturl()

    # if we have a balance on a non-default mint, we show its URL
    keysets = [k for k, v in wallet.balance_per_keyset().items()]
    for k in keysets:
        ks = await get_keyset(id=str(k), db=wallet.db)
        if ks and ks.mint_url != ctx.obj["HOST"]:
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


async def get_mint_wallet(ctx: Context):
    """
    Helper function that asks the user for an input to select which mint they want to load.
    Useful for selecting the mint that the user wants to send tokens from.
    """
    # we load a dummy wallet so we can check the balance per mint
    wallet: Wallet = ctx.obj["WALLET"]
    mint_balances = await wallet.balance_per_minturl()

    # if we have balances on more than one mint, we ask the user to select one
    if len(mint_balances) > 1:
        await print_mint_balances(ctx, wallet, show_mints=True)

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
    else:
        mint_url = list(mint_balances.keys())[0]

    # load this mint_url into a wallet
    mint_wallet = Wallet(
        mint_url, os.path.join(settings.cashu_dir, ctx.obj["WALLET_NAME"])
    )
    await mint_wallet.load_mint()

    return mint_wallet


async def serialize_TokenV2_to_TokenV3(wallet: Wallet, tokenv2: TokenV2):
    """Helper function for the CLI to receive legacy TokenV2 tokens.
    Takes a list of proofs and constructs a *serialized* TokenV3 to be received through
    the ordinary path.

    Returns:
        TokenV3: TokenV3
    """
    tokenv3 = TokenV3(token=[TokenV3Token(proofs=tokenv2.proofs)])
    if tokenv2.mints:
        tokenv3.token[0].mint = tokenv2.mints[0].url
    token_serialized = tokenv3.serialize()
    return token_serialized


async def serialize_TokenV1_to_TokenV3(wallet: Wallet, tokenv1: TokenV1):
    """Helper function for the CLI to receive legacy TokenV1 tokens.
    Takes a list of proofs and constructs a *serialized* TokenV3 to be received through
    the ordinary path.

    Returns:
        TokenV3: TokenV3
    """
    tokenv3 = TokenV3(token=[TokenV3Token(proofs=tokenv1.__root__)])
    token_serialized = tokenv3.serialize()
    return token_serialized
