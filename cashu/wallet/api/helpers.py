import base64
import json
import os
import urllib.parse
from typing import List

import click
from fastapi import HTTPException, status
from loguru import logger

from cashu.core.base import Proof, TokenV2, TokenV2Mint
from cashu.core.helpers import sum_proofs
from cashu.core.settings import settings
from cashu.wallet.crud import get_keyset, get_unused_locks
from cashu.wallet.wallet import Wallet as Wallet


async def verify_mints(wallet: Wallet, token: TokenV2, is_api: bool = False):
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
                mint.url, os.path.join(settings.cashu_dir, wallet.name)
            )
            # make sure that this mint supports this keyset
            mint_keysets = await keyset_wallet._get_keyset_ids(mint.url)
            if is_api:
                assert keyset in mint_keysets, HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="mint does not have this keyset.",
                )
            else:
                assert keyset in mint_keysets, "mint does not have this keyset."

            # we validate the keyset id by fetching the keys from the mint and computing the id locally
            mint_keyset = await keyset_wallet._get_keys_of_keyset(mint.url, keyset)
            if is_api:
                assert keyset == mint_keyset.id, HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="keyset not valid."
                )
            else:
                assert keyset == mint_keyset.id, Exception("keyset not valid.")

            # we check the db whether we know this mint already and ask the user if not
            mint_keysets = await get_keyset(mint_url=mint.url, db=keyset_wallet.db)
            if mint_keysets is None:
                if is_api:
                    # via api new mint is trusted
                    trust_token_mints = True
                else:
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
    if not is_api:
        assert trust_token_mints, Exception("Aborted!")


async def redeem_multimint(
    wallet: Wallet, token: TokenV2, script, signature, is_api: bool = False
):
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
                mint.url, os.path.join(settings.cashu_dir, wallet.name)
            )

            # load the keys
            await keyset_wallet.load_mint(keyset_id=keyset)

            # redeem proofs of this keyset
            redeem_proofs = [p for p in token.proofs if p.id == keyset]
            _, _ = await keyset_wallet.redeem(
                redeem_proofs, scnd_script=script, scnd_siganture=signature
            )
            if not is_api:
                print(f"Received {sum_proofs(redeem_proofs)} sats")


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


async def get_mint_wallet(wallet: Wallet, is_api: bool = False):
    """
    Helper function that asks the user for an input to select which mint they want to load.
    Useful for selecting the mint that the user wants to send tokens from.
    """
    await wallet.load_mint()

    mint_balances = await wallet.balance_per_minturl()

    if len(mint_balances) > 1:
        if not is_api:
            await print_mint_balances(wallet, show_mints=True)

        url_max = max(mint_balances, key=lambda v: mint_balances[v]["available"])
        nr_max = list(mint_balances).index(url_max) + 1

        if is_api:
            mint_nr_str = None
        else:
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
            if is_api:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="invalid input."
                )
            else:
                raise Exception("invalid input.")
    else:
        mint_url = list(mint_balances.keys())[0]

    # load this mint_url into a wallet
    mint_wallet = Wallet(mint_url, os.path.join(settings.cashu_dir, wallet.name))
    mint_keysets: WalletKeyset = await get_keyset(mint_url=mint_url, db=mint_wallet.db)  # type: ignore

    # load the keys
    assert mint_keysets.id
    await mint_wallet.load_mint(keyset_id=mint_keysets.id)

    return mint_wallet


# LNbits token link parsing
# can extract minut URL from LNbits token links like:
# https://lnbits.server/cashu/wallet?mint_id=aMintId&recv_token=W3siaWQiOiJHY2...
def token_from_lnbits_link(link):
    url, token = "", ""
    if len(link.split("&recv_token=")) == 2:
        # extract URL params
        params = urllib.parse.parse_qs(link.split("?")[1])
        # extract URL
        if "mint_id" in params:
            url = (
                link.split("?")[0].split("/wallet")[0]
                + "/api/v1/"
                + params["mint_id"][0]
            )
        # extract token
        token = params["recv_token"][0]
        return token, url
    else:
        return link, ""


async def proofs_to_serialized_tokenv2(
    wallet, proofs: List[Proof], url: str, is_api: bool = False
):
    """
    Ingests list of proofs and produces a serialized TokenV2
    """
    # and add url and keyset id to token
    token: TokenV2 = await wallet._make_token(proofs, include_mints=False)
    token.mints = []

    # get keysets of proofs
    keysets = list(set([p.id for p in proofs if p.id is not None]))

    # check whether we know the mint urls for these proofs
    for k in keysets:
        ks = await get_keyset(id=k, db=wallet.db)
        url = ks.mint_url if ks and ks.mint_url else ""

    if is_api:
        url = settings.mint_url
    else:
        url = url or (
            input(f"Enter mint URL (press enter for default {settings.mint_url}): ")
            or settings.mint_url
        )

    token.mints.append(TokenV2Mint(url=url, ids=keysets))
    token_serialized = await wallet._serialize_token_base64(token)
    return token_serialized


async def receive(wallet: Wallet, token: str, lock: str, is_api: bool = False):
    await wallet.load_mint()

    # check for P2SH locks
    if lock:
        # load the script and signature of this address from the database
        if is_api:
            assert len(lock.split("P2SH:")) == 2, HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="lock has wrong format. Expected P2SH:<address>.",
            )
        else:
            assert len(lock.split("P2SH:")) == 2, Exception(
                "lock has wrong format. Expected P2SH:<address>."
            )
        address_split = lock.split("P2SH:")[1]
        p2shscripts = await get_unused_locks(address_split, db=wallet.db)
        if is_api:
            assert len(p2shscripts) == 1, HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="lock not found."
            )
        else:
            assert len(p2shscripts) == 1, Exception("lock not found.")
        script, signature = p2shscripts[0].script, p2shscripts[0].signature
    else:
        script, signature = None, None

        # deserialize token

        # ----- backwards compatibility -----

        # we support old tokens (< 0.7) without mint information and (W3siaWQ...)
        # new tokens (>= 0.7) with multiple mint support (eyJ0b2...)
        try:
            # backwards compatibility: tokens without mint information
            # supports tokens of the form W3siaWQiOiJH

            # if it's an lnbits https:// link with a token as an argument, speacial treatment
            token, url = token_from_lnbits_link(token)

            # assume W3siaWQiOiJH.. token
            # next line trows an error if the desirialization with the old format doesn't
            # work and we can assume it's the new format
            proofs = [Proof(**p) for p in json.loads(base64.urlsafe_b64decode(token))]

            # we take the proofs parsed from the old format token and produce a new format token with it
            token = await proofs_to_serialized_tokenv2(
                wallet, proofs, url, is_api=is_api
            )
        except:
            pass

        # ----- receive token -----

        # deserialize token
        dtoken = json.loads(base64.urlsafe_b64decode(token))

        # backwards compatibility wallet to wallet < 0.8.0: V2 tokens renamed "tokens" field to "proofs"
        if "tokens" in dtoken:
            dtoken["proofs"] = dtoken.pop("tokens")

        # backwards compatibility wallet to wallet < 0.8.3: V2 tokens got rid of the "MINT_NAME" key in "mints" and renamed "ks" to "ids"
        if "mints" in dtoken and isinstance(dtoken["mints"], dict):
            dtoken["mints"] = list(dtoken["mints"].values())
            for m in dtoken["mints"]:
                m["ids"] = m.pop("ks")

        tokenObj = TokenV2.parse_obj(dtoken)
        if is_api:
            assert len(tokenObj.proofs), HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="no proofs in token."
            )
        else:
            assert len(tokenObj.proofs), Exception("no proofs in token")
        includes_mint_info: bool = (
            tokenObj.mints is not None and len(tokenObj.mints) > 0
        )

        # if there is a `mints` field in the token
        # we check whether the token has mints that we don't know yet
        # and ask the user if they want to trust the new mints
        if includes_mint_info:
            # we ask the user to confirm any new mints the tokens may include
            await verify_mints(wallet, tokenObj, is_api=is_api)
            # redeem tokens with new wallet instances
            await redeem_multimint(wallet, tokenObj, script, signature, is_api=is_api)
            # reload main wallet so the balance updates
            await wallet.load_proofs()
        else:
            # no mint information present, we extract the proofs and use wallet's default mint
            proofs = [Proof(**p) for p in dtoken["proofs"]]
            _, _ = await wallet.redeem(proofs, script, signature)
            if not is_api:
                print(f"Received {sum_proofs(proofs)} sats")

    return wallet.available_balance


async def send(
    wallet: Wallet, amount: int, lock: str, legacy: bool, is_api: bool = False
):
    """
    Prints token to send to stdout.
    """
    if lock and len(lock) < 22:
        if is_api:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="lock has to be at least 22 characters long.",
            )
        else:
            print("Error: lock has to be at least 22 characters long.")
            return
    p2sh = False
    if lock and len(lock.split("P2SH:")) == 2:
        p2sh = True

    wallet = await get_mint_wallet(wallet, is_api=is_api)
    await wallet.load_proofs()

    _, send_proofs = await wallet.split_to_send(
        wallet.proofs, amount, lock, set_reserved=True
    )
    token = await wallet.serialize_proofs(
        send_proofs,
        include_mints=True,
    )
    if not is_api:
        print(token)

    if legacy:
        if not is_api:
            print("")
            print(
                "Legacy token without mint information for older clients. "
                "This token can only be be received by wallets who use the mint the token is issued from:"
            )
            print("")
        token = await wallet.serialize_proofs(
            send_proofs,
            legacy=True,
        )
        if not is_api:
            print(token)

    return wallet.available_balance, token
