import asyncio
import os
import threading
import urllib.parse
from typing import List

import click
from click import Context
from loguru import logger

from cashu.core.base import Proof, TokenV2, TokenV2Mint, WalletKeyset
from cashu.core.helpers import sum_proofs
from cashu.core.settings import CASHU_DIR, MINT_URL, NOSTR_PRIVATE_KEY, NOSTR_RELAYS
from cashu.nostr.nostr.client.client import NostrClient
from cashu.nostr.nostr.event import Event
from cashu.nostr.nostr.key import PublicKey
from cashu.wallet.crud import get_keyset
from cashu.wallet.wallet import Wallet as Wallet


async def verify_mints(ctx: Context, token: TokenV2):
    """
    A helper function that iterates through all mints in the token and if it has
    not been encountered before, asks the user to confirm.

    It will instantiate a Wallet with each keyset and check whether the mint supports it.
    It will then get the keys for that keyset from the mint and check whether the keyset id is correct.
    """

    if token.mints is None:
        return
    logger.debug(f"Verifying mints")
    trust_token_mints = True
    for mint in token.mints:
        for keyset in set(mint.ids):
            # init a temporary wallet object
            keyset_wallet = Wallet(
                mint.url, os.path.join(CASHU_DIR, ctx.obj["WALLET_NAME"])
            )
            # make sure that this mint supports this keyset
            mint_keysets = await keyset_wallet._get_keyset_ids(mint.url)
            assert keyset in mint_keysets["keysets"], "mint does not have this keyset."

            # we validate the keyset id by fetching the keys from the mint and computing the id locally
            mint_keyset = await keyset_wallet._get_keyset(mint.url, keyset)
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


async def redeem_multimint(ctx: Context, token: TokenV2, script, signature):
    """
    Helper function to iterate thruogh a token with multiple mints and redeem them from
    these mints one keyset at a time.
    """
    # we get the mint information in the token and load the keys of each mint
    # we then redeem the tokens for each keyset individually
    if token.mints is None:
        return

    for mint in token.mints:
        for keyset in set(mint.ids):
            logger.debug(f"Redeeming tokens from keyset {keyset}")
            # init a temporary wallet object
            keyset_wallet = Wallet(
                mint.url, os.path.join(CASHU_DIR, ctx.obj["WALLET_NAME"])
            )

            # load the keys
            await keyset_wallet.load_mint(keyset_id=keyset)

            # redeem proofs of this keyset
            redeem_proofs = [p for p in token.proofs if p.id == keyset]
            _, _ = await keyset_wallet.redeem(
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
    wallet: Wallet = ctx.obj["WALLET"]
    await wallet.load_mint()

    mint_balances = await wallet.balance_per_minturl()

    if len(mint_balances) > 1:
        await print_mint_balances(ctx, wallet, show_mints=True)

        mint_nr_str = (
            input(f"Select mint [1-{len(mint_balances)}, press enter for default 1]: ")
            or "1"
        )
        if not mint_nr_str.isdigit():
            raise Exception("invalid input.")
        mint_nr = int(mint_nr_str)
    else:
        mint_nr = 1

    mint_url = list(mint_balances.keys())[mint_nr - 1]

    # load this mint_url into a wallet
    mint_wallet = Wallet(mint_url, os.path.join(CASHU_DIR, ctx.obj["WALLET_NAME"]))
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


async def proofs_to_serialized_tokenv2(wallet, proofs: List[Proof], url: str):
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

    url = url or (
        input(f"Enter mint URL (press enter for default {MINT_URL}): ") or MINT_URL
    )

    token.mints.append(TokenV2Mint(url=url, ids=keysets))
    token_serialized = await wallet._serialize_token_base64(token)
    return token_serialized


async def send_nostr(ctx: Context, amount: int, pubkey: str, verbose: bool, yes: bool):
    """
    Sends tokens via nostr.
    """
    # load a wallet for the chosen mint
    wallet = await get_mint_wallet(ctx)
    await wallet.load_proofs()
    _, send_proofs = await wallet.split_to_send(
        wallet.proofs, amount, set_reserved=True
    )
    token = await wallet.serialize_proofs(send_proofs)

    print("")
    print(token)

    if not yes:
        print("")
        click.confirm(
            f"Send {amount} sat to nostr pubkey {pubkey}?",
            abort=True,
            default=True,
        )

    # we only use ephemeral private keys for sending
    client = NostrClient(relays=NOSTR_RELAYS)
    if verbose:
        print(f"Your ephemeral nostr private key: {client.private_key.hex()}")
    await asyncio.sleep(1)
    client.dm(token, PublicKey(bytes.fromhex(pubkey)))
    print(f"Token sent to {pubkey}")
    client.close()


async def receive_nostr(ctx: Context, verbose: bool):
    if NOSTR_PRIVATE_KEY is None:
        print(
            "Warning: No nostr private key set! You don't have NOSTR_PRIVATE_KEY set in your .env file. I will create a random private key for this session but I will not remember it."
        )
        print("")
    client = NostrClient(privatekey_hex=NOSTR_PRIVATE_KEY, relays=NOSTR_RELAYS)
    print(f"Your nostr public key: {client.public_key.hex()}")
    if verbose:
        print(f"Your nostr private key (do not share!): {client.private_key.hex()}")
    await asyncio.sleep(2)

    def get_token_callback(event: Event, decrypted_content):
        if verbose:
            print(
                f"From {event.public_key[:3]}..{event.public_key[-3:]}: {decrypted_content}"
            )
        try:
            # call the receive method
            from cashu.wallet.cli import receive

            asyncio.run(receive(ctx, decrypted_content, ""))
        except Exception as e:
            pass

    t = threading.Thread(
        target=client.get_dm,
        args=(
            client.public_key,
            get_token_callback,
        ),
        name="Nostr DM",
    )
    t.start()
