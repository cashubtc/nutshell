import asyncio
import datetime
import threading

import click
from httpx import ConnectError
from loguru import logger

from cashu.core.base import TokenV3

from ..core.settings import settings
from ..nostr.client.client import NostrClient
from ..nostr.event import Event
from ..nostr.key import PublicKey
from .crud import get_nostr_last_check_timestamp, set_nostr_last_check_timestamp
from .helpers import deserialize_token_from_string, receive
from .wallet import Wallet


async def nip5_to_pubkey(wallet: Wallet, address: str):
    """
    Retrieves the nostr public key of a NIP-05 identifier.
    """
    # we will be using the requests session from the wallet
    await wallet._init_s()
    # if no username is given, use default _ (NIP-05 stuff)
    if "@" not in address:
        address = "_@" + address
    # now we can use it
    user, host = address.split("@")
    resp_dict = {}
    try:
        resp = await wallet.httpx.get(
            f"https://{host}/.well-known/nostr.json?name={user}",
        )
        resp.raise_for_status()
    except ConnectError:
        raise Exception(f"Could not connect to {host}")
    except Exception as e:
        raise e
    resp_dict = resp.json()
    assert "names" in resp_dict, Exception(f"did not receive any names from {host}")
    assert user in resp_dict["names"], Exception(f"{user}@{host} not found")
    pubkey = resp_dict["names"][user]
    return pubkey


async def send_nostr(
    wallet: Wallet,
    *,
    amount: int,
    pubkey: str,
    verbose: bool = False,
    yes: bool = True,
    include_dleq=False,
):
    """
    Sends tokens via nostr.
    """

    if "@" in pubkey or "." in pubkey:
        # matches user@domain.com and domain.com (which is _@domain.com)
        pubkey = await nip5_to_pubkey(wallet, pubkey)
    await wallet.load_mint()
    await wallet.load_proofs()
    _, send_proofs = await wallet.split_to_send(
        wallet.proofs, amount, set_reserved=True
    )
    token = await wallet.serialize_proofs(send_proofs, include_dleq=include_dleq)

    if pubkey.startswith("npub"):
        pubkey_to = PublicKey().from_npub(pubkey)
    else:
        pubkey_to = PublicKey(bytes.fromhex(pubkey))

    print("")
    print(token)

    if not yes:
        print("")
        click.confirm(
            f"Send {amount} sat to {pubkey_to.bech32()}?",
            abort=True,
            default=True,
        )

    client = NostrClient(
        private_key=settings.nostr_private_key or "", relays=settings.nostr_relays
    )
    if verbose and not settings.nostr_private_key:
        # we generated a random key if none was present
        print(f"Your nostr private key: {client.private_key.bech32()}")

    client.dm(token, pubkey_to)
    print(f"Token sent to {pubkey_to.bech32()}")
    await asyncio.sleep(1)
    client.close()
    return token, pubkey_to.bech32()


async def receive_nostr(
    wallet: Wallet,
) -> NostrClient:
    if settings.nostr_private_key is None:
        print(
            "Warning: No nostr private key set! You don't have NOSTR_PRIVATE_KEY set in"
            " your .env file. I will create a random private key for this session but I"
            " will not remember it."
        )
        print("")
    client = NostrClient(
        private_key=settings.nostr_private_key, relays=settings.nostr_relays
    )
    print(f"Your nostr public key: {client.public_key.bech32()}")
    # print(f"Your nostr private key (do not share!): {client.private_key.bech32()}")
    await asyncio.sleep(2)

    def get_token_callback(event: Event, decrypted_content: str):
        date_str = datetime.datetime.fromtimestamp(event.created_at).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        logger.debug(
            f"From {event.public_key[:3]}..{event.public_key[-3:]} on {date_str}:"
            f" {decrypted_content}"
        )
        # split the content into words
        words = decrypted_content.split(" ")
        for w in words:
            try:
                logger.trace(
                    "Nostr: setting last check timestamp to"
                    f" {event.created_at} ({date_str})"
                )
                # call the receive method
                tokenObj: TokenV3 = deserialize_token_from_string(w)
                print(
                    f"Receiving {tokenObj.get_amount()} sat on mint"
                    f" {tokenObj.get_mints()[0]} from nostr user {event.public_key} at"
                    f" {date_str}"
                )
                asyncio.run(
                    receive(
                        wallet,
                        tokenObj,
                    )
                )
                asyncio.run(
                    set_nostr_last_check_timestamp(
                        timestamp=event.created_at, db=wallet.db
                    )
                )

            except Exception as e:
                logger.debug(e)
                pass

    # determine timestamp of last check so we don't scan all historical DMs
    last_check = await get_nostr_last_check_timestamp(db=wallet.db)
    if last_check:
        date_str = datetime.datetime.fromtimestamp(last_check).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        logger.debug(f"Last check: {date_str}")
        last_check -= 60 * 60  # 1 hour tolerance

    logger.debug("Starting Nostr DM thread")
    t = threading.Thread(
        target=client.get_dm,
        args=(client.public_key, get_token_callback, {"since": last_check}),
        name="Nostr DM",
    )
    t.start()
    return client
