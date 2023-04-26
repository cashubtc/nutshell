import asyncio
import threading
import time

import click
from fastapi import HTTPException, status
from requests.exceptions import ConnectionError

from cashu.core.settings import settings
from cashu.nostr.nostr.client.client import NostrClient
from cashu.nostr.nostr.event import Event
from cashu.nostr.nostr.key import PublicKey
from cashu.wallet.crud import (
    get_nostr_last_check_timestamp,
    set_nostr_last_check_timestamp,
)
from cashu.wallet.helpers import get_mint_wallet, receive
from cashu.wallet.wallet import Wallet


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
        resp = wallet.s.get(
            f"https://{host}/.well-known/nostr.json?name={user}",
        )
        resp.raise_for_status()
    except ConnectionError:
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
    amount: int,
    pubkey: str,
    verbose: bool = False,
    yes: bool = True,
    is_api: bool = False,
    specific_mint: int = None
):
    """
    Sends tokens via nostr.
    """
    # load a wallet for the chosen mint
    wallet = await get_mint_wallet(wallet, is_api=is_api, specific_mint=specific_mint)

    if "@" in pubkey or "." in pubkey:
        # matches user@domain.com and domain.com (which is _@domain.com)
        pubkey = await nip5_to_pubkey(wallet, pubkey)

    await wallet.load_proofs()
    _, send_proofs = await wallet.split_to_send(
        wallet.proofs, amount, set_reserved=True
    )
    token = await wallet.serialize_proofs(send_proofs)

    if pubkey.startswith("npub"):
        pubkey_to = PublicKey().from_npub(pubkey)
    else:
        pubkey_to = PublicKey(bytes.fromhex(pubkey))

    if not is_api:
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
    if not is_api:
        print(f"Token sent to {pubkey_to.bech32()}")
    await asyncio.sleep(5)
    client.close()
    return token, pubkey_to.bech32()


async def receive_nostr(wallet: Wallet, verbose: bool = False, is_api: bool = False):
    if settings.nostr_private_key is None:
        if is_api:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="nostr private key is missing.",
            )
        else:
            print(
                "Warning: No nostr private key set! You don't have NOSTR_PRIVATE_KEY set in your .env file. "
                "I will create a random private key for this session but I will not remember it."
            )
            print("")
    client = NostrClient(
        private_key=settings.nostr_private_key, relays=settings.nostr_relays
    )
    if not is_api:
        print(f"Your nostr public key: {client.public_key.bech32()}")
        if verbose:
            print(
                f"Your nostr private key (do not share!): {client.private_key.bech32()}"
            )
        await asyncio.sleep(2)

    def get_token_callback(event: Event, decrypted_content):
        if verbose and not is_api:
            print(
                f"From {event.public_key[:3]}..{event.public_key[-3:]}: {decrypted_content}"
            )
        try:
            # call the receive method
            asyncio.run(receive(wallet, decrypted_content, ""))
        except Exception as e:
            pass

    # determine timestamp of last check so we don't scan all historical DMs
    last_check = await get_nostr_last_check_timestamp(db=wallet.db)
    if last_check:
        last_check -= 60 * 60  # 1 hour tolerance
    await set_nostr_last_check_timestamp(timestamp=int(time.time()), db=wallet.db)

    t = threading.Thread(
        target=client.get_dm,
        args=(client.public_key, get_token_callback, {"since": last_check}),
        name="Nostr DM",
    )
    t.start()
