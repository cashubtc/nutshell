import base64
import json
import os

from loguru import logger

from ..core.base import TokenV1, TokenV2, TokenV3, TokenV3Token
from ..core.db import Database
from ..core.helpers import sum_proofs
from ..core.migrations import migrate_databases
from ..core.settings import settings
from ..wallet import migrations
from ..wallet.crud import get_keysets
from ..wallet.wallet import Wallet


async def migrate_wallet_db(db: Database):
    await migrate_databases(db, migrations)


async def init_wallet(wallet: Wallet, load_proofs: bool = True):
    """Performs migrations and loads proofs from db."""
    await wallet._migrate_database()
    await wallet._init_private_key()
    if load_proofs:
        await wallet.load_proofs(reload=True)


async def list_mints(wallet: Wallet):
    await wallet.load_proofs()
    balances = await wallet.balance_per_minturl()
    mints = list(balances.keys())
    if wallet.url not in mints:
        mints.append(wallet.url)
    return mints


async def redeem_TokenV3_multimint(wallet: Wallet, token: TokenV3):
    """
    Helper function to iterate thruogh a token with multiple mints and redeem them from
    these mints one keyset at a time.
    """
    for t in token.token:
        assert t.mint, Exception(
            "redeem_TokenV3_multimint: multimint redeem without URL"
        )
        mint_wallet = await Wallet.with_db(
            t.mint, os.path.join(settings.cashu_dir, wallet.name)
        )
        keyset_ids = mint_wallet._get_proofs_keysets(t.proofs)
        logger.trace(f"Keysets in tokens: {keyset_ids}")
        # loop over all keysets
        for keyset_id in set(keyset_ids):
            await mint_wallet.load_mint(keyset_id)
            mint_wallet.unit = mint_wallet.keysets[keyset_id].unit
            # redeem proofs of this keyset
            redeem_proofs = [p for p in t.proofs if p.id == keyset_id]
            _, _ = await mint_wallet.redeem(redeem_proofs)
            print(f"Received {mint_wallet.unit.str(sum_proofs(redeem_proofs))}")


def serialize_TokenV2_to_TokenV3(tokenv2: TokenV2):
    """Helper function to receive legacy TokenV2 tokens.
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


def serialize_TokenV1_to_TokenV3(tokenv1: TokenV1):
    """Helper function to receive legacy TokenV1 tokens.
    Takes a list of proofs and constructs a *serialized* TokenV3 to be received through
    the ordinary path.

    Returns:
        TokenV3: TokenV3
    """
    tokenv3 = TokenV3(token=[TokenV3Token(proofs=tokenv1.__root__)])
    token_serialized = tokenv3.serialize()
    return token_serialized


def deserialize_token_from_string(token: str) -> TokenV3:
    # deserialize token

    # ----- backwards compatibility -----

    # V2Tokens (0.7-0.11.0) (eyJwcm9...)
    if token.startswith("eyJwcm9"):
        try:
            tokenv2 = TokenV2.parse_obj(json.loads(base64.urlsafe_b64decode(token)))
            token = serialize_TokenV2_to_TokenV3(tokenv2)
        except Exception:
            pass

    # V1Tokens (<0.7) (W3siaWQ...)
    if token.startswith("W3siaWQ"):
        try:
            tokenv1 = TokenV1.parse_obj(json.loads(base64.urlsafe_b64decode(token)))
            token = serialize_TokenV1_to_TokenV3(tokenv1)
        except Exception:
            pass

    if token.startswith("cashu"):
        tokenObj = TokenV3.deserialize(token)
        assert len(tokenObj.token), Exception("no proofs in token")
        assert len(tokenObj.token[0].proofs), Exception("no proofs in token")
        return tokenObj

    raise Exception("Invalid token")


async def receive(
    wallet: Wallet,
    tokenObj: TokenV3,
):
    logger.debug(f"receive: {tokenObj}")
    proofs = [p for t in tokenObj.token for p in t.proofs]

    includes_mint_info: bool = any([t.mint for t in tokenObj.token])

    if includes_mint_info:
        # redeem tokens with new wallet instances
        await redeem_TokenV3_multimint(
            wallet,
            tokenObj,
        )
    else:
        # this is very legacy code, virtually any token should have mint information
        # no mint information present, we extract the proofs and use wallet's default mint
        # first we load the mint URL from the DB
        keyset_in_token = proofs[0].id
        assert keyset_in_token
        # we get the keyset from the db
        mint_keysets = await get_keysets(id=keyset_in_token, db=wallet.db)
        assert mint_keysets, Exception(f"we don't know this keyset: {keyset_in_token}")
        mint_keyset = mint_keysets[0]
        assert mint_keyset.mint_url, Exception("we don't know this mint's URL")
        # now we have the URL
        mint_wallet = await Wallet.with_db(
            mint_keyset.mint_url,
            os.path.join(settings.cashu_dir, wallet.name),
        )
        await mint_wallet.load_mint(keyset_in_token)
        _, _ = await mint_wallet.redeem(proofs)
        print(f"Received {mint_wallet.unit.str(sum_proofs(proofs))}")

    # reload main wallet so the balance updates
    await wallet.load_proofs(reload=True)
    return wallet.available_balance


async def send(
    wallet: Wallet,
    *,
    amount: int,
    lock: str,
    legacy: bool,
    split: bool = True,
    include_dleq: bool = False,
):
    """
    Prints token to send to stdout.
    """
    secret_lock = None
    if lock:
        assert len(lock) > 21, Exception(
            "Error: lock has to be at least 22 characters long."
        )
        if not lock.startswith("P2PK:"):
            raise Exception("Error: lock has to start with P2PK:")
        # we add a time lock to the P2PK lock by appending the current unix time + 14 days
        else:
            logger.debug(f"Locking token to: {lock}")
            logger.debug(
                f"Adding a time lock of {settings.locktime_delta_seconds} seconds."
            )
            secret_lock = await wallet.create_p2pk_lock(
                lock.split(":")[1],
                locktime_seconds=settings.locktime_delta_seconds,
                sig_all=True,
                n_sigs=1,
            )

    await wallet.load_proofs()
    if split:
        await wallet.load_mint()
        _, send_proofs = await wallet.split_to_send(
            wallet.proofs, amount, secret_lock, set_reserved=True
        )
    else:
        # get a proof with specific amount
        send_proofs = []
        for p in wallet.proofs:
            if not p.reserved and p.amount == amount:
                send_proofs = [p]
                break
        assert send_proofs, Exception(
            "No proof with this amount found. Available amounts:"
            f" {set([p.amount for p in wallet.proofs])}"
        )

    token = await wallet.serialize_proofs(
        send_proofs,
        include_mints=True,
        include_dleq=include_dleq,
    )
    print(token)
    await wallet.set_reserved(send_proofs, reserved=True)
    if legacy:
        print("")
        print("Old token format:")
        print("")
        token = await wallet.serialize_proofs(
            send_proofs,
            legacy=True,
            include_dleq=include_dleq,
        )
        print(token)

    return wallet.available_balance, token
