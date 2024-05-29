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


async def redeem_TokenV3_multimint(wallet: Wallet, token: TokenV3) -> Wallet:
    """
    Helper function to iterate thruogh a token with multiple mints and redeem them from
    these mints one keyset at a time.
    """
    if not token.unit:
        # load unit from wallet keyset db
        keysets = await get_keysets(id=token.token[0].proofs[0].id, db=wallet.db)
        if keysets:
            token.unit = keysets[0].unit.name

    for t in token.token:
        assert t.mint, Exception(
            "redeem_TokenV3_multimint: multimint redeem without URL"
        )
        mint_wallet = await Wallet.with_db(
            t.mint,
            os.path.join(settings.cashu_dir, wallet.name),
            unit=token.unit or wallet.unit.name,
        )
        keyset_ids = mint_wallet._get_proofs_keysets(t.proofs)
        logger.trace(f"Keysets in tokens: {' '.join(set(keyset_ids))}")
        await mint_wallet.load_mint()
        proofs_to_keep, _ = await mint_wallet.redeem(t.proofs)
        print(f"Received {mint_wallet.unit.str(sum_proofs(proofs_to_keep))}")

    # return the last mint_wallet
    return mint_wallet


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
) -> Wallet:
    logger.debug(f"receive: {tokenObj}")
    proofs = [p for t in tokenObj.token for p in t.proofs]

    includes_mint_info: bool = any([t.mint for t in tokenObj.token])

    if includes_mint_info:
        # redeem tokens with new wallet instances
        mint_wallet = await redeem_TokenV3_multimint(
            wallet,
            tokenObj,
        )
    else:
        # this is very legacy code, virtually any token should have mint information
        # no mint information present, we extract the proofs find the mint and unit from the db
        keyset_in_token = proofs[0].id
        assert keyset_in_token
        # we get the keyset from the db
        mint_keysets = await get_keysets(id=keyset_in_token, db=wallet.db)
        assert mint_keysets, Exception(f"we don't know this keyset: {keyset_in_token}")
        mint_keyset = [k for k in mint_keysets if k.id == keyset_in_token][0]
        assert mint_keyset.mint_url, Exception("we don't know this mint's URL")
        # now we have the URL
        mint_wallet = await Wallet.with_db(
            mint_keyset.mint_url,
            os.path.join(settings.cashu_dir, wallet.name),
            unit=mint_keyset.unit.name or wallet.unit.name,
        )
        await mint_wallet.load_mint(keyset_in_token)
        _, _ = await mint_wallet.redeem(proofs)
        print(f"Received {mint_wallet.unit.str(sum_proofs(proofs))}")

    # reload main wallet so the balance updates
    await wallet.load_proofs(reload=True)
    return mint_wallet


async def send(
    wallet: Wallet,
    *,
    amount: int,
    lock: str,
    legacy: bool,
    offline: bool = False,
    include_dleq: bool = False,
    include_fees: bool = False,
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
            print(f"Secret lock: {secret_lock}")

    await wallet.load_proofs()

    await wallet.load_mint()
    # get a proof with specific amount
    send_proofs, fees = await wallet.select_to_send(
        wallet.proofs,
        amount,
        set_reserved=False,
        offline=offline,
        include_fees=include_fees,
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
