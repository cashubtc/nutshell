import os

from loguru import logger

from ..core.base import TokenV3, TokenV4
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


def deserialize_token_from_string(token: str) -> TokenV3:
    # deserialize token

    if token.startswith("cashuA"):
        tokenObj = TokenV3.deserialize(token)
        assert len(tokenObj.token), Exception("no proofs in token")
        assert len(tokenObj.token[0].proofs), Exception("no proofs in token")
        return tokenObj
    if token.startswith("cashuB"):
        tokenObj = TokenV4.deserialize(token).to_tokenv3()
        assert len(tokenObj.token), Exception("no proofs in token")
        assert len(tokenObj.token[0].proofs), Exception("no proofs in token")
        return tokenObj

    raise Exception("Invalid token")


async def receive(
    wallet: Wallet,
    tokenObj: TokenV3,
) -> Wallet:
    # redeem tokens with new wallet instances
    mint_wallet = await redeem_TokenV3_multimint(
        wallet,
        tokenObj,
    )

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
        legacy=legacy,
    )
    print(token)
    await wallet.set_reserved(send_proofs, reserved=True)

    return wallet.available_balance, token
