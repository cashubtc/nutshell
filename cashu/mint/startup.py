import asyncio

from loguru import logger

from cashu.core.migrations import migrate_databases
from cashu.core.settings import CASHU_DIR, LIGHTNING
from cashu.lightning import WALLET
from cashu.mint import migrations

from cashu.core.settings import MINT_PRIVATE_KEY
from cashu.mint.ledger import Ledger
from cashu.core.db import Database


async def start_mint_init():
    ledger = Ledger(
        db=Database("mint", "data/mint"),
        seed=MINT_PRIVATE_KEY,
        derivation_path="0/0/0/0",
    )
    await migrate_databases(ledger.db, migrations)
    await ledger.load_used_proofs()
    await ledger.init_keysets()

    if LIGHTNING:
        error_message, balance = await WALLET.status()
        if error_message:
            logger.warning(
                f"The backend for {WALLET.__class__.__name__} isn't working properly: '{error_message}'",
                RuntimeWarning,
            )
        logger.info(f"Lightning balance: {balance} sat")

    logger.info(f"Data dir: {CASHU_DIR}")
    logger.info("Mint started.")
