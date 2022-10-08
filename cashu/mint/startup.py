import asyncio

from loguru import logger

from cashu.core.migrations import migrate_databases
from cashu.core.settings import CASHU_DIR, LIGHTNING
from cashu.lightning import WALLET
from cashu.mint import migrations

from . import ledger


async def load_ledger():
    await migrate_databases(ledger.db, migrations)
    # await asyncio.wait([m001_initial(ledger.db)])
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
