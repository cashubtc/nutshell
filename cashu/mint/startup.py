# startup routine of the standalone app. These are the steps that need
# to be taken by external apps importing the cashu mint.

import asyncio

from loguru import logger

from cashu.core.db import Database
from cashu.core.migrations import migrate_databases
from cashu.core.settings import CASHU_DIR, LIGHTNING, MINT_PRIVATE_KEY
from cashu.lightning.lnbits import LNbitsWallet
from cashu.mint import migrations
from cashu.mint.ledger import Ledger

ledger = Ledger(
    db=Database("mint", "data/mint"),
    seed=MINT_PRIVATE_KEY,
    # seed="asd",
    derivation_path="0/0/0/0",
    lightning=LNbitsWallet() if LIGHTNING else None,
)


async def start_mint_init():

    await migrate_databases(ledger.db, migrations)
    await ledger.load_used_proofs()
    await ledger.init_keysets()

    if LIGHTNING:
        error_message, balance = await ledger.lightning.status()
        if error_message:
            logger.warning(
                f"The backend for {ledger.lightning.__class__.__name__} isn't working properly: '{error_message}'",
                RuntimeWarning,
            )
        logger.info(f"Lightning balance: {balance} sat")

    logger.info(f"Data dir: {CASHU_DIR}")
    logger.info("Mint started.")
