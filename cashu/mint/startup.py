# startup routine of the standalone app. These are the steps that need
# to be taken by external apps importing the cashu mint.

import asyncio
import importlib

from loguru import logger

from ..core.db import Database
from ..core.migrations import migrate_databases
from ..core.settings import settings
from ..mint import migrations
from ..mint.crud import LedgerCrud
from ..mint.ledger import Ledger

logger.debug("Enviroment Settings:")
for key, value in settings.dict().items():
    logger.debug(f"{key}: {value}")

wallets_module = importlib.import_module("cashu.lightning")
lightning_backend = getattr(wallets_module, settings.mint_lightning_backend)()

assert settings.mint_private_key is not None, "No mint private key set."

ledger = Ledger(
    db=Database("mint", settings.mint_database),
    seed=settings.mint_private_key,
    derivation_path=settings.mint_derivation_path,
    lightning=lightning_backend,
    crud=LedgerCrud(),
)


async def rotate_keys(n_seconds=10):
    """Rotate keyset epoch every n_seconds.
    Note: This is just a helper function for testing purposes.
    """
    i = 0
    while True:
        i += 1
        logger.info("Rotating keys.")
        ledger.derivation_path = f"0/0/0/{i}"
        await ledger.init_keysets()
        logger.info(f"Current keyset: {ledger.keyset.id}")
        await asyncio.sleep(n_seconds)


async def start_mint_init():
    await migrate_databases(ledger.db, migrations)
    await ledger.init_keysets()

    if settings.lightning:
        logger.info(f"Using backend: {settings.mint_lightning_backend}")
        status = await ledger.lightning.status()
        if status.error_message:
            logger.warning(
                f"The backend for {ledger.lightning.__class__.__name__} isn't"
                f" working properly: '{status.error_message}'",
                RuntimeWarning,
            )
        logger.info(f"Lightning balance: {status.balance_msat} msat")

    logger.info(f"Data dir: {settings.cashu_dir}")
    logger.info("Mint started.")
    # asyncio.create_task(rotate_keys())
