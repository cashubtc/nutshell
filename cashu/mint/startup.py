# startup routine of the standalone app. These are the steps that need
# to be taken by external apps importing the cashu mint.

import asyncio
import importlib

from loguru import logger

from ..core.base import Method, Unit
from ..core.db import Database
from ..core.migrations import migrate_databases
from ..core.settings import settings
from ..mint import migrations
from ..mint.crud import LedgerCrudSqlite
from ..mint.ledger import Ledger

logger.debug("Enviroment Settings:")
for key, value in settings.dict().items():
    if key in [
        "mint_private_key",
        "mint_seed_decryption_key",
        "nostr_private_key",
        "mint_lnbits_key",
        "mint_strike_key",
        "mint_lnd_rest_macaroon",
        "mint_lnd_rest_admin_macaroon",
        "mint_lnd_rest_invoice_macaroon",
        "mint_corelightning_rest_macaroon",
    ]:
        value = "********" if value is not None else None
    logger.debug(f"{key}: {value}")

wallets_module = importlib.import_module("cashu.lightning")
lightning_backend = getattr(wallets_module, settings.mint_lightning_backend)()

assert settings.mint_private_key is not None, "No mint private key set."

# strike_backend = getattr(wallets_module, "StrikeUSDWallet")()
# backends = {
#     Method.bolt11: {Unit.sat: lightning_backend, Unit.usd: strike_backend},
# }
# backends = {
#     Method.bolt11: {Unit.sat: lightning_backend, Unit.msat: lightning_backend},
# }
# backends = {
#     Method.bolt11: {Unit.sat: lightning_backend, Unit.msat: lightning_backend,
# }
backends = {
    Method.bolt11: {Unit.sat: lightning_backend},
}
ledger = Ledger(
    db=Database("mint", settings.mint_database),
    seed=settings.mint_private_key,
    seed_decryption_key=settings.mint_seed_decryption_key,
    derivation_path=settings.mint_derivation_path,
    backends=backends,
    crud=LedgerCrudSqlite(),
)


async def rotate_keys(n_seconds=60):
    """Rotate keyset epoch every n_seconds.
    Note: This is just a helper function for testing purposes.
    """
    i = 0
    while True:
        i += 1
        logger.info("Rotating keys.")
        incremented_derivation_path = (
            "/".join(ledger.derivation_path.split("/")[:-1]) + f"/{i}"
        )
        await ledger.activate_keyset(derivation_path=incremented_derivation_path)
        logger.info(f"Current keyset: {ledger.keyset.id}")
        await asyncio.sleep(n_seconds)


async def start_mint_init():
    await migrate_databases(ledger.db, migrations)
    if settings.mint_cache_secrets:
        await ledger.load_used_proofs()
    await ledger.init_keysets()

    for derivation_path in settings.mint_derivation_path_list:
        await ledger.activate_keyset(derivation_path=derivation_path)

    for method in ledger.backends:
        for unit in ledger.backends[method]:
            logger.info(
                f"Using {ledger.backends[method][unit].__class__.__name__} backend for"
                f" method: '{method.name}' and unit: '{unit.name}'"
            )
            status = await ledger.backends[method][unit].status()
            if status.error_message:
                logger.warning(
                    "The backend for"
                    f" {ledger.backends[method][unit].__class__.__name__} isn't"
                    f" working properly: '{status.error_message}'",
                    RuntimeWarning,
                )
            logger.info(f"Backend balance: {status.balance} {unit.name}")

    logger.info(f"Data dir: {settings.cashu_dir}")
    logger.info("Mint started.")
    # asyncio.create_task(rotate_keys())
