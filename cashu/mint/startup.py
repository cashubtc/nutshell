# startup routine of the standalone app. These are the steps that need
# to be taken by external apps importing the cashu mint.

import asyncio
import importlib
from typing import Dict

from loguru import logger

from ..core.base import Method, Unit
from ..core.db import Database
from ..core.migrations import migrate_databases
from ..core.settings import settings
from ..lightning.base import LightningBackend
from ..mint import migrations
from ..mint.crud import LedgerCrudSqlite
from ..mint.ledger import Ledger

# kill the program if python runs in non-__debug__ mode
# which could lead to asserts not being executed for optimized code
if not __debug__:
    raise Exception("Nutshell cannot run in non-debug mode.")

logger.debug("Enviroment Settings:")
for key, value in settings.dict().items():
    if key in [
        "mint_private_key",
        "mint_seed_decryption_key",
        "nostr_private_key",
        "mint_lnbits_key",
        "mint_blink_key",
        "mint_strike_key",
        "mint_lnd_rest_macaroon",
        "mint_lnd_rest_admin_macaroon",
        "mint_lnd_rest_invoice_macaroon",
        "mint_corelightning_rest_macaroon",
        "mint_clnrest_rune",
    ]:
        value = "********" if value is not None else None

    if key == "mint_database" and value and value.startswith("postgres://"):
        value = "postgres://********"

    logger.debug(f"{key}: {value}")

wallets_module = importlib.import_module("cashu.lightning")

backends: Dict[Method, Dict[Unit, LightningBackend]] = {}
if settings.mint_backend_bolt11_sat:
    backend_bolt11_sat = getattr(wallets_module, settings.mint_backend_bolt11_sat)(
        unit=Unit.sat
    )
    backends.setdefault(Method.bolt11, {})[Unit.sat] = backend_bolt11_sat
if settings.mint_backend_bolt11_usd:
    backend_bolt11_usd = getattr(wallets_module, settings.mint_backend_bolt11_usd)(
        unit=Unit.usd
    )
    backends.setdefault(Method.bolt11, {})[Unit.usd] = backend_bolt11_usd
if settings.mint_backend_bolt11_eur:
    backend_bolt11_eur = getattr(wallets_module, settings.mint_backend_bolt11_eur)(
        unit=Unit.eur
    )
    backends.setdefault(Method.bolt11, {})[Unit.eur] = backend_bolt11_eur
if not backends:
    raise Exception("No backends are set.")

if not settings.mint_private_key:
    raise Exception("No mint private key is set.")

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
            f"{'/'.join(ledger.derivation_path.split('/')[:-1])}/{i}"
        )
        await ledger.activate_keyset(derivation_path=incremented_derivation_path)
        logger.info(f"Current keyset: {ledger.keyset.id}")
        await asyncio.sleep(n_seconds)


async def start_mint_init():
    await migrate_databases(ledger.db, migrations)
    await ledger.startup_ledger()
    logger.info("Mint started.")
    # asyncio.create_task(rotate_keys())


async def shutdown_mint():
    await ledger.shutdown_ledger()
    logger.info("Mint shutdown.")
    logger.remove()
