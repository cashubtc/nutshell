# startup routine of the standalone app. These are the steps that need
# to be taken by external apps importing the cashu mint.

import asyncio
import hashlib
import importlib
import json
from copy import copy
from typing import Dict

from loguru import logger

import cashu.mint.management_rpc.management_rpc as management_rpc

from ..core.base import Method, Unit
from ..core.db import Database
from ..core.migrations import migrate_databases
from ..core.settings import settings
from ..lightning.base import LightningBackend
from ..mint import migrations as mint_migrations
from ..mint.auth import migrations as auth_migrations
from ..mint.auth.server import AuthLedger
from ..mint.crud import LedgerCrudSqlite
from ..mint.ledger import Ledger

# kill the program if python runs in non-__debug__ mode
# which could lead to asserts not being executed for optimized code
if not __debug__:
    raise Exception("Nutshell cannot run in non-debug mode.")

logger.debug("Enviroment Settings:")
for key, value in settings.model_dump().items():
    if key in [
        "mint_private_key",
        "mint_seed_decryption_key",
        "mint_lnbits_key",
        "mint_blink_key",
        "mint_strike_key",
        "mint_spark_api_key",
        "mint_spark_mnemonic",
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
if settings.mint_backend_bolt11_msat:
    backend_bolt11_msat = getattr(wallets_module, settings.mint_backend_bolt11_msat)(
        unit=Unit.msat
    )
    backends.setdefault(Method.bolt11, {})[Unit.msat] = backend_bolt11_msat
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

# start auth ledger
auth_ledger = AuthLedger(
    db=Database("auth", settings.mint_auth_database),
    seed="auth seed here",
    amounts=[1],
    derivation_path="m/0'/999'/0'",
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


async def start_auth():
    await migrate_databases(auth_ledger.db, auth_migrations)
    logger.info("Starting auth ledger.")
    await auth_ledger.init_keysets()
    await auth_ledger.init_auth()
    logger.info("Auth ledger started.")


async def apply_panic_mode_environment() -> None:
    if settings.mint_panic_mode is not None:
        panic_state = await ledger.panic.get_state()
        if panic_state.enabled != settings.mint_panic_mode:
            panic_state = await ledger.panic.set_state(
                enabled=settings.mint_panic_mode,
                reason=settings.mint_panic_mode_reason,
                updated_by=settings.mint_panic_mode_operator,
            )
            logger.warning(
                "Applied MINT_PANIC_MODE={} at startup (revision={}).",
                panic_state.enabled,
                panic_state.revision,
            )

    blinded_messages = settings.mint_panic_blacklist_blinded_messages
    if blinded_messages:
        canonical = json.dumps(
            sorted(set(blinded_messages)), separators=(",", ":")
        )
        selector_id = "env-b-" + hashlib.sha256(canonical.encode()).hexdigest()
        count = await ledger.panic.blacklist_blinded_messages(
            blinded_messages,
            reason=settings.mint_panic_mode_reason,
            created_by=settings.mint_panic_mode_operator,
            selector_id=selector_id,
        )
        if count:
            logger.warning(
                "Applied {} exact panic blacklist entries from the environment.",
                count,
            )

    for selector in settings.mint_panic_blacklist_time_ranges:
        try:
            issued_from = int(selector["issued_from"])
            issued_until = int(selector["issued_until"])
            reason = str(
                selector.get("reason", settings.mint_panic_mode_reason)
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(
                "invalid MINT_PANIC_BLACKLIST_SELECTORS entry"
            ) from exc
        canonical = json.dumps(
            {
                "issued_from": issued_from,
                "issued_until": issued_until,
                "reason": reason,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        selector_id = "env-time-" + hashlib.sha256(canonical.encode()).hexdigest()
        if await ledger.panic.selector_exists(selector_id):
            continue
        preview = await ledger.panic.preview_selector(
            issued_from=issued_from,
            issued_until=issued_until,
            reason=reason,
            created_by=settings.mint_panic_mode_operator,
            selector_id=selector_id,
        )
        count = await ledger.panic.commit_selector(
            preview,
            reason=reason,
            created_by=settings.mint_panic_mode_operator,
        )
        logger.warning(
            "Applied panic time-range selector {} from the environment: {} promises.",
            selector_id,
            count,
        )


async def start_mint():
    await migrate_databases(ledger.db, mint_migrations)
    await apply_panic_mode_environment()
    logger.info("Starting mint ledger.")
    await ledger.startup_ledger()
    logger.info("Mint started.")
    # asyncio.create_task(rotate_keys())


async def shutdown_mint():
    await ledger.shutdown_ledger()
    logger.info("Mint shutdown.")
    logger.remove()


rpc_server = None


async def start_management_rpc():
    global rpc_server
    rpc_server = await management_rpc.serve(copy(ledger))


async def shutdown_management_rpc():
    if rpc_server:
        await management_rpc.shutdown(rpc_server)
