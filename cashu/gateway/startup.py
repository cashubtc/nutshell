# startup routine of the standalone app. These are the steps that need
# to be taken by external apps importing the cashu gateway.

import importlib
from typing import Dict

from loguru import logger

from ..core.base import Method, Unit
from ..core.db import Database
from ..core.migrations import migrate_databases
from ..core.settings import settings
from ..lightning.base import LightningBackend
from . import migrations
from .crud import GatewayCrudSqlite
from .gateway import Gateway

# kill the program if python runs in non-__debug__ mode
# which could lead to asserts not being executed for optimized code
if not __debug__:
    raise Exception("Nutshell cannot run in non-debug mode.")

# logger.debug("Enviroment Settings:")
# for key, value in settings.dict().items():
#     if key in [
#         "gateway_private_key",
#         "gateway_seed_decryption_key",
#         "nostr_private_key",
#         "gateway_lnbits_key",
#         "gateway_blink_key",
#         "gateway_strike_key",
#         "gateway_lnd_rest_macaroon",
#         "gateway_lnd_rest_admin_macaroon",
#         "gateway_lnd_rest_invoice_macaroon",
#         "gateway_corelightning_rest_macaroon",
#     ]:
#         value = "********" if value is not None else None
#     logger.debug(f"{key}: {value}")

wallets_module = importlib.import_module("cashu.lightning")

backends: Dict[Method, Dict[Unit, LightningBackend]] = {}
if settings.gateway_backend_bolt11_sat:
    backend_bolt11_sat = getattr(wallets_module, settings.gateway_backend_bolt11_sat)(
        unit=Unit.sat
    )
    backends.setdefault(Method.bolt11, {})[Unit.sat] = backend_bolt11_sat
if not backends:
    raise Exception("No backends are set.")

if not settings.gateway_private_key:
    raise Exception("No gateway private key is set.")

gateway = Gateway(
    db=Database("gateway", settings.gateway_database),
    seed=settings.gateway_private_key,
    backends=backends,
    crud=GatewayCrudSqlite(),
)


async def start_gateway_init():
    await migrate_databases(gateway.db, migrations)
    await gateway.init_wallets()
    await gateway.startup_gateway()
    logger.info("Gateway started.")
