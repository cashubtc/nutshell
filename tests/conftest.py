import importlib
import multiprocessing
import os
import shutil
import time
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
import uvicorn
from uvicorn import Config, Server

from cashu.core.base import Method, Unit
from cashu.core.db import Database
from cashu.core.migrations import migrate_databases
from cashu.core.settings import settings
from cashu.mint import migrations as migrations_mint
from cashu.mint.crud import LedgerCrudSqlite
from cashu.mint.ledger import Ledger

SERVER_PORT = 3337
SERVER_ENDPOINT = f"http://localhost:{SERVER_PORT}"

settings.debug = True
settings.log_level = "TRACE"
settings.cashu_dir = "./test_data/"
settings.mint_host = "localhost"
settings.mint_port = SERVER_PORT
settings.mint_listen_port = SERVER_PORT
settings.mint_url = SERVER_ENDPOINT
settings.tor = False
settings.wallet_unit = "sat"
settings.mint_backend_bolt11_sat = settings.mint_backend_bolt11_sat or "FakeWallet"
settings.mint_backend_bolt11_usd = settings.mint_backend_bolt11_usd or "FakeWallet"
settings.fakewallet_brr = True
settings.fakewallet_delay_outgoing_payment = 0
settings.fakewallet_delay_incoming_payment = 1
settings.fakewallet_stochastic_invoice = False
assert (
    settings.mint_test_database != settings.mint_database
), "Test database is the same as the main database"
settings.mint_database = settings.mint_test_database
settings.mint_derivation_path = "m/0'/0'/0'"
settings.mint_derivation_path_list = ["m/0'/2'/0'"]  # USD
settings.mint_private_key = "TEST_PRIVATE_KEY"
settings.mint_seed_decryption_key = ""
settings.mint_max_balance = 0
settings.mint_transaction_rate_limit_per_minute = 60
settings.mint_lnd_enable_mpp = True
settings.mint_clnrest_enable_mpp = True
settings.mint_input_fee_ppk = 0
settings.db_connection_pool = True
# settings.mint_require_auth = False
settings.mint_watchdog_enabled = True
settings.mint_watchdog_ignore_mismatch = True  # turn off the watchdog for testing
settings.mint_watchdog_balance_check_interval_seconds = 2

assert "test" in settings.cashu_dir
shutil.rmtree(settings.cashu_dir, ignore_errors=True)
Path(settings.cashu_dir).mkdir(parents=True, exist_ok=True)

# from cashu.mint.startup import lightning_backend  # noqa


class UvicornServer(multiprocessing.Process):
    def __init__(self, config: Config):
        super().__init__()
        self.server = Server(config=config)
        self.config = config

    def stop(self):
        self.terminate()

    def run(self, *args, **kwargs):
        self.server.run()


# This fixture is used for all other tests
@pytest_asyncio.fixture(scope="function")
async def ledger():
    async def start_mint_init(ledger: Ledger) -> Ledger:
        await migrate_databases(ledger.db, migrations_mint)
        await ledger.startup_ledger()
        return ledger

    if not settings.mint_database.startswith("postgres"):
        # clear sqlite database
        db_file = os.path.join(settings.mint_database, "mint.sqlite3")
        if os.path.exists(db_file):
            os.remove(db_file)
    else:
        # clear postgres database
        db = Database("mint", settings.mint_database)
        async with db.connect() as conn:
            # drop all tables
            await conn.execute("DROP SCHEMA public CASCADE;")
            await conn.execute("CREATE SCHEMA public;")
        await db.engine.dispose()

    wallets_module = importlib.import_module("cashu.lightning")
    lightning_backend_sat = getattr(wallets_module, settings.mint_backend_bolt11_sat)(
        unit=Unit.sat
    )
    lightning_backend_usd = getattr(wallets_module, settings.mint_backend_bolt11_usd)(
        unit=Unit.usd
    )
    backends = {
        Method.bolt11: {
            Unit.sat: lightning_backend_sat,
            Unit.usd: lightning_backend_usd,
        },
    }
    ledger = Ledger(
        db=Database("mint", settings.mint_database),
        seed=settings.mint_private_key,
        derivation_path=settings.mint_derivation_path,
        backends=backends,
        crud=LedgerCrudSqlite(),
    )
    ledger = await start_mint_init(ledger)
    yield ledger
    print("teardown")
    await ledger.shutdown_ledger()


# # This fixture is used for tests that require API access to the mint
@pytest.fixture(autouse=True, scope="session")
def mint():
    config = uvicorn.Config(
        "cashu.mint.app:app",
        port=settings.mint_listen_port,
        host=settings.mint_listen_host,
        log_level="trace",
    )

    server = UvicornServer(config=config)
    server.start()

    # Wait until the server has bound to the localhost socket. Max out after 10s.
    tries = 0
    while tries < 100:
        try:
            httpx.get(settings.mint_url)
            break
        except httpx.ConnectError:
            tries += 1
            time.sleep(0.1)

    yield server
    server.stop()
