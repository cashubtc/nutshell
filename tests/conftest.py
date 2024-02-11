import asyncio
import importlib
import multiprocessing
import os
import shutil
import time
from pathlib import Path

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

settings.debug = False
settings.cashu_dir = "./test_data/"
settings.mint_host = "localhost"
settings.mint_port = SERVER_PORT
settings.mint_host = "0.0.0.0"
settings.mint_listen_port = SERVER_PORT
settings.mint_url = SERVER_ENDPOINT
settings.tor = False
settings.wallet_unit = "sat"
settings.mint_lightning_backend = settings.mint_lightning_backend or "FakeWallet"
settings.fakewallet_brr = True
settings.fakewallet_delay_payment = False
settings.fakewallet_stochastic_invoice = False
assert (
    settings.mint_test_database != settings.mint_database
), "Test database is the same as the main database"
settings.mint_database = settings.mint_test_database
settings.mint_derivation_path = "m/0'/0'/0'"
settings.mint_derivation_path_list = []
settings.mint_private_key = "TEST_PRIVATE_KEY"
settings.mint_seed_decryption_key = ""
settings.mint_max_balance = 0

assert "test" in settings.cashu_dir
shutil.rmtree(settings.cashu_dir, ignore_errors=True)
Path(settings.cashu_dir).mkdir(parents=True, exist_ok=True)

# from cashu.mint.startup import lightning_backend  # noqa


@pytest.fixture(scope="session")
def event_loop():
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


class UvicornServer(multiprocessing.Process):
    def __init__(self, config: Config):
        super().__init__()
        self.server = Server(config=config)
        self.config = config

    def stop(self):
        self.terminate()

    def run(self, *args, **kwargs):
        self.server.run()


# # This fixture is used for tests that require API access to the mint
@pytest.fixture(autouse=True, scope="session")
def mint():
    config = uvicorn.Config(
        "cashu.mint.app:app",
        port=settings.mint_listen_port,
        host=settings.mint_listen_host,
    )

    server = UvicornServer(config=config)
    server.start()
    time.sleep(1)
    yield server
    server.stop()


# This fixture is used for all other tests
@pytest_asyncio.fixture(scope="function")
async def ledger():
    async def start_mint_init(ledger: Ledger):
        await migrate_databases(ledger.db, migrations_mint)
        if settings.mint_cache_secrets:
            await ledger.load_used_proofs()
        await ledger.init_keysets()

    if not settings.mint_database.startswith("postgres"):
        # clear sqlite database
        db_file = os.path.join(settings.mint_database, "mint.sqlite3")
        if os.path.exists(db_file):
            os.remove(db_file)
    else:
        # clear postgres database
        db = Database("mint", settings.mint_database)
        async with db.connect() as conn:
            await conn.execute("DROP SCHEMA public CASCADE;")
            await conn.execute("CREATE SCHEMA public;")

    wallets_module = importlib.import_module("cashu.lightning")
    lightning_backend = getattr(wallets_module, settings.mint_lightning_backend)()
    backends = {
        Method.bolt11: {Unit.sat: lightning_backend},
    }
    ledger = Ledger(
        db=Database("mint", settings.mint_database),
        seed=settings.mint_private_key,
        derivation_path=settings.mint_derivation_path,
        backends=backends,
        crud=LedgerCrudSqlite(),
    )
    await start_mint_init(ledger)
    yield ledger
    print("teardown")
