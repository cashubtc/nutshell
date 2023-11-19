import multiprocessing
import os
import shutil
import time
from pathlib import Path

import pytest
import pytest_asyncio
import uvicorn
from uvicorn import Config, Server

from cashu.core.db import Database
from cashu.core.migrations import migrate_databases
from cashu.core.settings import settings
from cashu.lightning.fake import FakeWallet
from cashu.mint import migrations as migrations_mint
from cashu.mint.crud import LedgerCrudSqlite
from cashu.mint.ledger import Ledger

SERVER_PORT = 3337
SERVER_ENDPOINT = f"http://localhost:{SERVER_PORT}"

settings.cashu_dir = "./test_data/"
settings.mint_host = "localhost"
settings.mint_port = SERVER_PORT
settings.mint_host = "0.0.0.0"
settings.mint_listen_port = SERVER_PORT
settings.mint_url = SERVER_ENDPOINT
settings.tor = False
settings.mint_lightning_backend = settings.mint_lightning_backend or "FakeWallet"
settings.mint_database = "./test_data/test_mint"
settings.mint_derivation_path = "m/0'/0'/0'"
settings.mint_derivation_path_list = []
settings.mint_private_key = "TEST_PRIVATE_KEY"

shutil.rmtree(settings.cashu_dir, ignore_errors=True)
Path(settings.cashu_dir).mkdir(parents=True, exist_ok=True)


class UvicornServer(multiprocessing.Process):
    def __init__(self, config: Config):
        super().__init__()
        self.server = Server(config=config)
        self.config = config

    def stop(self):
        self.terminate()

    def run(self, *args, **kwargs):
        self.server.run()


@pytest_asyncio.fixture(scope="function")
async def ledger():
    async def start_mint_init(ledger: Ledger):
        await migrate_databases(ledger.db, migrations_mint)
        await ledger.load_used_proofs()
        await ledger.init_keysets()

    database_name = "test"

    if not settings.mint_database.startswith("postgres"):
        # clear sqlite database
        db_file = os.path.join(settings.mint_database, database_name + ".sqlite3")
        if os.path.exists(db_file):
            os.remove(db_file)

    ledger = Ledger(
        db=Database(database_name, settings.mint_database),
        seed=settings.mint_private_key,
        derivation_path=settings.mint_derivation_path,
        lightning=FakeWallet(),
        crud=LedgerCrudSqlite(),
    )
    await start_mint_init(ledger)
    yield ledger


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
