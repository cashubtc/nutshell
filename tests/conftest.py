import multiprocessing
import os
import shutil
import time
from pathlib import Path

import pytest
import pytest_asyncio
import uvicorn
from fastapi import FastAPI
from uvicorn import Config, Server

from cashu.core.db import Database
from cashu.core.migrations import migrate_databases
from cashu.core.settings import settings
from cashu.lightning.fake import FakeWallet
from cashu.mint import migrations as migrations_mint
from cashu.mint.ledger import Ledger
from cashu.wallet import migrations as migrations_wallet
from cashu.wallet.api.router import router
from cashu.wallet.wallet import Wallet

SERVER_ENDPOINT = "http://localhost:3337"


class UvicornServer(multiprocessing.Process):
    def __init__(self, config: Config, private_key: str = "TEST_PRIVATE_KEY"):
        super().__init__()
        self.server = Server(config=config)
        self.config = config
        self.private_key = private_key

    def stop(self):
        self.terminate()

    def run(self, *args, **kwargs):
        settings.lightning = False
        settings.mint_lightning_backend = "FakeWallet"
        settings.mint_listen_port = 3337
        settings.mint_database = "data/test_mint"
        settings.mint_private_key = self.private_key
        settings.mint_derivation_path = "0/0/0/0"

        dirpath = Path(settings.mint_database)
        if dirpath.exists() and dirpath.is_dir():
            shutil.rmtree(dirpath)

        dirpath = Path("data/test_wallet")
        if dirpath.exists() and dirpath.is_dir():
            shutil.rmtree(dirpath)

        self.server.run()


@pytest.fixture(autouse=True, scope="session")
def mint():
    settings.mint_listen_port = 3337
    settings.port = 3337
    settings.mint_url = "http://localhost:3337"
    settings.port = settings.mint_listen_port
    config = uvicorn.Config(
        "cashu.mint.app:app",
        port=settings.mint_listen_port,
        host="127.0.0.1",
    )

    server = UvicornServer(config=config)
    server.start()
    time.sleep(1)
    yield server
    server.stop()


@pytest_asyncio.fixture(scope="function")
async def ledger():
    async def start_mint_init(ledger):
        await migrate_databases(ledger.db, migrations_mint)
        await ledger.load_used_proofs()
        await ledger.init_keysets()

    db_file = "data/mint/test.sqlite3"
    if os.path.exists(db_file):
        os.remove(db_file)
    ledger = Ledger(
        db=Database("test", "data/mint"),
        seed="TEST_PRIVATE_KEY",
        derivation_path="0/0/0/0",
        lightning=FakeWallet(),
    )
    await start_mint_init(ledger)
    yield ledger


@pytest.fixture(autouse=True, scope="session")
def mint_3338():
    settings.mint_listen_port = 3338
    settings.port = 3338
    settings.mint_url = "http://localhost:3338"
    settings.port = settings.mint_listen_port
    config = uvicorn.Config(
        "cashu.mint.app:app",
        port=settings.mint_listen_port,
        host="127.0.0.1",
    )

    server = UvicornServer(config=config, private_key="SECOND_PRIVATE_KEY")
    server.start()
    time.sleep(1)
    yield server
    server.stop()
