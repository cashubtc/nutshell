import multiprocessing
import time

import pytest
import pytest_asyncio
import uvicorn
from uvicorn import Config, Server

from cashu.core.migrations import migrate_databases
from cashu.wallet import migrations
from cashu.wallet.wallet import Wallet

SERVER_ENDPOINT = "http://localhost:3337"


class UvicornServer(multiprocessing.Process):
    def __init__(self, config: Config):
        super().__init__()
        self.server = Server(config=config)
        self.config = config

    def stop(self):
        self.terminate()

    def run(self, *args, **kwargs):
        self.server.run()


@pytest.fixture(autouse=True, scope="session")
def mint():

    config = uvicorn.Config(
        "cashu.mint.app:app",
        port=3337,
        host="127.0.0.1",
    )

    server = UvicornServer(config=config)
    server.start()
    time.sleep(1)
    yield server
    server.stop()
