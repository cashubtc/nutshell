import asyncio

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from cashu.core.migrations import migrate_databases
from cashu.core.settings import settings
from cashu.wallet import migrations
from cashu.wallet.api.app import app
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT, mint


@pytest_asyncio.fixture(scope="function")
async def wallet(mint):
    wallet = Wallet(SERVER_ENDPOINT, "data/test_wallet_api", "wallet_api")
    await migrate_databases(wallet.db, migrations)
    await wallet.load_mint()
    wallet.status()
    yield wallet


@pytest.mark.asyncio
async def test_invoice(wallet: Wallet):
    with TestClient(app) as client:
        response = client.post("/invoice?amount=100")
        assert response.status_code == 200
        if settings.lightning:
            assert response.json()["invoice"]
        else:
            assert response.json()["amount"]


@pytest.mark.asyncio
async def test_invoice_with_split(wallet: Wallet):
    with TestClient(app) as client:
        response = client.post("/invoice?amount=10&split=1")
        assert response.status_code == 200
        if settings.lightning:
            assert response.json()["invoice"]
        else:
            assert response.json()["amount"]
        # await wallet.load_proofs(reload=True)
        # assert wallet.proof_amounts.count(1) >= 10


@pytest.mark.asyncio
async def test_balance():
    with TestClient(app) as client:
        response = client.get("/balance")
        assert response.status_code == 200
        assert response.json()["balance"]
        assert response.json()["keysets"]
        assert response.json()["mints"]


@pytest.mark.asyncio
async def test_send(wallet: Wallet):
    with TestClient(app) as client:
        response = client.post("/send?amount=10")
        assert response.status_code == 200
        assert response.json()["balance"]


@pytest.mark.asyncio
async def test_send_without_split(wallet: Wallet):
    with TestClient(app) as client:
        response = client.post("/send?amount=2&nosplit=true")
        assert response.status_code == 200
        assert response.json()["balance"]


@pytest.mark.asyncio
async def test_send_without_split_but_wrong_amount(wallet: Wallet):
    with TestClient(app) as client:
        response = client.post("/send?amount=10&nosplit=true")
        assert response.status_code == 400


@pytest.mark.asyncio
async def test_pending():
    with TestClient(app) as client:
        response = client.get("/pending")
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_receive_all(wallet: Wallet):
    with TestClient(app) as client:
        response = client.post("/receive?all=true")
        assert response.status_code == 200
        assert response.json()["initial_balance"]
        assert response.json()["balance"]


@pytest.mark.asyncio
async def test_burn_all(wallet: Wallet):
    with TestClient(app) as client:
        response = client.post("/send?amount=20")
        assert response.status_code == 200
        response = client.post("/burn?all=true")
        assert response.status_code == 200
        assert response.json()["balance"]


@pytest.mark.asyncio
async def test_pay():
    with TestClient(app) as client:
        invoice = (
            "lnbc100n1pjzp22cpp58xvjxvagzywky9xz3vurue822aaax"
            "735hzc5pj5fg307y58v5znqdq4vdshx6r4ypjx2ur0wd5hgl"
            "h6ahauv24wdmac4zk478pmwfzd7sdvm8tje3dmfue3lc2g4l"
            "9g40a073h39748uez9p8mxws5vqwjmkqr4wl5l7n4dlhj6z6"
            "va963cqvufrs4"
        )
        response = client.post(f"/pay?invoice={invoice}")
        if not settings.lightning:
            assert response.status_code == 400
        else:
            assert response.status_code == 200


@pytest.mark.asyncio
async def test_lock():
    with TestClient(app) as client:
        response = client.get("/lock")
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_locks():
    with TestClient(app) as client:
        response = client.get("/locks")
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_invoices():
    with TestClient(app) as client:
        response = client.get("/invoices")
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_wallets():
    with TestClient(app) as client:
        response = client.get("/wallets")
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_info():
    with TestClient(app) as client:
        response = client.get("/info")
        assert response.status_code == 200
        assert response.json()["version"]


@pytest.mark.asyncio
async def test_flow(wallet: Wallet):
    with TestClient(app) as client:
        if not settings.lightning:
            response = client.get("/balance")
            initial_balance = response.json()["balance"]
            response = client.post("/invoice?amount=100")
            response = client.get("/balance")
            assert response.json()["balance"] == initial_balance + 100
            response = client.post("/send?amount=50")
            response = client.get("/balance")
            assert response.json()["balance"] == initial_balance + 50
            response = client.post("/send?amount=50")
            response = client.get("/balance")
            assert response.json()["balance"] == initial_balance
            response = client.get("/pending")
            token = response.json()["pending_token"]["0"]["token"]
            amount = response.json()["pending_token"]["0"]["amount"]
            response = client.post(f"/receive?token={token}")
            response = client.get("/balance")
            assert response.json()["balance"] == initial_balance + amount
