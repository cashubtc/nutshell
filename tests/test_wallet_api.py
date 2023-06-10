import asyncio

from fastapi.testclient import TestClient

from cashu.core.migrations import migrate_databases
from cashu.core.settings import settings
from cashu.wallet import migrations
from cashu.wallet.api.app import app
from cashu.wallet.wallet import Wallet


async def init_wallet():
    wallet = Wallet(settings.mint_host, "data/wallet", "wallet")
    await migrate_databases(wallet.db, migrations)
    await wallet.load_proofs()
    return wallet


def test_invoice(mint):
    with TestClient(app) as client:
        response = client.post("/invoice?amount=100")
        assert response.status_code == 200
        if settings.lightning:
            assert response.json()["invoice"]
        else:
            assert response.json()["balance"]
            assert response.json()["amount"]


def test_invoice_with_split(mint):
    with TestClient(app) as client:
        response = client.post("/invoice?amount=10&split=1")
        assert response.status_code == 200
        if settings.lightning:
            assert response.json()["invoice"]
        else:
            assert response.json()["balance"]
            assert response.json()["amount"]
        # wallet = asyncio.run(init_wallet())
        # asyncio.run(wallet.load_proofs())
        # assert wallet.proof_amounts.count(1) >= 10


def test_balance():
    with TestClient(app) as client:
        response = client.get("/balance")
        assert response.status_code == 200
        assert response.json()["balance"]
        assert response.json()["keysets"]
        assert response.json()["mints"]


def test_send(mint):
    with TestClient(app) as client:
        response = client.post("/send?amount=10")
        assert response.status_code == 200
        assert response.json()["balance"]


def test_pending():
    with TestClient(app) as client:
        response = client.get("/pending")
        assert response.status_code == 200


def test_receive_all(mint):
    with TestClient(app) as client:
        response = client.post("/receive?all=true")
        assert response.status_code == 200
        assert response.json()["initial_balance"]
        assert response.json()["balance"]


def test_burn_all(mint):
    with TestClient(app) as client:
        response = client.post("/send?amount=20")
        assert response.status_code == 200
        response = client.post("/burn?all=true")
        assert response.status_code == 200
        assert response.json()["balance"]


def test_pay():
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


def test_lock():
    with TestClient(app) as client:
        response = client.get("/lock")
        assert response.status_code == 200


def test_locks():
    with TestClient(app) as client:
        response = client.get("/locks")
        assert response.status_code == 200


def test_invoices():
    with TestClient(app) as client:
        response = client.get("/invoices")
        assert response.status_code == 200


def test_wallets():
    with TestClient(app) as client:
        response = client.get("/wallets")
        assert response.status_code == 200


def test_info():
    with TestClient(app) as client:
        response = client.get("/info")
        assert response.status_code == 200
        assert response.json()["version"]


def test_flow(mint):
    with TestClient(app) as client:
        if not settings.lightning:
            response = client.get("/balance")
            initial_balance = response.json()["balance"]
            response = client.post("/invoice?amount=100")
            assert response.json()["balance"] == initial_balance + 100
            response = client.post("/send?amount=50")
            assert response.json()["balance"] == initial_balance + 50
            response = client.post("/send?amount=50")
            assert response.json()["balance"] == initial_balance
            response = client.get("/pending")
            token = response.json()["pending_token"]["0"]["token"]
            amount = response.json()["pending_token"]["0"]["amount"]
            response = client.post(f"/receive?token={token}")
            assert response.json()["balance"] == initial_balance + amount
