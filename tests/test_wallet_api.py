import asyncio

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from cashu.lightning.base import InvoiceResponse, PaymentStatus
from cashu.wallet.api.app import app
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import is_regtest


@pytest_asyncio.fixture(scope="function")
async def wallet():
    wallet = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet",
        name="wallet",
    )
    await wallet.load_mint()
    yield wallet


@pytest.mark.skipif(is_regtest, reason="regtest")
@pytest.mark.asyncio
async def test_invoice(wallet: Wallet):
    with TestClient(app) as client:
        response = client.post("/lightning/create_invoice?amount=100")
        assert response.status_code == 200
        invoice_response = InvoiceResponse.parse_obj(response.json())
        state = PaymentStatus(paid=False)
        while not state.paid:
            print("checking invoice state")
            response2 = client.get(
                f"/lightning/invoice_state?payment_hash={invoice_response.checking_id}"
            )
            state = PaymentStatus.parse_obj(response2.json())
            await asyncio.sleep(0.1)
            print("state:", state)
        print("paid")


@pytest.mark.skipif(is_regtest, reason="regtest")
@pytest.mark.asyncio
async def test_balance():
    with TestClient(app) as client:
        response = client.get("/balance")
        assert response.status_code == 200
        assert "balance" in response.json()
        assert response.json()["keysets"]
        assert response.json()["mints"]


@pytest.mark.skipif(is_regtest, reason="regtest")
@pytest.mark.asyncio
async def test_send(wallet: Wallet):
    with TestClient(app) as client:
        response = client.post("/send?amount=10")
        assert response.status_code == 200
        assert response.json()["balance"]


@pytest.mark.skipif(is_regtest, reason="regtest")
@pytest.mark.asyncio
async def test_send_without_split(wallet: Wallet):
    with TestClient(app) as client:
        response = client.post("/send?amount=2&nosplit=true")
        assert response.status_code == 200
        assert response.json()["balance"]


@pytest.mark.skipif(is_regtest, reason="regtest")
@pytest.mark.asyncio
async def test_send_without_split_but_wrong_amount(wallet: Wallet):
    with TestClient(app) as client:
        response = client.post("/send?amount=10&nosplit=true")
        assert response.status_code == 400


@pytest.mark.skipif(is_regtest, reason="regtest")
@pytest.mark.asyncio
async def test_pending():
    with TestClient(app) as client:
        response = client.get("/pending")
        assert response.status_code == 200


@pytest.mark.skipif(is_regtest, reason="regtest")
@pytest.mark.asyncio
async def test_receive_all(wallet: Wallet):
    with TestClient(app) as client:
        response = client.post("/receive?all=true")
        assert response.status_code == 200
        assert response.json()["initial_balance"]
        assert response.json()["balance"]


@pytest.mark.skipif(is_regtest, reason="regtest")
@pytest.mark.asyncio
async def test_burn_all(wallet: Wallet):
    with TestClient(app) as client:
        response = client.post("/send?amount=20")
        assert response.status_code == 200
        response = client.post("/burn?all=true")
        assert response.status_code == 200
        assert response.json()["balance"]


@pytest.mark.skipif(is_regtest, reason="regtest")
@pytest.mark.asyncio
async def test_pay():
    with TestClient(app) as client:
        invoice = (
            "lnbc100n1pjjcqzfdq4gdshx6r4ypjx2ur0wd5hgpp58xvj8yn00d5"
            "7uhshwzcwgy9uj3vwf5y2lr5fjf78s4w9l4vhr6xssp5stezsyty9r"
            "hv3lat69g4mhqxqun56jyehhkq3y8zufh83xyfkmmq4usaqwrt5q4f"
            "adm44g6crckp0hzvuyv9sja7t65hxj0ucf9y46qstkay7gfnwhuxgr"
            "krf7djs38rml39l8wpn5ug9shp3n55quxhdecqfwxg23"
        )
        response = client.post(f"/lightning/pay_invoice?bolt11={invoice}")
        assert response.status_code == 200


@pytest.mark.skipif(is_regtest, reason="regtest")
@pytest.mark.asyncio
async def test_lock():
    with TestClient(app) as client:
        response = client.get("/lock")
        assert response.status_code == 200


@pytest.mark.skipif(is_regtest, reason="regtest")
@pytest.mark.asyncio
async def test_locks():
    with TestClient(app) as client:
        response = client.get("/locks")
        assert response.status_code == 200


@pytest.mark.skipif(is_regtest, reason="regtest")
@pytest.mark.asyncio
async def test_invoices():
    with TestClient(app) as client:
        response = client.get("/invoices")
        assert response.status_code == 200


@pytest.mark.skipif(is_regtest, reason="regtest")
@pytest.mark.asyncio
async def test_wallets():
    with TestClient(app) as client:
        response = client.get("/wallets")
        assert response.status_code == 200


@pytest.mark.skipif(is_regtest, reason="regtest")
@pytest.mark.asyncio
async def test_info():
    with TestClient(app) as client:
        response = client.get("/info")
        assert response.status_code == 200
        assert response.json()["version"]


@pytest.mark.skipif(is_regtest, reason="regtest")
@pytest.mark.asyncio
async def test_flow(wallet: Wallet):
    with TestClient(app) as client:
        response = client.get("/balance")
        initial_balance = response.json()["balance"]
        response = client.post("/lightning/create_invoice?amount=100")
        invoice_response = InvoiceResponse.parse_obj(response.json())
        state = PaymentStatus(paid=False)
        while not state.paid:
            print("checking invoice state")
            response2 = client.get(
                f"/lightning/invoice_state?payment_hash={invoice_response.checking_id}"
            )
            state = PaymentStatus.parse_obj(response2.json())
            await asyncio.sleep(0.1)
            print("state:", state)

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
