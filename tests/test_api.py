from fastapi.testclient import TestClient

from cashu.core.settings import settings
from cashu.wallet.api.app import app

# needs mint running with "poetry run mint"
client = TestClient(app)


def test_invoice():
    response = client.post("/invoice?amount=100")
    assert response.status_code == 200
    if settings.lightning:
        assert response.json()["invoice"]
    else:
        assert response.json()["balance"]
        assert response.json()["amount"]


def test_balance():
    response = client.get("/balance")
    assert response.status_code == 200
    assert response.json()["balance"]
    assert response.json()["balance per keyset"]
    assert response.json()["mint 1"]


def test_send():
    response = client.post("/send?amount=10")
    assert response.status_code == 200
    assert response.json()["balance"]


def test_pending():
    response = client.get("/pending")
    assert response.status_code == 200
    assert response.json()["0"]


def test_receive():
    response = client.post("/receive?all=true")
    assert response.status_code == 200
    assert response.json()["initial balance"]
    assert response.json()["balance"]


def test_burn():
    response = client.post("/send?amount=20")
    assert response.status_code == 200
    response = client.post("/burn?all=true")
    assert response.status_code == 200
    assert response.json()["balance"]


def test_pay():
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
    response = client.get("/lock")
    assert response.status_code == 200


def test_locks():
    response = client.get("/locks")
    assert response.status_code == 200


def test_invoices():
    response = client.get("/invoices")
    assert response.status_code == 200
    assert response.json()["invoices"]


def test_wallets():
    response = client.get("/wallets")
    assert response.status_code == 200


def test_info():
    response = client.get("/info")
    assert response.status_code == 200
    assert response.json()["version"]


def test_flow():
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
        token = response.json()["0"]["token"]
        amount = response.json()["0"]["amount"]
        response = client.post(f"/receive?token={token}")
        assert response.json()["balance"] == initial_balance + amount
