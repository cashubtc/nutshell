import httpx
import pytest
import pytest_asyncio

from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.helpers import pay_if_regtest

BASE_URL = "http://localhost:3337"


@pytest_asyncio.fixture(scope="function")
async def wallet(mint):
    wallet1 = await Wallet.with_db(
        url=BASE_URL,
        db="test_data/wallet_mint_api",
        name="wallet_mint_api",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest.mark.asyncio
async def test_api_keys(ledger: Ledger):
    response = httpx.get(f"{BASE_URL}/keys")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert ledger.keyset.public_keys
    assert response.json() == {
        str(k): v.serialize().hex() for k, v in ledger.keyset.public_keys.items()
    }


@pytest.mark.asyncio
async def test_api_keysets(ledger: Ledger):
    response = httpx.get(f"{BASE_URL}/keysets")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert ledger.keyset.public_keys
    assert response.json()["keysets"] == list(ledger.keysets.keysets.keys())


@pytest.mark.asyncio
async def test_api_keyset_keys(ledger: Ledger):
    response = httpx.get(f"{BASE_URL}/keys/d5c08d2006765ffc")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert ledger.keyset.public_keys
    assert response.json() == {
        str(k): v.serialize().hex() for k, v in ledger.keyset.public_keys.items()
    }


@pytest.mark.asyncio
async def test_split(ledger: Ledger, wallet: Wallet):
    invoice = await wallet.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet.mint(64, id=invoice.id)
    assert wallet.balance == 64
    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(200, 201)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)
    # outputs = wallet._construct_outputs([32, 32], ["a", "b"], ["c", "d"])
    inputs_payload = [p.to_dict() for p in wallet.proofs]
    outputs_payload = [o.dict() for o in outputs]
    payload = {"proofs": inputs_payload, "outputs": outputs_payload}
    response = httpx.post(f"{BASE_URL}/split", json=payload, timeout=None)
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert result["promises"]


@pytest.mark.asyncio
async def test_split_deprecated_with_amount(ledger: Ledger, wallet: Wallet):
    invoice = await wallet.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet.mint(64, id=invoice.id)
    assert wallet.balance == 64
    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(300, 301)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)
    # outputs = wallet._construct_outputs([32, 32], ["a", "b"], ["c", "d"])
    inputs_payload = [p.to_dict() for p in wallet.proofs]
    outputs_payload = [o.dict() for o in outputs]
    # we supply an amount here, which should cause the very old deprecated split endpoint to be used
    payload = {"proofs": inputs_payload, "outputs": outputs_payload, "amount": 32}
    response = httpx.post(f"{BASE_URL}/split", json=payload, timeout=None)
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    # old deprecated output format
    assert result["fst"]
    assert result["snd"]


@pytest.mark.asyncio
async def test_api_mint_validation(ledger):
    response = httpx.get(f"{BASE_URL}/mint?amount=-21")
    assert "detail" in response.json()
    response = httpx.get(f"{BASE_URL}/mint?amount=0")
    assert "detail" in response.json()
    response = httpx.get(f"{BASE_URL}/mint?amount=2100000000000001")
    assert "detail" in response.json()
    response = httpx.get(f"{BASE_URL}/mint?amount=1")
    assert "detail" not in response.json()
