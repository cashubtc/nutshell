import bolt11
import httpx
import pytest
import pytest_asyncio

from cashu.core.base import CheckSpendableRequest, CheckSpendableResponse, Proof
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
async def test_info(ledger: Ledger):
    response = httpx.get(f"{BASE_URL}/info")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert ledger.pubkey
    assert response.json()["pubkey"] == ledger.pubkey.serialize().hex()


@pytest.mark.asyncio
async def test_api_keys(ledger: Ledger):
    response = httpx.get(f"{BASE_URL}/v1/keys")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert ledger.keyset.public_keys
    expected = {
        "keysets": [
            {
                "id": "d5c08d2006765ffc",
                "unit": "sat",
                "keys": {
                    str(k): v.serialize().hex()
                    for k, v in ledger.keyset.public_keys.items()
                },
            }
        ]
    }
    assert response.json() == expected


@pytest.mark.asyncio
async def test_api_keysets(ledger: Ledger):
    response = httpx.get(f"{BASE_URL}/v1/keysets")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    expected = {
        "keysets": [
            {
                "id": "d5c08d2006765ffc",
                "unit": "sat",
                "active": True,
            },
            # for backwards compatibility of the new keyset ID format,
            # we also return the same keyset with the old base64 ID
            {
                "id": "1cCNIAZ2X/w1",
                "unit": "sat",
                "active": True,
            },
        ]
    }
    assert response.json() == expected


@pytest.mark.asyncio
async def test_api_keyset_keys(ledger: Ledger):
    response = httpx.get(f"{BASE_URL}/v1/keys/d5c08d2006765ffc")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert ledger.keyset.public_keys
    expected = {
        "keysets": [
            {
                "id": "d5c08d2006765ffc",
                "unit": "sat",
                "keys": {
                    str(k): v.serialize().hex()
                    for k, v in ledger.keyset.public_keys.items()
                },
            }
        ]
    }
    assert response.json() == expected


@pytest.mark.asyncio
async def test_api_keyset_keys_old_keyset_id(ledger: Ledger):
    response = httpx.get(f"{BASE_URL}/v1/keys/1cCNIAZ2X_w1")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert ledger.keyset.public_keys
    expected = {
        "keysets": [
            {
                "id": "1cCNIAZ2X/w1",
                "unit": "sat",
                "keys": {
                    str(k): v.serialize().hex()
                    for k, v in ledger.keyset.public_keys.items()
                },
            }
        ]
    }
    assert response.json() == expected


@pytest.mark.asyncio
async def test_split(ledger: Ledger, wallet: Wallet):
    invoice = await wallet.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet.mint(64, id=invoice.id)
    assert wallet.balance == 64
    secrets, rs, derivation_paths = await wallet.generate_n_secrets(2, skip_bump=True)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)
    # outputs = wallet._construct_outputs([32, 32], ["a", "b"], ["c", "d"])
    inputs_payload = [p.to_dict() for p in wallet.proofs]
    outputs_payload = [o.dict() for o in outputs]
    payload = {"inputs": inputs_payload, "outputs": outputs_payload}
    response = httpx.post(f"{BASE_URL}/v1/split", json=payload)
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert len(result["signatures"]) == 2
    assert result["signatures"][0]["amount"] == 32
    assert result["signatures"][1]["amount"] == 32
    assert result["signatures"][0]["id"] == "d5c08d2006765ffc"
    assert result["signatures"][0]["dleq"]
    assert "e" in result["signatures"][0]["dleq"]
    assert "s" in result["signatures"][0]["dleq"]


@pytest.mark.asyncio
async def test_mint_quote(ledger: Ledger):
    response = httpx.post(
        f"{BASE_URL}/v1/mint/quote",
        json={"method": "bolt11", "unit": "sat", "amount": 100},
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert result["quote"]
    assert result["request"]
    assert result["method"] == "bolt11"
    assert result["unit"] == "sat"
    assert result["amount"] == 100
    invoice = bolt11.decode(result["request"])
    assert invoice.amount_msat == 100 * 1000


@pytest.mark.asyncio
async def test_mint(ledger: Ledger, wallet: Wallet):
    invoice = await wallet.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    quote_id = invoice.id
    secrets, rs, derivation_paths = await wallet.generate_n_secrets(2, skip_bump=True)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)
    outputs_payload = [o.dict() for o in outputs]
    response = httpx.post(
        f"{BASE_URL}/v1/mint",
        json={"quote": quote_id, "outputs": outputs_payload},
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert result["quote"] == quote_id
    assert len(result["signatures"]) == 2
    assert result["signatures"][0]["amount"] == 32
    assert result["signatures"][1]["amount"] == 32
    assert result["signatures"][0]["id"] == "d5c08d2006765ffc"
    assert result["signatures"][0]["dleq"]
    assert "e" in result["signatures"][0]["dleq"]
    assert "s" in result["signatures"][0]["dleq"]


@pytest.mark.asyncio
async def test_melt_quote(ledger: Ledger, wallet: Wallet):
    # internal invoice
    invoice = await wallet.request_mint(64)
    request = invoice.bolt11
    response = httpx.post(
        f"{BASE_URL}/v1/melt/quote",
        json={"method": "bolt11", "unit": "sat", "request": request},
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert result["quote"]
    assert result["unit"] == "sat"
    assert result["amount"] == 64
    # internal invoice, fee should be 0
    assert result["fee_reserve"] == 0


@pytest.mark.asyncio
async def test_api_check_state(ledger: Ledger):
    proofs = [
        Proof(id="1234", amount=0, secret="asdasdasd", C="asdasdasd"),
        Proof(id="1234", amount=0, secret="asdasdasd1", C="asdasdasd1"),
    ]
    payload = CheckSpendableRequest(proofs=proofs)
    response = httpx.post(
        f"{BASE_URL}/check",
        json=payload.dict(),
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    states = CheckSpendableResponse.parse_obj(response.json())
    assert states.spendable
    assert len(states.spendable) == 2
    assert states.pending
    assert len(states.pending) == 2
