import bolt11
import httpx
import pytest
import pytest_asyncio

from cashu.core.base import (
    PostCheckStateRequest,
    PostCheckStateResponse,
    SpentState,
)
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.helpers import get_real_invoice, is_fake, is_regtest, pay_if_regtest

BASE_URL = "http://localhost:3337"


@pytest_asyncio.fixture(scope="function")
async def wallet(ledger: Ledger):
    wallet1 = await Wallet.with_db(
        url=BASE_URL,
        db="test_data/wallet_mint_api",
        name="wallet_mint_api",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_info(ledger: Ledger):
    response = httpx.get(f"{BASE_URL}/v1/info")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert ledger.pubkey
    assert response.json()["pubkey"] == ledger.pubkey.serialize().hex()


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_api_keys(ledger: Ledger):
    response = httpx.get(f"{BASE_URL}/v1/keys")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert ledger.keyset.public_keys
    expected = {
        "keysets": [
            {
                "id": keyset.id,
                "unit": keyset.unit.name,
                "keys": {
                    str(k): v.serialize().hex() for k, v in keyset.public_keys.items()  # type: ignore
                },
            }
            for keyset in ledger.keysets.values()
        ]
    }
    assert response.json() == expected


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_api_keysets(ledger: Ledger):
    response = httpx.get(f"{BASE_URL}/v1/keysets")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    expected = {
        "keysets": [
            {
                "id": "009a1f293253e41e",
                "unit": "sat",
                "active": True,
            },
            # for backwards compatibility of the new keyset ID format,
            # we also return the same keyset with the old base64 ID
            {
                "id": "eGnEWtdJ0PIM",
                "unit": "sat",
                "active": True,
            },
        ]
    }
    assert response.json() == expected


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_api_keyset_keys(ledger: Ledger):
    response = httpx.get(f"{BASE_URL}/v1/keys/009a1f293253e41e")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert ledger.keyset.public_keys
    expected = {
        "keysets": [
            {
                "id": "009a1f293253e41e",
                "unit": "sat",
                "keys": {
                    str(k): v.serialize().hex()
                    for k, v in ledger.keysets["009a1f293253e41e"].public_keys.items()  # type: ignore
                },
            }
        ]
    }
    assert response.json() == expected


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_api_keyset_keys_old_keyset_id(ledger: Ledger):
    response = httpx.get(f"{BASE_URL}/v1/keys/eGnEWtdJ0PIM")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert ledger.keyset.public_keys
    expected = {
        "keysets": [
            {
                "id": "eGnEWtdJ0PIM",
                "unit": "sat",
                "keys": {
                    str(k): v.serialize().hex()
                    for k, v in ledger.keysets["eGnEWtdJ0PIM"].public_keys.items()  # type: ignore
                },
            }
        ]
    }
    assert response.json() == expected


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_split(ledger: Ledger, wallet: Wallet):
    invoice = await wallet.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet.mint(64, id=invoice.id)
    assert wallet.balance == 64
    secrets, rs, derivation_paths = await wallet.generate_n_secrets(2)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)
    # outputs = wallet._construct_outputs([32, 32], ["a", "b"], ["c", "d"])
    inputs_payload = [p.to_dict() for p in wallet.proofs]
    outputs_payload = [o.dict() for o in outputs]
    payload = {"inputs": inputs_payload, "outputs": outputs_payload}
    response = httpx.post(f"{BASE_URL}/v1/swap", json=payload)
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert len(result["signatures"]) == 2
    assert result["signatures"][0]["amount"] == 32
    assert result["signatures"][1]["amount"] == 32
    assert result["signatures"][0]["id"] == "009a1f293253e41e"
    assert result["signatures"][0]["dleq"]
    assert "e" in result["signatures"][0]["dleq"]
    assert "s" in result["signatures"][0]["dleq"]


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_mint_quote(ledger: Ledger):
    response = httpx.post(
        f"{BASE_URL}/v1/mint/quote/bolt11",
        json={"unit": "sat", "amount": 100},
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert result["quote"]
    assert result["request"]
    invoice = bolt11.decode(result["request"])
    assert invoice.amount_msat == 100 * 1000
    assert result["expiry"] == invoice.expiry

    # get mint quote again from api
    response = httpx.get(
        f"{BASE_URL}/v1/mint/quote/bolt11/{result['quote']}",
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result2 = response.json()
    assert result2["quote"] == result["quote"]


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_mint(ledger: Ledger, wallet: Wallet):
    invoice = await wallet.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    quote_id = invoice.id
    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)
    outputs_payload = [o.dict() for o in outputs]
    response = httpx.post(
        f"{BASE_URL}/v1/mint/bolt11",
        json={"quote": quote_id, "outputs": outputs_payload},
        timeout=None,
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert len(result["signatures"]) == 2
    assert result["signatures"][0]["amount"] == 32
    assert result["signatures"][1]["amount"] == 32
    assert result["signatures"][0]["id"] == "009a1f293253e41e"
    assert result["signatures"][0]["dleq"]
    assert "e" in result["signatures"][0]["dleq"]
    assert "s" in result["signatures"][0]["dleq"]


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
@pytest.mark.skipif(
    is_regtest,
    reason="regtest",
)
async def test_melt_quote_internal(ledger: Ledger, wallet: Wallet):
    # internal invoice
    invoice = await wallet.request_mint(64)
    request = invoice.bolt11
    response = httpx.post(
        f"{BASE_URL}/v1/melt/quote/bolt11",
        json={"unit": "sat", "request": request},
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert result["quote"]
    assert result["amount"] == 64
    # TODO: internal invoice, fee should be 0
    assert result["fee_reserve"] == 0
    invoice_obj = bolt11.decode(request)
    assert result["expiry"] == invoice_obj.expiry

    # get melt quote again from api
    response = httpx.get(
        f"{BASE_URL}/v1/melt/quote/bolt11/{result['quote']}",
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result2 = response.json()
    assert result2["quote"] == result["quote"]


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
@pytest.mark.skipif(
    is_fake,
    reason="only works on regtest",
)
async def test_melt_quote_external(ledger: Ledger, wallet: Wallet):
    # internal invoice
    invoice_dict = get_real_invoice(64)
    request = invoice_dict["payment_request"]
    response = httpx.post(
        f"{BASE_URL}/v1/melt/quote/bolt11",
        json={"unit": "sat", "request": request},
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert result["quote"]
    assert result["amount"] == 64
    # external invoice, fee should be 2
    assert result["fee_reserve"] == 2


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_melt_internal(ledger: Ledger, wallet: Wallet):
    # internal invoice
    invoice = await wallet.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet.mint(64, id=invoice.id)
    assert wallet.balance == 64

    # create invoice to melt to
    invoice = await wallet.request_mint(64)
    invoice_payment_request = invoice.bolt11

    quote = await wallet.melt_quote(invoice_payment_request)
    assert quote.amount == 64
    assert quote.fee_reserve == 0

    inputs_payload = [p.to_dict() for p in wallet.proofs]

    # outputs for change
    secrets, rs, derivation_paths = await wallet.generate_n_secrets(1)
    outputs, rs = wallet._construct_outputs([2], secrets, rs)
    outputs_payload = [o.dict() for o in outputs]

    response = httpx.post(
        f"{BASE_URL}/v1/melt/bolt11",
        json={
            "quote": quote.quote,
            "inputs": inputs_payload,
            "outputs": outputs_payload,
        },
        timeout=None,
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert result.get("payment_preimage") is not None
    assert result["paid"] is True


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
@pytest.mark.skipif(
    is_fake,
    reason="only works on regtest",
)
async def test_melt_external(ledger: Ledger, wallet: Wallet):
    # internal invoice
    invoice = await wallet.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet.mint(64, id=invoice.id)
    assert wallet.balance == 64

    invoice_dict = get_real_invoice(62)
    invoice_payment_request = invoice_dict["payment_request"]

    quote = await wallet.melt_quote(invoice_payment_request)
    assert quote.amount == 62
    assert quote.fee_reserve == 2

    keep, send = await wallet.split_to_send(wallet.proofs, 64)
    inputs_payload = [p.to_dict() for p in send]

    # outputs for change
    secrets, rs, derivation_paths = await wallet.generate_n_secrets(1)
    outputs, rs = wallet._construct_outputs([2], secrets, rs)
    outputs_payload = [o.dict() for o in outputs]

    response = httpx.post(
        f"{BASE_URL}/v1/melt/bolt11",
        json={
            "quote": quote.quote,
            "inputs": inputs_payload,
            "outputs": outputs_payload,
        },
        timeout=None,
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert result.get("payment_preimage") is not None
    assert result["paid"] is True
    assert result["change"]
    # we get back 2 sats because Lightning was free to pay on regtest
    assert result["change"][0]["amount"] == 2


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_api_check_state(ledger: Ledger):
    payload = PostCheckStateRequest(secrets=["asdasdasd", "asdasdasd1"])
    response = httpx.post(
        f"{BASE_URL}/v1/checkstate",
        json=payload.dict(),
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    response = PostCheckStateResponse.parse_obj(response.json())
    assert response
    assert len(response.states) == 2
    assert response.states[0].state == SpentState.unspent
