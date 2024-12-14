import bolt11
import httpx
import pytest
import pytest_asyncio

from cashu.core.base import MeltQuoteState, MintQuoteState
from cashu.core.models import (
    GetInfoResponse,
    MintMethodSetting,
    PostCheckStateRequest,
    PostCheckStateResponse,
    PostMeltQuoteResponse,
    PostMintQuoteResponse,
    PostRestoreRequest,
    PostRestoreResponse,
)
from cashu.core.nuts import nut20
from cashu.core.nuts.nuts import MINT_NUT
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from cashu.wallet.crud import bump_secret_derivation
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
    info = GetInfoResponse(**response.json())
    assert info.nuts
    assert info.nuts[MINT_NUT]["disabled"] is False
    setting = MintMethodSetting.parse_obj(info.nuts[MINT_NUT]["methods"][0])
    assert setting.method == "bolt11"
    assert setting.unit == "sat"


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
                    str(k): v.serialize().hex()
                    for k, v in keyset.public_keys.items()  # type: ignore
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
                "input_fee_ppk": 0,
            },
            {
                "id": "00c074b96c7e2b0e",
                "unit": "usd",
                "active": True,
                "input_fee_ppk": 0,
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
async def test_split(ledger: Ledger, wallet: Wallet):
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64
    secrets, rs, derivation_paths = await wallet.generate_n_secrets(2)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)
    # outputs = wallet._construct_outputs([32, 32], ["a", "b"], ["c", "d"])
    inputs_payload = [p.to_dict() for p in wallet.proofs]
    outputs_payload = [o.dict() for o in outputs]
    payload = {"inputs": inputs_payload, "outputs": outputs_payload}
    response = httpx.post(f"{BASE_URL}/v1/swap", json=payload, timeout=None)
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
        json={"unit": "sat", "amount": 100, "pubkey": "02" + "00" * 32},
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert result["quote"]
    assert result["request"]
    assert result["pubkey"] == "02" + "00" * 32

    # deserialize the response
    resp_quote = PostMintQuoteResponse(**result)
    assert resp_quote.quote == result["quote"]
    assert resp_quote.state == MintQuoteState.unpaid.value

    # check if DEPRECATED paid flag is also returned
    assert result["paid"] is False
    assert resp_quote.paid is False

    invoice = bolt11.decode(result["request"])
    assert invoice.amount_msat == 100 * 1000

    expiry = None
    if invoice.expiry is not None:
        expiry = invoice.date + invoice.expiry

    assert result["expiry"] == expiry

    # pay the invoice
    await pay_if_regtest(result["request"])

    # get mint quote again from api
    response = httpx.get(
        f"{BASE_URL}/v1/mint/quote/bolt11/{result['quote']}",
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result2 = response.json()
    assert result2["quote"] == result["quote"]
    # deserialize the response
    resp_quote = PostMintQuoteResponse(**result2)
    assert resp_quote.quote == result["quote"]
    assert resp_quote.state == MintQuoteState.paid.value

    # check if DEPRECATED paid flag is also returned
    assert result2["paid"] is True
    assert resp_quote.paid is True
    assert resp_quote.pubkey == "02" + "00" * 32


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_mint(ledger: Ledger, wallet: Wallet):
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)
    assert mint_quote.privkey
    signature = nut20.sign_mint_quote(mint_quote.quote, outputs, mint_quote.privkey)
    outputs_payload = [o.dict() for o in outputs]
    response = httpx.post(
        f"{BASE_URL}/v1/mint/bolt11",
        json={
            "quote": mint_quote.quote,
            "outputs": outputs_payload,
            "signature": signature,
        },
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
async def test_mint_bolt11_no_signature(ledger: Ledger, wallet: Wallet):
    """
    For backwards compatibility, we do not require a NUT-20 signature
    for minting with bolt11.
    """

    response = httpx.post(
        f"{BASE_URL}/v1/mint/quote/bolt11",
        json={
            "unit": "sat",
            "amount": 64,
            # no pubkey
        },
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert result["pubkey"] is None
    await pay_if_regtest(result["request"])
    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)
    outputs_payload = [o.dict() for o in outputs]
    response = httpx.post(
        f"{BASE_URL}/v1/mint/bolt11",
        json={
            "quote": result["quote"],
            "outputs": outputs_payload,
            # no signature
        },
        timeout=None,
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"


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
    mint_quote = await wallet.request_mint(64)
    request = mint_quote.request
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

    # deserialize the response
    resp_quote = PostMeltQuoteResponse(**result)
    assert resp_quote.quote == result["quote"]
    assert resp_quote.payment_preimage is None
    assert resp_quote.change is None
    assert resp_quote.state == MeltQuoteState.unpaid.value

    # check if DEPRECATED paid flag is also returned
    assert result["paid"] is False
    assert resp_quote.paid is False

    invoice_obj = bolt11.decode(request)

    expiry = None
    if invoice_obj.expiry is not None:
        expiry = invoice_obj.date + invoice_obj.expiry

    assert result["expiry"] == expiry

    # # get melt quote again from api
    # response = httpx.get(
    #     f"{BASE_URL}/v1/melt/quote/bolt11/{result['quote']}",
    # )
    # assert response.status_code == 200, f"{response.url} {response.status_code}"
    # result2 = response.json()
    # assert result2["quote"] == result["quote"]

    # # deserialize the response
    # resp_quote = PostMeltQuoteResponse(**result2)
    # assert resp_quote.quote == result["quote"]
    # assert resp_quote.payment_preimage is not None
    # assert len(resp_quote.payment_preimage) == 64
    # assert resp_quote.change is not None
    # assert resp_quote.state == MeltQuoteState.paid.value

    # # check if DEPRECATED paid flag is also returned
    # assert result2["paid"] is True
    # assert resp_quote.paid is True


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
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    # create invoice to melt to
    mint_quote = await wallet.request_mint(64)
    invoice_payment_request = mint_quote.request

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
    assert result.get("payment_preimage") is None
    assert result["paid"] is True

    # deserialize the response
    resp_quote = PostMeltQuoteResponse(**result)
    assert resp_quote.quote == quote.quote

    # internal invoice, no preimage, no change
    assert resp_quote.payment_preimage is None
    assert resp_quote.change == []
    assert resp_quote.state == MeltQuoteState.paid.value

    # check if DEPRECATED paid flag is also returned
    assert result["paid"] is True
    assert resp_quote.paid is True


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
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    invoice_dict = get_real_invoice(62)
    invoice_payment_request = invoice_dict["payment_request"]

    quote = await wallet.melt_quote(invoice_payment_request)
    assert quote.amount == 62
    assert quote.fee_reserve == 2

    keep, send = await wallet.swap_to_send(wallet.proofs, 64)
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
    response.raise_for_status()
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert result.get("payment_preimage") is not None
    assert result["paid"] is True
    assert result["change"]
    # we get back 2 sats because Lightning was free to pay on regtest
    assert result["change"][0]["amount"] == 2

    # deserialize the response
    resp_quote = PostMeltQuoteResponse(**result)
    assert resp_quote.quote == quote.quote
    assert resp_quote.payment_preimage is not None
    assert len(resp_quote.payment_preimage) == 64
    assert resp_quote.change is not None
    assert resp_quote.change[0].amount == 2
    assert resp_quote.state == MeltQuoteState.paid.value

    # check if DEPRECATED paid flag is also returned
    assert result["paid"] is True
    assert resp_quote.paid is True


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_api_check_state(ledger: Ledger):
    payload = PostCheckStateRequest(Ys=["asdasdasd", "asdasdasd1"])
    response = httpx.post(
        f"{BASE_URL}/v1/checkstate",
        json=payload.dict(),
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    response = PostCheckStateResponse.parse_obj(response.json())
    assert response
    assert len(response.states) == 2
    assert response.states[0].state.unspent


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_api_restore(ledger: Ledger, wallet: Wallet):
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64
    secret_counter = await bump_secret_derivation(
        db=wallet.db, keyset_id=wallet.keyset_id, by=0, skip=True
    )
    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(
        secret_counter - 1, secret_counter - 1
    )
    outputs, rs = wallet._construct_outputs([64], secrets, rs)

    payload = PostRestoreRequest(outputs=outputs)
    response = httpx.post(
        f"{BASE_URL}/v1/restore",
        json=payload.dict(),
    )
    data = response.json()
    assert "signatures" in data
    assert "outputs" in data
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    response = PostRestoreResponse.parse_obj(response.json())
    assert response
    assert response
    assert len(response.signatures) == 1
    assert len(response.outputs) == 1
    assert response.outputs == outputs
