import httpx
import pytest
import pytest_asyncio

from cashu.core.base import (
    CheckSpendableRequest_deprecated,
    CheckSpendableResponse_deprecated,
    Proof,
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
        db="test_data/wallet_mint_api_deprecated",
        name="wallet_mint_api_deprecated",
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
    assert response.json()["keysets"] == list(ledger.keysets.keys())


@pytest.mark.asyncio
async def test_api_keyset_keys(ledger: Ledger):
    response = httpx.get(f"{BASE_URL}/keys/009a1f293253e41e")
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
    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(20000, 20001)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)
    # outputs = wallet._construct_outputs([32, 32], ["a", "b"], ["c", "d"])
    inputs_payload = [p.to_dict() for p in wallet.proofs]
    outputs_payload = [o.dict() for o in outputs]
    # strip "id" from outputs_payload, which is not used in the deprecated split endpoint
    for o in outputs_payload:
        o.pop("id")
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
    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(80000, 80001)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)
    # outputs = wallet._construct_outputs([32, 32], ["a", "b"], ["c", "d"])
    inputs_payload = [p.to_dict() for p in wallet.proofs]
    outputs_payload = [o.dict() for o in outputs]
    # strip "id" from outputs_payload, which is not used in the deprecated split endpoint
    for o in outputs_payload:
        o.pop("id")
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


@pytest.mark.asyncio
async def test_mint(ledger: Ledger, wallet: Wallet):
    invoice = await wallet.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    quote_id = invoice.id
    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)
    outputs_payload = [o.dict() for o in outputs]
    response = httpx.post(
        f"{BASE_URL}/mint",
        json={"outputs": outputs_payload},
        params={"hash": quote_id},
        timeout=None,
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert len(result["promises"]) == 2
    assert result["promises"][0]["amount"] == 32
    assert result["promises"][1]["amount"] == 32
    if settings.debug_mint_only_deprecated:
        assert result["promises"][0]["id"] == "eGnEWtdJ0PIM"
    else:
        assert result["promises"][0]["id"] == "009a1f293253e41e"
    assert result["promises"][0]["dleq"]
    assert "e" in result["promises"][0]["dleq"]
    assert "s" in result["promises"][0]["dleq"]


@pytest.mark.asyncio
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
        f"{BASE_URL}/melt",
        json={
            "pr": invoice_payment_request,
            "proofs": inputs_payload,
            "outputs": outputs_payload,
        },
        timeout=None,
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert result.get("preimage") is not None
    assert result["paid"] is True


@pytest.mark.asyncio
async def test_melt_internal_no_change_outputs(ledger: Ledger, wallet: Wallet):
    # Clients without NUT-08 will not send change outputs
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

    response = httpx.post(
        f"{BASE_URL}/melt",
        json={
            "pr": invoice_payment_request,
            "proofs": inputs_payload,
        },
        timeout=None,
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert result.get("preimage") is not None
    assert result["paid"] is True


@pytest.mark.asyncio
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

    # create invoice to melt to
    # use 2 sat less because we need to pay the fee
    invoice_dict = get_real_invoice(62)
    invoice_payment_request = invoice_dict["payment_request"]

    quote = await wallet.melt_quote(invoice_payment_request)
    assert quote.amount == 62
    assert quote.fee_reserve == 2

    inputs_payload = [p.to_dict() for p in wallet.proofs]

    # outputs for change
    secrets, rs, derivation_paths = await wallet.generate_n_secrets(1)
    outputs, rs = wallet._construct_outputs([2], secrets, rs)
    outputs_payload = [o.dict() for o in outputs]

    response = httpx.post(
        f"{BASE_URL}/melt",
        json={
            "pr": invoice_payment_request,
            "proofs": inputs_payload,
            "outputs": outputs_payload,
        },
        timeout=None,
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert result.get("preimage") is not None
    assert result["paid"] is True
    assert result["change"]
    # we get back 2 sats because Lightning was free to pay on regtest
    assert result["change"][0]["amount"] == 2


@pytest.mark.asyncio
async def test_checkfees(ledger: Ledger, wallet: Wallet):
    # internal invoice
    invoice = await wallet.request_mint(64)
    response = httpx.post(
        f"{BASE_URL}/checkfees",
        json={
            "pr": invoice.bolt11,
        },
        timeout=None,
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    # internal invoice, so no fee
    assert result["fee"] == 0


@pytest.mark.asyncio
@pytest.mark.skipif(not is_regtest, reason="only works on regtest")
async def test_checkfees_external(ledger: Ledger, wallet: Wallet):
    # external invoice
    invoice_dict = get_real_invoice(62)
    invoice_payment_request = invoice_dict["payment_request"]
    response = httpx.post(
        f"{BASE_URL}/checkfees",
        json={"pr": invoice_payment_request},
        timeout=None,
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    # external invoice, so fee
    assert result["fee"] == 2


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_api_check_state(ledger: Ledger):
    proofs = [
        Proof(id="1234", amount=0, secret="asdasdasd", C="asdasdasd"),
        Proof(id="1234", amount=0, secret="asdasdasd1", C="asdasdasd1"),
    ]
    payload = CheckSpendableRequest_deprecated(proofs=proofs)
    response = httpx.post(
        f"{BASE_URL}/check",
        json=payload.dict(),
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    states = CheckSpendableResponse_deprecated.parse_obj(response.json())
    assert states.spendable
    assert len(states.spendable) == 2
    assert states.pending
    assert len(states.pending) == 2
