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
from cashu.mint.ledger import Ledger
from cashu.wallet.crud import bump_secret_derivation
from cashu.wallet.wallet import Wallet
from tests.helpers import (
    get_real_invoice,
    get_real_invoice_routed,
    is_cln_backend,
    is_fake,
    is_regtest,
    pay_if_regtest,
    use_v2_keyset,
)

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
async def test_landing_page():
    response = httpx.get(f"{BASE_URL}/")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert "text/html" in response.headers.get("content-type", "")
    assert "Cashu Mint" in response.text


@pytest.mark.asyncio
async def test_info(ledger: Ledger):
    response = httpx.get(f"{BASE_URL}/v1/info")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert ledger.pubkey
    assert response.json()["pubkey"] == ledger.pubkey.format().hex()
    info = GetInfoResponse(**response.json())
    assert info.nuts
    assert info.nuts[MINT_NUT]["disabled"] is False
    setting = MintMethodSetting.model_validate(info.nuts[MINT_NUT]["methods"][0])
    assert setting.method == "bolt11"
    assert setting.method_name == "bolt11"
    assert setting.unit == "sat"
    assert setting.options
    assert setting.options.description is True


@pytest.mark.asyncio
async def test_api_keys(ledger: Ledger):
    response = httpx.get(f"{BASE_URL}/v1/keys")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert ledger.keyset.public_keys
    expected = {
        "keysets": [
            {
                "id": keyset.id,
                "unit": keyset.unit.name,
                "active": keyset.active,
                "input_fee_ppk": keyset.input_fee_ppk,
                "keys": {
                    str(k): v.format().hex()
                    for k, v in keyset.public_keys.items()  # type: ignore
                },
                "final_expiry": keyset.final_expiry,
            }
            for keyset in ledger.keysets.values()
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
                "final_expiry": None,
                "id": keyset.id,
                "unit": keyset.unit.name,
                "active": True,
                "input_fee_ppk": 0,
            }
            for keyset in ledger.keysets.values()
        ]
    }
    assert response.json() == expected


@pytest.mark.asyncio
async def test_api_keyset_keys(ledger: Ledger):
    response = httpx.get(f"{BASE_URL}/v1/keys/{ledger.keyset.id}")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert ledger.keyset.public_keys
    expected = {
        "keysets": [
            {
                "final_expiry": None,
                "id": ledger.keyset.id,
                "unit": "sat",
                "active": True,
                "input_fee_ppk": 0,
                "keys": {
                    str(k): v.format().hex()
                    for k, v in ledger.keysets[ledger.keyset.id].public_keys.items()  # type: ignore
                },
            }
        ]
    }
    assert response.json() == expected


@pytest.mark.asyncio
async def test_api_keyset_keys_old_keyset_id(ledger: Ledger):
    response = httpx.get(f"{BASE_URL}/v1/keys/{ledger.keyset.id}")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert ledger.keyset.public_keys
    expected = {
        "keysets": [
            {
                "final_expiry": None,
                "id": ledger.keyset.id,
                "unit": "sat",
                "active": True,
                "input_fee_ppk": 0,
                "keys": {
                    str(k): v.format().hex()
                    for k, v in ledger.keysets[ledger.keyset.id].public_keys.items()  # type: ignore
                },
            }
        ]
    }
    assert response.json() == expected


@pytest.mark.asyncio
async def test_swap(ledger: Ledger, wallet: Wallet):
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64
    secrets, rs, derivation_paths = await wallet.generate_n_secrets(2)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)
    # outputs = wallet._construct_outputs([32, 32], ["a", "b"], ["c", "d"])
    wallet._attach_nutroot_witnesses(wallet.proofs, outputs)
    inputs_payload = [p.to_dict() for p in wallet.proofs]
    outputs_payload = [o.model_dump() for o in outputs]
    payload = {"inputs": inputs_payload, "outputs": outputs_payload}
    response = httpx.post(f"{BASE_URL}/v1/swap", json=payload, timeout=None)
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert len(result["signatures"]) == 2
    assert result["signatures"][0]["amount"] == 32
    assert result["signatures"][1]["amount"] == 32
    assert result["signatures"][0]["id"] == ledger.keyset.id
    # NUT-12 is version-scoped: v3 signatures carry no DLEQ.
    assert result["signatures"][0].get("dleq") is None


@pytest.mark.asyncio
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
    assert resp_quote.amount == 100
    assert resp_quote.unit == "sat"
    assert resp_quote.method == "bolt11"
    assert resp_quote.request == result["request"]
    assert resp_quote.amount_paid == 0
    assert resp_quote.amount_issued == 0
    assert resp_quote.updated_at is not None
    assert resp_quote.updated_at > 0

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
    assert resp_quote.amount == 100
    assert resp_quote.unit == "sat"
    assert resp_quote.method == "bolt11"
    assert resp_quote.request == result["request"]
    assert resp_quote.amount_paid == 100
    assert resp_quote.amount_issued == 0
    assert resp_quote.updated_at is not None
    assert resp_quote.updated_at >= result["updated_at"]

    assert resp_quote.pubkey == "02" + "00" * 32


@pytest.mark.asyncio
async def test_mint(ledger: Ledger, wallet: Wallet):
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)
    assert mint_quote.privkey
    signature = nut20.sign_mint_quote_v3(
        mint_quote.quote, mint_quote.amount, outputs, mint_quote.privkey
    )
    outputs_payload = [o.model_dump() for o in outputs]
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
    assert result["signatures"][0]["id"] == ledger.keyset.id
    # NUT-12 is version-scoped: v3 signatures carry no DLEQ.
    assert result["signatures"][0].get("dleq") is None


@pytest.mark.asyncio
async def test_mint_bolt11_no_signature(ledger: Ledger, wallet: Wallet):
    """
    For backwards compatibility, we do not require a NUT-20 signature
    for minting with bolt11 on pre-v3 keysets. A v3 quote must be locked,
    so this mints onto the v2 keyset.
    """
    await use_v2_keyset(wallet)

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
    outputs_payload = [o.model_dump() for o in outputs]
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
    assert resp_quote.amount == 64
    assert resp_quote.unit == "sat"
    assert resp_quote.method == "bolt11"
    assert resp_quote.request == request

    invoice_obj = bolt11.decode(request)

    expiry = None
    if invoice_obj.expiry is not None:
        expiry = invoice_obj.date + invoice_obj.expiry

    assert result["expiry"] == expiry


@pytest.mark.asyncio
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

    # outputs for change
    secrets, rs, derivation_paths = await wallet.generate_n_secrets(1)
    outputs, rs = wallet._construct_outputs([2], secrets, rs)
    wallet._attach_nutroot_witnesses(
        wallet.proofs, outputs, melt_quote_id=quote.quote, melt_quote_amount=quote.amount
    )
    inputs_payload = [p.to_dict() for p in wallet.proofs]
    outputs_payload = [o.model_dump() for o in outputs]

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

    # deserialize the response
    resp_quote = PostMeltQuoteResponse(**result)
    assert resp_quote.quote == quote.quote

    # internal invoice, no preimage, no change
    assert resp_quote.payment_preimage is None
    assert resp_quote.change == []
    assert resp_quote.state == MeltQuoteState.paid.value
    assert resp_quote.amount == 64
    assert resp_quote.unit == "sat"
    assert resp_quote.method == "bolt11"
    assert resp_quote.request == invoice_payment_request


@pytest.mark.asyncio
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

    # outputs for change
    secrets, rs, derivation_paths = await wallet.generate_n_secrets(1)
    outputs, rs = wallet._construct_outputs([2], secrets, rs)
    wallet._attach_nutroot_witnesses(
        send, outputs, melt_quote_id=quote.quote, melt_quote_amount=quote.amount
    )
    inputs_payload = [p.to_dict() for p in send]
    outputs_payload = [o.model_dump() for o in outputs]

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
    assert result["change"]
    # we get back 2 sats because Lightning was free to pay on regtest
    assert result["change"][0]["amount"] == 2

    # deserialize the response
    resp_quote = PostMeltQuoteResponse(**result)
    assert resp_quote.quote == quote.quote
    assert resp_quote.amount == 62
    assert resp_quote.unit == "sat"
    assert resp_quote.request == invoice_payment_request
    assert resp_quote.payment_preimage is not None
    assert len(resp_quote.payment_preimage) == 64
    assert resp_quote.change is not None
    assert resp_quote.change[0].amount == 2
    assert resp_quote.state == MeltQuoteState.paid.value


@pytest.mark.asyncio
@pytest.mark.skipif(
    is_fake,
    reason="only works on regtest",
)
async def test_melt_external_with_routing_fee(ledger: Ledger, wallet: Wallet):
    # Raw melt payload without a v3 witness, so mint on the pre-v3 keyset.
    await use_v2_keyset(wallet)
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    # external invoice that the mint can only pay through a routing node
    invoice_payment_request = get_real_invoice_routed(62)

    quote = await wallet.melt_quote(invoice_payment_request)
    assert quote.amount == 62
    assert quote.fee_reserve == 2

    keep, send = await wallet.swap_to_send(wallet.proofs, 64)
    inputs_payload = [p.to_dict() for p in send]

    # outputs for change
    secrets, rs, derivation_paths = await wallet.generate_n_secrets(1)
    outputs, rs = wallet._construct_outputs([2], secrets, rs)
    outputs_payload = [o.model_dump() for o in outputs]

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
    resp_quote = PostMeltQuoteResponse(**response.json())
    assert resp_quote.state == MeltQuoteState.paid.value
    assert resp_quote.payment_preimage is not None

    melt_quote = await ledger.crud.get_melt_quote(quote_id=quote.quote, db=ledger.db)
    assert melt_quote, "No melt quote in db"
    assert melt_quote.fee_paid > 0, "No routing fee paid"
    # the mint passes the fee reserve to the backend as the fee limit
    assert melt_quote.fee_paid <= quote.fee_reserve, "Fee exceeded the fee reserve"

    # change must compensate exactly for the unspent part of the reserve
    change_sat = sum([c.amount for c in resp_quote.change or []])
    assert change_sat == quote.fee_reserve - melt_quote.fee_paid, (
        "Wrong change returned"
    )


@pytest.mark.asyncio
@pytest.mark.skipif(
    is_fake,
    reason="only works on regtest",
)
@pytest.mark.skipif(
    is_cln_backend,
    reason="CLN pathfinding is randomized, the exact fee is not deterministic",
)
async def test_melt_external_routing_fee_rounding(ledger: Ledger, wallet: Wallet):
    # Raw melt payload without a v3 witness, so mint on the pre-v3 keyset.
    await use_v2_keyset(wallet)
    mint_quote = await wallet.request_mint(1024)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(1024, quote_id=mint_quote.quote)
    assert wallet.balance == 1024

    # external invoice that the mint can only pay through a routing node
    invoice_payment_request = get_real_invoice_routed(1000)

    quote = await wallet.melt_quote(invoice_payment_request)
    assert quote.amount == 1000
    # fee reserve is 2% of the amount
    assert quote.fee_reserve == 20

    keep, send = await wallet.swap_to_send(wallet.proofs, 1020)
    inputs_payload = [p.to_dict() for p in send]

    # 5 blank outputs for the change of the 20 sat fee reserve
    secrets, rs, derivation_paths = await wallet.generate_n_secrets(5)
    outputs, rs = wallet._construct_outputs([1, 1, 1, 1, 1], secrets, rs)
    outputs_payload = [o.model_dump() for o in outputs]

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
    resp_quote = PostMeltQuoteResponse(**response.json())
    assert resp_quote.state == MeltQuoteState.paid.value

    # the routing fee for 1000 sat is 1001 msat (1000 msat base fee + 1 ppm)
    # which the mint must round up to 2 sat when it accounts the fee
    melt_quote = await ledger.crud.get_melt_quote(quote_id=quote.quote, db=ledger.db)
    assert melt_quote, "No melt quote in db"
    assert melt_quote.fee_paid == 2, "Fee not rounded up to the next sat"

    # we get back the fee reserve minus the rounded up fee
    change_sat = sum([c.amount for c in resp_quote.change or []])
    assert change_sat == 18, "Wrong change returned"


@pytest.mark.asyncio
async def test_api_check_state(ledger: Ledger):
    payload = PostCheckStateRequest(Ys=["asdasdasd", "asdasdasd1"])
    response = httpx.post(
        f"{BASE_URL}/v1/checkstate",
        json=payload.model_dump(),
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    check_state_response = PostCheckStateResponse.model_validate(response.json())
    assert check_state_response
    assert len(check_state_response.states) == 2
    assert check_state_response.states[0].state.unspent


@pytest.mark.asyncio
async def test_api_check_state_v3_serves_witness_digest(
    ledger: Ledger, wallet: Wallet
):
    """A spent v3 proof's state carries the transaction digest its witness
    signed (NUT-07): the witness verifies only against it."""
    from cashu.core.base import ProofSpentState
    from cashu.core.crypto.nutroot import (
        keyset_id_transcript_bytes,
        secret_transcript_bytes,
    )
    from cashu.core.crypto.transcript import (
        TransactionShape,
        TranscriptBlindedOutput,
        TranscriptProofInput,
        transaction_digest,
    )

    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    secrets, rs, derivation_paths = await wallet.generate_n_secrets(2)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)
    inputs = wallet.proofs
    wallet._attach_nutroot_witnesses(inputs, outputs)
    payload = {
        "inputs": [p.to_dict() for p in inputs],
        "outputs": [o.model_dump() for o in outputs],
    }
    response = httpx.post(f"{BASE_URL}/v1/swap", json=payload, timeout=None)
    assert response.status_code == 200, f"{response.url} {response.status_code}"

    expected_digest = transaction_digest(
        TransactionShape(
            proof_inputs=[
                TranscriptProofInput(
                    amount=p.amount,
                    keyset_id=keyset_id_transcript_bytes(p.id),
                    secret=secret_transcript_bytes(p.secret, p.id),
                    C=bytes.fromhex(p.C),
                )
                for p in inputs
            ],
            blinded_outputs=[
                TranscriptBlindedOutput(
                    amount=o.amount,
                    keyset_id=keyset_id_transcript_bytes(o.id),
                    B_=bytes.fromhex(o.B_),
                )
                for o in outputs
            ],
        )
    ).hex()

    state_payload = PostCheckStateRequest(Ys=[p.Y for p in inputs])
    response = httpx.post(
        f"{BASE_URL}/v1/checkstate", json=state_payload.model_dump()
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    states = PostCheckStateResponse.model_validate(response.json()).states
    assert states
    for state in states:
        assert state.state == ProofSpentState.spent
        assert state.witness
        assert state.digest == expected_digest


@pytest.mark.asyncio
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
    original_proof = next(
        proof for proof in wallet.proofs if proof.secret == secrets[0]
    )
    # NUT-12 is version-scoped: v3 proofs carry no DLEQ.
    assert original_proof.dleq is None

    payload = PostRestoreRequest(outputs=outputs)
    response = httpx.post(
        f"{BASE_URL}/v1/restore",
        json=payload.model_dump(),
    )
    data = response.json()
    assert "signatures" in data
    assert "outputs" in data
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    restore_response = PostRestoreResponse.model_validate(response.json())
    assert restore_response
    assert len(restore_response.signatures) == 1
    assert len(restore_response.outputs) == 1
    assert restore_response.outputs == outputs
    assert restore_response.signatures[0].dleq is None


@pytest.mark.asyncio
async def test_mint_quote_check(ledger: Ledger, wallet: Wallet):
    mint_quote1 = await wallet.request_mint(64)
    mint_quote2 = await wallet.request_mint(32)

    response = httpx.post(
        f"{BASE_URL}/v1/mint/quote/bolt11/check",
        json={"quotes": [mint_quote1.quote, mint_quote2.quote]},
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert len(result) == 2
    assert result[0]["quote"] == mint_quote1.quote
    assert result[0]["amount"] == 64
    assert result[0]["method"] == "bolt11"
    assert result[0]["state"] in ["UNPAID", "PAID"]
    assert result[1]["quote"] == mint_quote2.quote
    assert result[1]["amount"] == 32
    assert result[1]["method"] == "bolt11"
    assert result[1]["state"] in ["UNPAID", "PAID"]


@pytest.mark.asyncio
async def test_mint_batch_success(ledger: Ledger, wallet: Wallet):
    mint_quote1 = await wallet.request_mint(64)
    mint_quote2 = await wallet.request_mint(32)

    await pay_if_regtest(mint_quote1.request)
    await pay_if_regtest(mint_quote2.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    # Output total 96, first quote is 64, second is 32
    outputs, rs = wallet._construct_outputs([64, 32], secrets, rs)

    assert mint_quote1.privkey
    assert mint_quote2.privkey

    # Signatures over the one batch transaction digest (all quote inputs + outputs)
    batch = [(mint_quote1.quote, 64), (mint_quote2.quote, 32)]
    sig1 = nut20.sign_mint_quote_batch_v3(batch, outputs, mint_quote1.privkey)
    sig2 = nut20.sign_mint_quote_batch_v3(batch, outputs, mint_quote2.privkey)

    outputs_payload = [o.model_dump() for o in outputs]

    response = httpx.post(
        f"{BASE_URL}/v1/mint/bolt11/batch",
        json={
            "quotes": [mint_quote1.quote, mint_quote2.quote],
            "quote_amounts": [64, 32],
            "outputs": outputs_payload,
            "signatures": [sig1, sig2],
        },
        timeout=None,
    )

    assert response.status_code == 200, (
        f"{response.url} {response.status_code} {response.text}"
    )
    result = response.json()
    assert len(result["signatures"]) == 2
    assert result["signatures"][0]["amount"] == 64
    assert result["signatures"][1]["amount"] == 32


@pytest.mark.asyncio
async def test_mint_batch_duplicate_quotes(ledger: Ledger, wallet: Wallet):
    mint_quote1 = await wallet.request_mint(64)

    response = httpx.post(
        f"{BASE_URL}/v1/mint/bolt11/batch",
        json={
            "quotes": [mint_quote1.quote, mint_quote1.quote],
            "quote_amounts": [64, 64],
            "outputs": [],
            "signatures": [None, None],
        },
    )

    assert response.status_code == 400
    assert "Duplicate quote IDs provided" in response.text


@pytest.mark.asyncio
async def test_mint_batch_wrong_amount(ledger: Ledger, wallet: Wallet):
    mint_quote1 = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote1.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)

    outputs_payload = [o.model_dump() for o in outputs]
    assert mint_quote1.privkey is not None
    sig1 = nut20.sign_mint_quote(mint_quote1.quote, outputs, mint_quote1.privkey)

    response = httpx.post(
        f"{BASE_URL}/v1/mint/bolt11/batch",
        json={
            "quotes": [mint_quote1.quote],
            "quote_amounts": [32],  # Intentionally wrong quote amount
            "outputs": outputs_payload,
            "signatures": [sig1],
        },
    )

    assert response.status_code == 400
    assert "does not match quote" in response.text


def test_format_limit():
    from cashu.mint.router import format_limit

    assert format_limit(1_500_000, "sat") == "1.5M sat"
    assert format_limit(1_000_000, "sat") == "1M sat"
    assert format_limit(1_500, "sat") == "1.5K sat"
    assert format_limit(1_000, "sat") == "1K sat"
    assert format_limit(500, "sat") == "500 sat"
