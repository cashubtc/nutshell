import pytest
import pytest_asyncio

from cashu.core.base import Amount, BlindedMessage, MeltQuoteState, Method, Proof, Unit
from cashu.core.crypto.b_dhke import step1_alice, step3_alice
from cashu.core.crypto.secp import PublicKey
from cashu.core.errors import (
    KeysetInactiveError,
    OutputsAlreadySignedError,
    OutputsArePendingError,
    TransactionDuplicateOutputsError,
    TransactionError,
)
from cashu.core.models import PostMeltQuoteRequest, PostMintQuoteRequest
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from tests.helpers import is_fake

pytestmark = [pytest.mark.asyncio, pytest.mark.skipif(not is_fake, reason="FakeWallet")]


@pytest_asyncio.fixture
async def issued_proof(ledger: Ledger) -> Proof:
    secret = "keyset-change-input"
    B_, r = step1_alice(secret)
    quote = await ledger.mint_quote(PostMintQuoteRequest(amount=64, unit="sat"))
    promises = await ledger.mint(
        outputs=[BlindedMessage(id=ledger.keyset.id, amount=64, B_=B_.format().hex())],
        quote_id=quote.quote,
    )
    promise = promises[0]
    C = step3_alice(
        PublicKey(bytes.fromhex(promise.C_)),
        r,
        ledger.keysets[promise.id].public_keys[64],
    )
    return Proof(id=promise.id, amount=64, secret=secret, C=C.format().hex())


async def _melt_quote(ledger: Ledger):
    invoice = await ledger.backends[Method.bolt11][Unit.sat].create_invoice(
        Amount(Unit.sat, 32)
    )
    return await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=invoice.payment_request)
    )


@pytest.mark.parametrize(
    "rotation_stage",
    ["before_submission", "before_storage", "during_payment", "recovery"],
)
async def test_melt_change_survives_keyset_rotation(
    ledger: Ledger, issued_proof: Proof, monkeypatch, rotation_stage: str
):
    keyset = ledger.keysets[issued_proof.id]
    quote = await _melt_quote(ledger)
    secrets = [f"keyset-change-{i}" for i in range(6)]
    blinds = [step1_alice(secret) for secret in secrets]
    outputs = [
        BlindedMessage(id=keyset.id, amount=0, B_=B_.format().hex()) for B_, _ in blinds
    ]

    if rotation_stage == "before_submission":
        await ledger.rotate_next_keyset(Unit.sat)
    elif rotation_stage == "before_storage":
        store = ledger._store_blinded_messages

        async def rotate_before_storage(*args, **kwargs):
            await ledger.rotate_next_keyset(Unit.sat)
            return await store(*args, **kwargs)

        monkeypatch.setattr(ledger, "_store_blinded_messages", rotate_before_storage)
    elif rotation_stage == "during_payment":
        backend = ledger.backends[Method.bolt11][Unit.sat]
        pay_invoice = backend.pay_invoice

        async def rotate_after_payment(*args, **kwargs):
            result = await pay_invoice(*args, **kwargs)
            await ledger.rotate_next_keyset(Unit.sat)
            return result

        monkeypatch.setattr(backend, "pay_invoice", rotate_after_payment)
    else:
        monkeypatch.setattr(settings, "fakewallet_pay_invoice_state", "PENDING")
        monkeypatch.setattr(settings, "fakewallet_payment_state", "PENDING")

    response = await ledger.melt(
        proofs=[issued_proof], quote=quote.quote, outputs=outputs
    )
    if rotation_stage == "recovery":
        assert response.state == MeltQuoteState.pending.value
        await ledger.rotate_next_keyset(Unit.sat)
        monkeypatch.setattr(settings, "fakewallet_payment_state", "SETTLED")
    else:
        assert response.state == MeltQuoteState.paid.value

    settled = await ledger.get_melt_quote(quote.quote)
    assert settled.paid
    assert not keyset.active
    assert settled.change
    assert {promise.id for promise in settled.change} == {keyset.id}
    change_amount = issued_proof.amount - quote.amount - settled.fee_paid
    assert sum(promise.amount for promise in settled.change) == change_amount > 0

    change_proofs = [
        Proof(
            id=promise.id,
            amount=promise.amount,
            secret=secret,
            C=step3_alice(
                PublicKey(bytes.fromhex(promise.C_)),
                r,
                keyset.public_keys[promise.amount],
            )
            .format()
            .hex(),
        )
        for promise, secret, (_, r) in zip(settled.change, secrets, blinds)
    ]
    await ledger._verify_inputs(change_proofs)
    states = await ledger.db_read.get_proofs_states([issued_proof.Y])
    assert states[0].spent
    assert not await ledger.crud.get_pending_proofs_for_quote(
        quote_id=quote.quote, db=ledger.db
    )
    assert not await ledger.crud.get_blinded_messages_melt_id(
        melt_id=quote.quote, db=ledger.db, signed=False
    )
    _, restored = await ledger.restore(outputs)
    assert restored == settled.change
    retry = await ledger._finalize_melt_paid(quote.quote)
    assert retry.change == settled.change
    balance, _ = await ledger.crud.get_balance(db=ledger.db, keyset=keyset)
    assert balance.amount == change_amount


@pytest.mark.parametrize("operation", ["mint", "swap"])
async def test_ordinary_outputs_reject_rotated_keyset(
    ledger: Ledger, issued_proof: Proof, operation: str
):
    quote = await ledger.mint_quote(PostMintQuoteRequest(amount=64, unit="sat"))
    B_, _ = step1_alice("ordinary-output-after-rotation")
    outputs = [BlindedMessage(id=issued_proof.id, amount=64, B_=B_.format().hex())]
    await ledger.rotate_next_keyset(Unit.sat)

    with pytest.raises(KeysetInactiveError):
        if operation == "mint":
            await ledger.mint(outputs=outputs, quote_id=quote.quote)
        else:
            await ledger.swap(proofs=[issued_proof], outputs=outputs)

    states = await ledger.db_read.get_proofs_states([issued_proof.Y])
    assert states[0].unspent
    assert await ledger.restore(outputs) == ([], [])


@pytest.mark.parametrize(
    "invalid, error, message",
    [
        ("unknown", TransactionError, "keyset id unknown"),
        ("mixed", TransactionError, "different keyset ids"),
        ("unit", TransactionError, "output unit usd does not match quote unit sat"),
        ("blinded_message", TransactionError, "invalid blinded message"),
        ("duplicate", TransactionDuplicateOutputsError, None),
        ("signed", OutputsAlreadySignedError, None),
        ("pending", OutputsArePendingError, None),
    ],
)
async def test_inactive_change_preserves_output_validation(
    ledger: Ledger, issued_proof: Proof, invalid: str, error, message
):
    quote = await _melt_quote(ledger)
    B_, _ = step1_alice("invalid-change")
    output = BlindedMessage(id=issued_proof.id, amount=1, B_=B_.format().hex())
    outputs = [output]
    if invalid in ("signed", "pending"):
        await ledger._store_blinded_messages(outputs)
        if invalid == "signed":
            await ledger._sign_blinded_messages(outputs)

    new_keyset = await ledger.rotate_next_keyset(Unit.sat)
    if invalid == "unknown":
        output.id = "ff" * 33
    elif invalid == "mixed":
        outputs.append(output.model_copy(update={"id": new_keyset.id}))
    elif invalid == "unit":
        usd_keyset = next(k for k in ledger.keysets.values() if k.unit == Unit.usd)
        await ledger.rotate_next_keyset(Unit.usd)
        output.id = usd_keyset.id
    elif invalid == "blinded_message":
        output.B_ = "deadbeef"
    elif invalid == "duplicate":
        outputs.append(output.model_copy())

    with pytest.raises(error, match=message):
        await ledger.melt(proofs=[issued_proof], quote=quote.quote, outputs=outputs)

    states = await ledger.db_read.get_proofs_states([issued_proof.Y])
    assert states[0].unspent
