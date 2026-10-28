from unittest.mock import AsyncMock

import pytest

from cashu.core.base import (
    Amount,
    BlindedMessage,
    BlindedSignature,
    MeltQuoteState,
    Method,
    MintQuoteState,
    Proof,
    Unit,
)
from cashu.core.crypto import b_dhke
from cashu.core.crypto.secp import PrivateKey, PublicKey
from cashu.core.errors import KeysetInactiveError
from cashu.core.models import PostMeltQuoteRequest, PostMintQuoteRequest
from cashu.lightning.base import (
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
    PaymentStatusResult,
)
from cashu.mint.ledger import Ledger
from tests.helpers import get_fake_invoice, is_fake

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(not is_fake, reason="only FakeWallet"),
]


def _outputs(keyset_id: str, amounts: list[int], label: str):
    secrets = [f"{label}-{i}" for i in range(len(amounts))]
    blinded = [b_dhke.step1_alice(secret) for secret in secrets]
    outputs = [
        BlindedMessage(id=keyset_id, amount=amount, B_=B_.format().hex())
        for amount, (B_, _) in zip(amounts, blinded)
    ]
    return outputs, secrets, [r for _, r in blinded]


def _unblind(
    ledger: Ledger,
    outputs: list[BlindedMessage],
    signatures: list[BlindedSignature],
    secrets: list[str],
    rs: list[PrivateKey],
) -> list[Proof]:
    proofs = []
    for output, signature, secret, r in zip(outputs, signatures, secrets, rs):
        assert signature.id == output.id
        keyset = ledger.keysets[signature.id]
        assert keyset.public_keys
        A = keyset.public_keys[signature.amount]
        C_ = PublicKey(bytes.fromhex(signature.C_))
        assert signature.dleq
        assert b_dhke.alice_verify_dleq(
            PublicKey(bytes.fromhex(output.B_)),
            C_,
            PrivateKey(bytes.fromhex(signature.dleq.e)),
            PrivateKey(bytes.fromhex(signature.dleq.s)),
            A,
        )
        proof = Proof(
            id=signature.id,
            amount=signature.amount,
            secret=secret,
            C=b_dhke.step3_alice(C_, r, A).format().hex(),
        )
        assert ledger._verify_proof_bdhke(proof)
        proofs.append(proof)
    assert len(proofs) == len(signatures)
    return proofs


async def _issue_proofs(ledger: Ledger) -> list[Proof]:
    quote = await ledger.mint_quote(PostMintQuoteRequest(unit="sat", amount=128))
    outputs, secrets, rs = _outputs(ledger.keyset.id, [128], "funding")
    signatures = await ledger.mint(outputs=outputs, quote_id=quote.quote)
    return _unblind(ledger, outputs, signatures, secrets, rs)


async def _request(ledger: Ledger, operation: str):
    if operation == "mint":
        return await ledger.mint_quote(PostMintQuoteRequest(unit="sat", amount=128))
    if operation == "melt":
        return await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=get_fake_invoice(64))
        )
    return None


async def _transact(ledger, operation, proofs, outputs, quote):
    if operation == "mint":
        return await ledger.mint(outputs=outputs, quote_id=quote.quote)
    if operation == "swap":
        return await ledger.swap(proofs=proofs, outputs=outputs)
    response = await ledger.melt(proofs=proofs, quote=quote.quote, outputs=outputs)
    assert response.state == MeltQuoteState.paid.value
    assert response.change
    return response.change


@pytest.mark.parametrize("operation", ["mint", "swap", "melt"])
async def test_new_requests_reject_inactive_outputs(
    ledger: Ledger, monkeypatch, operation
):
    proofs = await _issue_proofs(ledger)
    old_keyset = ledger.keyset
    quote = await _request(ledger, operation)
    amounts = [0] * 7 if operation == "melt" else [128]
    outputs, _, _ = _outputs(old_keyset.id, amounts, "rejected")
    pay_invoice = AsyncMock()
    monkeypatch.setattr(
        ledger.backends[Method.bolt11][Unit.sat], "pay_invoice", pay_invoice
    )
    new_keyset = await ledger.rotate_next_keyset(Unit.sat)

    with pytest.raises(KeysetInactiveError):
        await _transact(ledger, operation, proofs, outputs, quote)

    pay_invoice.assert_not_awaited()
    assert not old_keyset.active
    assert new_keyset.active
    assert await ledger._check_outputs_pending_or_issued_before(outputs) == []
    states = await ledger.db_read.get_proofs_states([proof.Y for proof in proofs])
    assert all(state.unspent for state in states)
    balance, _ = await ledger.crud.get_balance(db=ledger.db, keyset=old_keyset)
    assert balance.amount == 128
    if operation == "mint":
        assert (await ledger.get_mint_quote(quote.quote)).state == MintQuoteState.paid
    elif operation == "melt":
        assert (await ledger.get_melt_quote(quote.quote)).state == MeltQuoteState.unpaid


@pytest.mark.parametrize("operation", ["mint", "swap", "melt"])
async def test_transactions_honor_outputs_rotated_after_verification(
    ledger: Ledger, monkeypatch, operation
):
    proofs = await _issue_proofs(ledger)
    old_keyset = ledger.keyset
    quote = await _request(ledger, operation)
    amounts = [0] * 7 if operation == "melt" else [128]
    outputs, secrets, rs = _outputs(old_keyset.id, amounts, "accepted")
    verify_outputs = ledger._verify_outputs

    async def verify_then_rotate(*args, **kwargs):
        await verify_outputs(*args, **kwargs)
        await ledger.rotate_next_keyset(Unit.sat)

    monkeypatch.setattr(ledger, "_verify_outputs", verify_then_rotate)
    monkeypatch.setattr(
        ledger.backends[Method.bolt11][Unit.sat],
        "pay_invoice",
        AsyncMock(
            return_value=PaymentResponse(
                result=PaymentResult.SETTLED, fee=Amount(Unit.sat, 1), preimage="0" * 64
            )
        ),
    )

    signatures = await _transact(ledger, operation, proofs, outputs, quote)

    assert not old_keyset.active
    expected_amounts = [32, 16, 8, 4, 2, 1] if operation == "melt" else [128]
    assert [signature.amount for signature in signatures] == expected_amounts
    _unblind(ledger, outputs, signatures, secrets, rs)
    restored_outputs, restored = await ledger.restore(outputs)
    assert [output.B_ for output in restored_outputs] == [
        output.B_ for output in outputs[: len(signatures)]
    ]
    assert restored == signatures
    balance, _ = await ledger.crud.get_balance(db=ledger.db, keyset=old_keyset)
    assert balance.amount == {"mint": 256, "swap": 128, "melt": 63}[operation]
    if operation == "mint":
        assert (await ledger.get_mint_quote(quote.quote)).state == MintQuoteState.issued
    else:
        states = await ledger.db_read.get_proofs_states([proof.Y for proof in proofs])
        assert all(state.spent for state in states)


@pytest.mark.parametrize("settlement", ["immediate", "quote_check", "startup"])
async def test_melt_honors_change_rotated_during_payment(
    ledger: Ledger, monkeypatch, settlement
):
    proofs = await _issue_proofs(ledger)
    old_keyset = ledger.keyset
    quote = await _request(ledger, "melt")
    outputs, secrets, rs = _outputs(old_keyset.id, [0] * 7, "change")
    backend = ledger.backends[Method.bolt11][Unit.sat]

    async def pay_and_rotate(melt_quote, fee_limit_msat):
        stored = await ledger.crud.get_blinded_messages_melt_id(
            db=ledger.db, melt_id=quote.quote
        )
        assert [output.B_ for output in stored] == [output.B_ for output in outputs]
        states = await ledger.db_read.get_proofs_states([proof.Y for proof in proofs])
        assert all(state.pending for state in states)
        assert old_keyset.active
        await ledger.rotate_next_keyset(Unit.sat)
        return PaymentResponse(
            result=(
                PaymentResult.SETTLED
                if settlement == "immediate"
                else PaymentResult.PENDING
            ),
            checking_id=melt_quote.checking_id,
            fee=Amount(Unit.sat, 1),
            preimage="0" * 64,
        )

    pay_invoice = AsyncMock(side_effect=pay_and_rotate)
    monkeypatch.setattr(backend, "pay_invoice", pay_invoice)
    monkeypatch.setattr(
        backend,
        "get_payment_status",
        AsyncMock(return_value=PaymentStatus(result=PaymentStatusResult.PENDING)),
    )
    response = await ledger.melt(proofs=proofs, quote=quote.quote, outputs=outputs)
    assert not old_keyset.active
    if settlement != "immediate":
        assert response.state == MeltQuoteState.pending.value
        assert not response.change
        pending = await ledger.get_melt_quote(quote.quote)
        assert pending.pending
        assert not pending.change
        monkeypatch.setattr(
            backend,
            "get_payment_status",
            AsyncMock(
                return_value=PaymentStatus(
                    result=PaymentStatusResult.SETTLED,
                    fee=Amount(Unit.sat, 1),
                    preimage="0" * 64,
                )
            ),
        )

    if settlement == "startup":
        ledger = Ledger(
            db=ledger.db,
            seed=ledger.seed,
            derivation_path=ledger.derivation_path,
            backends=ledger.backends,
            crud=ledger.crud,
        )
        await ledger._startup_keysets()
        assert not ledger.keysets[old_keyset.id].active
        await ledger._check_pending_proofs_and_melt_quotes()

    paid = await ledger.get_melt_quote(quote.quote)
    assert paid.paid
    assert paid.fee_paid == 1
    assert paid.payment_preimage == "0" * 64
    assert paid.change
    assert [signature.amount for signature in paid.change] == [32, 16, 8, 4, 2, 1]
    if settlement == "immediate":
        assert response.state == MeltQuoteState.paid.value
        assert response.change == paid.change
    change_proofs = _unblind(ledger, outputs, paid.change, secrets, rs)
    restored_outputs, restored = await ledger.restore(outputs)
    assert [output.B_ for output in restored_outputs] == [
        output.B_ for output in outputs[:6]
    ]
    assert restored == paid.change
    assert (await ledger.get_melt_quote(quote.quote)).change == paid.change
    assert (
        await ledger.crud.get_blinded_messages_melt_id(
            db=ledger.db, melt_id=quote.quote
        )
        == []
    )
    assert (
        await ledger.crud.get_pending_proofs_for_quote(
            db=ledger.db, quote_id=quote.quote
        )
        == []
    )
    states = await ledger.db_read.get_proofs_states([proof.Y for proof in proofs])
    assert all(state.spent for state in states)
    balance, _ = await ledger.crud.get_balance(db=ledger.db, keyset=old_keyset)
    assert balance.amount == 63
    pay_invoice.assert_awaited_once()

    # Change signed by the retired keyset remains spendable into the active one.
    new_keyset = next(
        keyset
        for keyset in ledger.keysets.values()
        if keyset.active and keyset.unit == Unit.sat
    )
    new_outputs, _, _ = _outputs(new_keyset.id, [32, 16, 8, 4, 2, 1], "redeem-change")
    signatures = await ledger.swap(proofs=change_proofs, outputs=new_outputs)
    assert sum(signature.amount for signature in signatures) == 63
    assert all(signature.id == new_keyset.id for signature in signatures)
    balance, _ = await ledger.crud.get_balance(db=ledger.db, keyset=old_keyset)
    assert balance.amount == 0
