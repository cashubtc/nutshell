"""Tests for `cashu.mint.verification.LedgerVerification`."""

import secrets
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cashu.core.base import (
    BlindedMessage,
    Method,
    MintQuote,
    MintQuoteState,
    P2PKWitness,
    Proof,
    Unit,
)
from cashu.core.crypto.b_dhke import step1_alice
from cashu.core.errors import (
    InvalidProofsError,
    NoSecretInProofsError,
    NotAllowedError,
    OutputsAlreadySignedError,
    OutputsArePendingError,
    ProofsAlreadySpentError,
    SecretTooLongError,
    TransactionDuplicateInputsError,
    TransactionDuplicateOutputsError,
    TransactionError,
    TransactionMultipleUnitsError,
    TransactionUnitError,
    TransactionUnitMismatchError,
    WitnessTooLongError,
)
from cashu.core.nuts import nut20
from cashu.core.p2pk import SigFlags, schnorr_sign
from cashu.core.secret import Secret, SecretKind, Tags
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from tests.helpers import assert_err


def _blinded_output(
    ledger: Ledger, *, amount: int = 8, label: str = "out"
) -> BlindedMessage:
    B_, _ = step1_alice(label)
    return BlindedMessage(
        amount=amount,
        B_=B_.format().hex(),
        id=ledger.keyset.id,
    )


def _mint_quote_no_pubkey() -> MintQuote:
    return MintQuote(
        quote="quote-id-nut20",
        method="bolt11",
        request="lnbc1fake",
        checking_id="chk1",
        unit="sat",
        amount=8,
        state=MintQuoteState.paid,
        pubkey=None,
    )


def _mint_quote_with_pubkey(pubkey: str) -> MintQuote:
    return MintQuote(
        quote="quote-id-nut20-signed",
        method="bolt11",
        request="lnbc1fake2",
        checking_id="chk2",
        unit="sat",
        amount=8,
        state=MintQuoteState.paid,
        pubkey=pubkey,
    )


# ---------------------------------------------------------------------------
# _verify_secret_criteria
# ---------------------------------------------------------------------------


def test_verify_secret_criteria_accepts_present_secret(ledger: Ledger):
    p = Proof(id=ledger.keyset.id, amount=8, secret="hello", C="02" + "ab" * 32)
    assert ledger._verify_secret_criteria(p) is True


def test_verify_secret_criteria_rejects_empty_secret(ledger: Ledger):
    p = Proof(id=ledger.keyset.id, amount=8, secret="", C="02" + "ab" * 32)
    with pytest.raises(NoSecretInProofsError):
        ledger._verify_secret_criteria(p)


def test_verify_secret_criteria_rejects_too_long_secret(ledger: Ledger):
    p = Proof(
        id=ledger.keyset.id,
        amount=8,
        secret="x" * (settings.mint_max_secret_length + 1),
        C="02" + "ab" * 32,
    )
    with pytest.raises(SecretTooLongError):
        ledger._verify_secret_criteria(p)


# ---------------------------------------------------------------------------
# _verify_input_witness_criteria
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_witness_too_long(ledger: Ledger):
    proof = Proof.from_dict(
        {
            "amount": 8,
            "secret": "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
            "C": "02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904",
            "id": "009a1f293253e41e",
            "witness": secrets.token_hex(5000),
        }
    )

    await assert_err(
        ledger.verify_inputs_and_outputs(proofs=[proof], outputs=[]),
        WitnessTooLongError(),
    )


def test_verify_input_witness_criteria_accepts_short_witness(ledger: Ledger):
    p = Proof(
        id=ledger.keyset.id,
        amount=8,
        secret="s",
        C="02" + "ab" * 32,
        witness='{"signatures":[]}',
    )
    assert ledger._verify_input_witness_criteria(p) is True


def test_verify_input_witness_criteria_rejects_long_witness(ledger: Ledger):
    p = Proof(
        id=ledger.keyset.id,
        amount=8,
        secret="s",
        C="02" + "ab" * 32,
        witness="w" * (settings.mint_max_witness_length + 1),
    )
    with pytest.raises(WitnessTooLongError):
        ledger._verify_input_witness_criteria(p)


# ---------------------------------------------------------------------------
# _verify_amount
# ---------------------------------------------------------------------------


def test_verify_amount_accepts_valid(ledger: Ledger):
    assert ledger._verify_amount(8) == 8


def test_verify_amount_rejects_zero(ledger: Ledger):
    with pytest.raises(NotAllowedError, match="invalid amount"):
        ledger._verify_amount(0)


def test_verify_amount_rejects_negative(ledger: Ledger):
    with pytest.raises(NotAllowedError, match="invalid amount"):
        ledger._verify_amount(-1)


def test_verify_amount_rejects_too_large(ledger: Ledger):
    with pytest.raises(NotAllowedError, match="invalid amount"):
        ledger._verify_amount(2**settings.max_order)


# ---------------------------------------------------------------------------
# Duplicates and amounts (inputs vs outputs)
# ---------------------------------------------------------------------------


def test_verify_no_duplicate_proofs(ledger: Ledger):
    a = Proof(id=ledger.keyset.id, amount=1, secret="a", C="02" + "aa" * 32)
    b = Proof(id=ledger.keyset.id, amount=1, secret="b", C="02" + "bb" * 32)
    assert ledger._verify_no_duplicate_proofs([a, b]) is True
    assert ledger._verify_no_duplicate_proofs([a, a.model_copy()]) is False


def test_verify_no_duplicate_outputs(ledger: Ledger):
    o1 = _blinded_output(ledger, label="o1")
    o2 = _blinded_output(ledger, label="o2")
    assert ledger._verify_no_duplicate_outputs([o1, o2]) is True
    dup = BlindedMessage(amount=o1.amount, B_=o1.B_, id=o1.id)
    assert ledger._verify_no_duplicate_outputs([o1, dup]) is False


def test_verify_input_output_amounts_rejects_outputs_exceed_inputs(ledger: Ledger):
    p = Proof(id=ledger.keyset.id, amount=4, secret="s", C="02" + "cc" * 32)
    outs = [_blinded_output(ledger, amount=8, label="big")]
    with pytest.raises(TransactionError, match="less than output amounts"):
        ledger._verify_input_output_amounts([p], outs)


def test_verify_input_output_amounts_accepts_equal_or_greater(ledger: Ledger):
    p = Proof(id=ledger.keyset.id, amount=16, secret="s", C="02" + "dd" * 32)
    outs = [_blinded_output(ledger, amount=8, label="half")]
    ledger._verify_input_output_amounts([p], outs)


# ---------------------------------------------------------------------------
# _verify_units_match and _verify_inputs_outputs_units_match
# ---------------------------------------------------------------------------


def test_verify_units_match_accepts_same_unit(ledger: Ledger):
    kid = ledger.keyset.id
    p = Proof(id=kid, amount=8, secret="s", C="02" + "ee" * 32)
    o = _blinded_output(ledger, label="u")
    assert ledger._verify_units_match([p], [o]) == ledger.keysets[kid].unit


def test_verify_units_match_rejects_mismatched_units(ledger: Ledger):
    orig = dict(ledger.keysets)
    try:
        ks_a = MagicMock(unit=Unit.sat)
        ks_b = MagicMock(unit=Unit.usd)
        ledger.keysets = {"ka": ks_a, "kb": ks_b}
        pa = Proof(id="ka", amount=8, secret="s", C="02" + "ff" * 32)
        ob = BlindedMessage(amount=8, B_="02" + "11" * 32, id="kb")
        with pytest.raises(TransactionUnitMismatchError):
            ledger._verify_units_match([pa], [ob])
    finally:
        ledger.keysets = orig


def test_verify_inputs_outputs_units_match(ledger: Ledger):
    kid = ledger.keyset.id
    proofs = [
        Proof(id=kid, amount=8, secret="a", C="02" + "12" * 32),
        Proof(id=kid, amount=8, secret="b", C="02" + "13" * 32),
    ]
    outs = [_blinded_output(ledger, label="x"), _blinded_output(ledger, label="y")]
    assert ledger._verify_inputs_outputs_units_match(proofs, outs) is True


def test_verify_inputs_outputs_units_match_rejects_multi_unit_inputs(ledger: Ledger):
    orig = dict(ledger.keysets)
    try:
        ks_a = MagicMock(unit=Unit.sat)
        ks_b = MagicMock(unit=Unit.usd)
        ledger.keysets = {"ka": ks_a, "kb": ks_b}
        pa = Proof(id="ka", amount=8, secret="a", C="02" + "14" * 32)
        pb = Proof(id="kb", amount=8, secret="b", C="02" + "15" * 32)
        o = BlindedMessage(amount=8, B_="02" + "16" * 32, id="ka")
        with pytest.raises(TransactionMultipleUnitsError, match="inputs"):
            ledger._verify_inputs_outputs_units_match([pa, pb], [o])
    finally:
        ledger.keysets = orig


# ---------------------------------------------------------------------------
# get_fees_for_proofs
# ---------------------------------------------------------------------------


def test_get_fees_for_proofs_single_proof(ledger: Ledger):
    p = Proof(id=ledger.keyset.id, amount=8, secret="s", C="02" + "17" * 32)
    fee = ledger.get_fees_for_proofs([p])
    assert isinstance(fee, int)
    assert fee >= 0


def test_get_fees_for_proofs_rejects_mixed_units(ledger: Ledger):
    orig = dict(ledger.keysets)
    try:
        ledger.keysets = {
            "k_sat": MagicMock(unit=Unit.sat, input_fee_ppk=100),
            "k_usd": MagicMock(unit=Unit.usd, input_fee_ppk=100),
        }
        p1 = MagicMock()
        p1.id = "k_sat"
        p2 = MagicMock()
        p2.id = "k_usd"
        with pytest.raises(TransactionUnitError, match="inputs have different units"):
            ledger.get_fees_for_proofs([p1, p2])
    finally:
        ledger.keysets = orig


# ---------------------------------------------------------------------------
# _verify_equation_balanced
# ---------------------------------------------------------------------------


def test_verify_equation_balanced_rejects_no_proofs(ledger: Ledger):
    o = _blinded_output(ledger)
    with pytest.raises(TransactionError, match="no proofs provided"):
        ledger._verify_equation_balanced([], [o])


def test_verify_equation_balanced_rejects_no_outputs(ledger: Ledger):
    p = Proof(id=ledger.keyset.id, amount=8, secret="s", C="02" + "18" * 32)
    with pytest.raises(TransactionError, match="no outputs provided"):
        ledger._verify_equation_balanced([p], [])


def test_verify_equation_balanced_accepts_balanced_with_fees(ledger: Ledger):
    kid = ledger.keyset.id
    proofs = [
        Proof(id=kid, amount=8, secret="a", C="02" + "19" * 32),
        Proof(id=kid, amount=8, secret="b", C="02" + "1a" * 32),
    ]
    fee = ledger.get_fees_for_proofs(proofs)
    total_in = sum(p.amount for p in proofs)
    out_amt = total_in - fee
    o1 = _blinded_output(ledger, amount=out_amt, label="bal1")
    ledger._verify_equation_balanced(proofs, [o1])


def test_verify_equation_balanced_rejects_unbalanced(ledger: Ledger):
    kid = ledger.keyset.id
    proofs = [Proof(id=kid, amount=8, secret="a", C="02" + "1b" * 32)]
    outs = [_blinded_output(ledger, amount=1, label="tiny")]
    with pytest.raises(TransactionError, match="not balanced"):
        ledger._verify_equation_balanced(proofs, outs)


# ---------------------------------------------------------------------------
# _verify_and_get_unit_method
# ---------------------------------------------------------------------------


def test_verify_and_get_unit_method_accepts_bolt11_sat(ledger: Ledger):
    u, m = ledger._verify_and_get_unit_method("sat", "bolt11")
    assert u == Unit.sat
    assert m == Method.bolt11


def test_verify_and_get_unit_method_rejects_unknown_unit(ledger: Ledger):
    with pytest.raises(NotAllowedError, match="not supported in any keyset"):
        ledger._verify_and_get_unit_method("auth", "bolt11")


def test_verify_and_get_unit_method_rejects_unsupported_backend(ledger: Ledger):
    orig = ledger.backends
    try:
        ledger.backends = {Method.bolt11: {}}
        with pytest.raises(NotAllowedError, match="no support for method"):
            ledger._verify_and_get_unit_method("sat", "bolt11")
    finally:
        ledger.backends = orig


# ---------------------------------------------------------------------------
# _verify_mint_quote_witness
# ---------------------------------------------------------------------------


def test_verify_mint_quote_witness_skips_when_no_pubkey(ledger: Ledger):
    quote = _mint_quote_no_pubkey()
    outs = [_blinded_output(ledger, label="nut20")]
    assert ledger._verify_mint_quote_witness(quote, outs, signature=None) is True


def test_verify_mint_quote_witness_requires_signature_when_pubkey_set(ledger: Ledger):
    priv, pub = nut20.generate_keypair()
    quote = _mint_quote_with_pubkey(pub)
    outs = [_blinded_output(ledger, label="nut20b")]
    assert ledger._verify_mint_quote_witness(quote, outs, signature=None) is False
    sig = nut20.sign_mint_quote(quote.quote, outs, priv)
    assert ledger._verify_mint_quote_witness(quote, outs, signature=sig) is True


def test_verify_mint_quote_witness_rejects_bad_signature(ledger: Ledger):
    priv, pub = nut20.generate_keypair()
    quote = _mint_quote_with_pubkey(pub)
    outs = [_blinded_output(ledger, label="nut20c")]
    wrong_sig = nut20.sign_mint_quote("other-quote", outs, priv)
    assert ledger._verify_mint_quote_witness(quote, outs, signature=wrong_sig) is False


# ---------------------------------------------------------------------------
# _verify_proof_bdhke
# ---------------------------------------------------------------------------


def test_verify_proof_bdhke_rejects_invalid_token(ledger: Ledger):
    kid = ledger.keyset.id
    p = Proof(
        id=kid,
        amount=8,
        secret="66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
        C="02" + "de" * 32,
    )
    assert ledger._verify_proof_bdhke(p) is False


def test_verify_proof_bdhke_asserts_unknown_keyset(ledger: Ledger):
    p = Proof(
        id="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        amount=8,
        secret="s",
        C="02" + "ef" * 32,
    )
    with pytest.raises(AssertionError, match="keyset"):
        ledger._verify_proof_bdhke(p)


# ---------------------------------------------------------------------------
# _verify_inputs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_inputs_rejects_empty_list(ledger: Ledger):
    with pytest.raises(TransactionError, match="no proofs provided"):
        await ledger._verify_inputs([])


@pytest.mark.asyncio
async def test_verify_inputs_rejects_duplicate_secrets(ledger: Ledger):
    kid = ledger.keyset.id
    p = Proof(id=kid, amount=8, secret="same", C="02" + "1c" * 32)
    with (
        patch.object(ledger, "_verify_proof_bdhke", return_value=True),
        patch.object(
            ledger.db_read,
            "_verify_proofs_spendable",
            AsyncMock(return_value=True),
        ),
        patch.object(ledger, "_verify_input_spending_conditions", return_value=True),
    ):
        with pytest.raises(TransactionDuplicateInputsError):
            await ledger._verify_inputs([p, p.model_copy()])


@pytest.mark.asyncio
async def test_verify_inputs_rejects_invalid_bdhke(ledger: Ledger):
    kid = ledger.keyset.id
    p = Proof(id=kid, amount=8, secret="s", C="02" + "1d" * 32)
    with patch.object(
        ledger.db_read,
        "_verify_proofs_spendable",
        AsyncMock(return_value=True),
    ):
        with pytest.raises(InvalidProofsError):
            await ledger._verify_inputs([p])


# ---------------------------------------------------------------------------
# _verify_outputs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_outputs_rejects_empty(ledger: Ledger):
    with pytest.raises(TransactionError, match="no outputs provided"):
        await ledger._verify_outputs([])


@pytest.mark.asyncio
async def test_verify_outputs_rejects_mixed_keyset_ids(ledger: Ledger):
    o1 = _blinded_output(ledger, label="m1")
    o2 = _blinded_output(ledger, label="m2")
    o2 = o2.model_copy(
        update={
            "id": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        }
    )
    with pytest.raises(TransactionError, match="different keyset ids"):
        await ledger._verify_outputs([o1, o2])


@pytest.mark.asyncio
async def test_verify_outputs_rejects_unknown_keyset(ledger: Ledger):
    o = _blinded_output(ledger, label="uk")
    o = o.model_copy(
        update={
            "id": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        }
    )
    with pytest.raises(TransactionError, match="keyset id unknown"):
        await ledger._verify_outputs([o])


@pytest.mark.asyncio
async def test_verify_outputs_rejects_inactive_keyset(ledger: Ledger):
    o = _blinded_output(ledger, label="inact")
    ks = ledger.keysets[ledger.keyset.id]
    prev = ks.active
    try:
        ks.active = False
        with pytest.raises(TransactionError, match="keyset id inactive"):
            await ledger._verify_outputs([o])
    finally:
        ks.active = prev


@pytest.mark.asyncio
async def test_verify_outputs_rejects_duplicate_blinds(ledger: Ledger):
    o = _blinded_output(ledger, label="dupb")
    with pytest.raises(TransactionDuplicateOutputsError):
        await ledger._verify_outputs([o, o.model_copy()])


@pytest.mark.asyncio
async def test_verify_outputs_rejects_pending_stored_outputs(ledger: Ledger):
    o = _blinded_output(ledger, label="pend")
    pending = [o.model_copy(update={"C_": None})]

    async def fake_check(outputs, conn=None):
        return pending

    with patch.object(ledger, "_check_outputs_pending_or_issued_before", fake_check):
        with pytest.raises(OutputsArePendingError):
            await ledger._verify_outputs([o])


@pytest.mark.asyncio
async def test_verify_outputs_rejects_already_signed(ledger: Ledger):
    o = _blinded_output(ledger, label="sgn")
    signed = [o.model_copy(update={"C_": "03" + "ab" * 32})]

    async def fake_check(outputs, conn=None):
        return signed

    with patch.object(ledger, "_check_outputs_pending_or_issued_before", fake_check):
        with pytest.raises(OutputsAlreadySignedError):
            await ledger._verify_outputs([o])


@pytest.mark.asyncio
async def test_verify_outputs_accepts_fresh_outputs(ledger: Ledger):
    o = _blinded_output(ledger, label="fresh")
    await ledger._verify_outputs([o])


@pytest.mark.asyncio
async def test_verify_outputs_skip_amount_check_allows_zero(ledger: Ledger):
    o = _blinded_output(ledger, amount=0, label="nut8")
    await ledger._verify_outputs([o], skip_amount_check=True)


# ---------------------------------------------------------------------------
# _check_outputs_pending_or_issued_before
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_outputs_pending_or_issued_before_returns_empty_for_unknown_b(
    ledger: Ledger,
):
    o = _blinded_output(ledger, label="never_stored")
    result = await ledger._check_outputs_pending_or_issued_before([o])
    assert result == []


# ---------------------------------------------------------------------------
# _verify_inputs_and_outputs_together
# ---------------------------------------------------------------------------


def test_verify_inputs_and_outputs_together_runs_balance_and_spending(ledger: Ledger):
    kid = ledger.keyset.id
    proofs = [
        Proof(id=kid, amount=8, secret="a", C="02" + "1e" * 32),
        Proof(id=kid, amount=8, secret="b", C="02" + "1f" * 32),
    ]
    fee = ledger.get_fees_for_proofs(proofs)
    out_amt = sum(p.amount for p in proofs) - fee
    outs = [_blinded_output(ledger, amount=out_amt, label="tog")]
    with patch.object(
        ledger, "_verify_input_output_spending_conditions", return_value=True
    ):
        ledger._verify_inputs_and_outputs_together(proofs, outs)


# ---------------------------------------------------------------------------
# verify_inputs_and_outputs (integration)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_inputs_and_outputs_outputs_none_skips_output_pipeline(
    ledger: Ledger,
):
    with (
        patch.object(ledger, "_verify_inputs", AsyncMock(return_value=None)),
        patch.object(ledger, "_verify_outputs", new_callable=AsyncMock) as vo,
        patch.object(ledger, "_verify_inputs_and_outputs_together") as together,
    ):
        await ledger.verify_inputs_and_outputs(
            proofs=[MagicMock(spec=Proof)], outputs=None
        )
    vo.assert_not_called()
    together.assert_not_called()


@pytest.mark.asyncio
async def test_verify_inputs_and_outputs_with_outputs_calls_together(ledger: Ledger):
    outs = [_blinded_output(ledger, label="pipe")]
    with (
        patch.object(ledger, "_verify_inputs", AsyncMock(return_value=None)),
        patch.object(ledger, "_verify_inputs_and_outputs_together") as together,
    ):
        await ledger.verify_inputs_and_outputs(
            proofs=[MagicMock(spec=Proof)], outputs=outs
        )
    together.assert_called_once()


@pytest.mark.asyncio
async def test_verify_inputs_and_outputs_empty_outputs_list_fails_after_inputs(
    ledger: Ledger,
):
    with patch.object(ledger, "_verify_inputs", AsyncMock(return_value=None)):
        await assert_err(
            ledger.verify_inputs_and_outputs(
                proofs=[MagicMock(spec=Proof)], outputs=[]
            ),
            TransactionError(),
        )


@pytest.mark.asyncio
async def test_verify_inputs_and_outputs_happy_path_outputs_only_phase(ledger: Ledger):
    """Inputs mocked; real output verification for never-seen blinds."""
    outs = [_blinded_output(ledger, label="happy")]
    with (
        patch.object(ledger, "_verify_inputs", AsyncMock(return_value=None)),
        patch.object(ledger, "_verify_inputs_and_outputs_together", return_value=None),
    ):
        await ledger.verify_inputs_and_outputs(
            proofs=[MagicMock(spec=Proof)], outputs=outs
        )


# ---------------------------------------------------------------------------
# Spending conditions (ledger helper used by verification)
# ---------------------------------------------------------------------------


def test_witness_without_spending_condition(ledger: Ledger):
    proof = Proof.from_dict(
        {
            "amount": 8,
            "secret": "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
            "C": "02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904",
            "id": "009a1f293253e41e",
            "witness": secrets.token_hex(50),
        }
    )

    with pytest.raises(TransactionError, match="witness data not allowed"):
        ledger._verify_input_spending_conditions(proof)


# =============================================================================
# Exhaustive paths: _verify_inputs, _verify_outputs, _verify_inputs_and_outputs_
# together, verify_inputs_and_outputs
# =============================================================================


def _proof_plain(
    ledger: Ledger, *, amount: int = 8, secret: str = "plain-secret-ok"
) -> Proof:
    return Proof(
        id=ledger.keyset.id,
        amount=amount,
        secret=secret,
        C="02" + secrets.token_hex(32),
        witness=None,
    )


def _p2pk_sig_all_secret(pub_hex: str) -> str:
    return Secret(
        kind=SecretKind.P2PK.value,
        data=pub_hex,
        tags=Tags(tags=[["sigflag", SigFlags.SIG_ALL.value]]),
        nonce="0" * 32,
    ).serialize()


def _keysets_by_unit(ledger: Ledger) -> tuple[str | None, str | None]:
    """Return (sat_keyset_id, usd_keyset_id) if both exist."""
    sat_id = next((k for k, ks in ledger.keysets.items() if ks.unit == Unit.sat), None)
    usd_id = next((k for k, ks in ledger.keysets.items() if ks.unit == Unit.usd), None)
    return sat_id, usd_id


# --- _verify_inputs: every failure path (order matches verification.py) ---


@pytest.mark.asyncio
async def test_verify_inputs_invalid_amount_raises_not_allowed_not_transaction_error(
    ledger: Ledger,
):
    """`_verify_amount` raises before `all(...)` completes; 'invalid amount' TX is unreachable."""
    p = _proof_plain(ledger, amount=0)
    with pytest.raises(NotAllowedError, match="invalid amount"):
        await ledger._verify_inputs([p])


@pytest.mark.asyncio
async def test_verify_inputs_empty_secret_raises_no_secret(ledger: Ledger):
    p = _proof_plain(ledger, secret="")
    with pytest.raises(NoSecretInProofsError):
        await ledger._verify_inputs([p])


@pytest.mark.asyncio
async def test_verify_inputs_secret_too_long_raises(ledger: Ledger):
    p = _proof_plain(ledger, secret="z" * (settings.mint_max_secret_length + 1))
    with pytest.raises(SecretTooLongError):
        await ledger._verify_inputs([p])


@pytest.mark.asyncio
async def test_verify_inputs_witness_too_long_raises(ledger: Ledger):
    p = _proof_plain(ledger)
    p.witness = "w" * (settings.mint_max_witness_length + 1)
    with pytest.raises(WitnessTooLongError):
        await ledger._verify_inputs([p])


@pytest.mark.asyncio
async def test_verify_inputs_witness_on_plain_secret_raises(ledger: Ledger):
    p = _proof_plain(ledger, secret="not-a-cbor-secret")
    p.witness = "{}"
    with (
        patch.object(ledger, "_verify_proof_bdhke", return_value=True),
        patch.object(
            ledger.db_read,
            "_verify_proofs_spendable",
            AsyncMock(return_value=True),
        ),
    ):
        with pytest.raises(TransactionError, match="witness data not allowed"):
            await ledger._verify_inputs([p])


@pytest.mark.asyncio
async def test_verify_inputs_spending_false_raises_validation_failed(ledger: Ledger):
    p = _proof_plain(ledger)
    with (
        patch.object(ledger, "_verify_proof_bdhke", return_value=True),
        patch.object(
            ledger.db_read,
            "_verify_proofs_spendable",
            AsyncMock(return_value=True),
        ),
        patch.object(ledger, "_verify_input_spending_conditions", return_value=False),
    ):
        with pytest.raises(
            TransactionError, match="validation of input spending conditions failed"
        ):
            await ledger._verify_inputs([p])


@pytest.mark.asyncio
async def test_verify_inputs_spending_raises_propagates(ledger: Ledger):
    p = _proof_plain(ledger)
    with (
        patch.object(ledger, "_verify_proof_bdhke", return_value=True),
        patch.object(
            ledger.db_read,
            "_verify_proofs_spendable",
            AsyncMock(return_value=True),
        ),
        patch.object(
            ledger,
            "_verify_input_spending_conditions",
            side_effect=TransactionError("p2pk failed"),
        ),
    ):
        with pytest.raises(TransactionError, match="p2pk failed"):
            await ledger._verify_inputs([p])


@pytest.mark.asyncio
async def test_verify_inputs_not_spendable_raises_proofs_already_spent(ledger: Ledger):
    p = _proof_plain(ledger)
    with (
        patch.object(ledger, "_verify_proof_bdhke", return_value=True),
        patch.object(ledger, "_verify_input_spending_conditions", return_value=True),
        patch.object(
            ledger.db_read,
            "_verify_proofs_spendable",
            AsyncMock(side_effect=ProofsAlreadySpentError()),
        ),
    ):
        with pytest.raises(ProofsAlreadySpentError):
            await ledger._verify_inputs([p])


@pytest.mark.asyncio
async def test_verify_inputs_success_with_mocks(ledger: Ledger):
    p = _proof_plain(ledger)
    with (
        patch.object(ledger, "_verify_proof_bdhke", return_value=True),
        patch.object(ledger, "_verify_input_spending_conditions", return_value=True),
        patch.object(
            ledger.db_read,
            "_verify_proofs_spendable",
            AsyncMock(return_value=True),
        ),
    ):
        await ledger._verify_inputs([p])


@pytest.mark.asyncio
async def test_verify_inputs_second_proof_fails_amount_stops_pipeline(ledger: Ledger):
    ok = _proof_plain(ledger, secret="a")
    bad = _proof_plain(ledger, amount=0, secret="b")
    with pytest.raises(NotAllowedError):
        await ledger._verify_inputs([ok, bad])


# --- _verify_outputs: remaining branches ---


@pytest.mark.asyncio
async def test_verify_outputs_invalid_amount_zero_without_skip(ledger: Ledger):
    o = _blinded_output(ledger, amount=0, label="zero-amt")
    with pytest.raises(NotAllowedError, match="invalid amount"):
        await ledger._verify_outputs([o], skip_amount_check=False)


@pytest.mark.asyncio
async def test_verify_outputs_second_output_invalid_amount(ledger: Ledger):
    o1 = _blinded_output(ledger, amount=8, label="ok1")
    o2 = _blinded_output(ledger, amount=0, label="bad2")
    with pytest.raises(NotAllowedError, match="invalid amount"):
        await ledger._verify_outputs([o1, o2], skip_amount_check=False)


@pytest.mark.asyncio
async def test_verify_outputs_stored_before_signed_branch_any_c_(ledger: Ledger):
    """`OutputsAlreadySignedError` when any returned row has truthy C_."""
    o = _blinded_output(ledger, label="signed-branch")

    async def fake_check(outputs, conn=None):
        return [
            o.model_copy(update={"C_": "03" + "cd" * 32}),
            o.model_copy(update={"C_": None}),
        ]

    with patch.object(ledger, "_check_outputs_pending_or_issued_before", fake_check):
        with pytest.raises(OutputsAlreadySignedError):
            await ledger._verify_outputs([o])


@pytest.mark.asyncio
async def test_verify_outputs_stored_before_pending_when_no_signed_in_list(
    ledger: Ledger,
):
    o = _blinded_output(ledger, label="pending-branch")

    async def fake_check(outputs, conn=None):
        return [
            o.model_copy(update={"C_": None}),
            o.model_copy(update={"C_": None}),
        ]

    with patch.object(ledger, "_check_outputs_pending_or_issued_before", fake_check):
        with pytest.raises(OutputsArePendingError):
            await ledger._verify_outputs([o])


@pytest.mark.asyncio
async def test_verify_outputs_multiple_fresh_outputs(ledger: Ledger):
    await ledger._verify_outputs(
        [
            _blinded_output(ledger, label="m1"),
            _blinded_output(ledger, label="m2"),
        ]
    )


# --- _verify_inputs_and_outputs_together: all failure/success paths ---


def test_together_input_amounts_equal_outputs_ok_until_equation(ledger: Ledger):
    proofs = [_proof_plain(ledger, secret="a"), _proof_plain(ledger, secret="b")]
    fee = ledger.get_fees_for_proofs(proofs)
    outs = [
        _blinded_output(ledger, amount=sum(p.amount for p in proofs) - fee, label="eq")
    ]
    with patch.object(
        ledger, "_verify_input_output_spending_conditions", return_value=True
    ):
        ledger._verify_inputs_and_outputs_together(proofs, outs)


def test_together_fails_input_output_amounts_before_equation(ledger: Ledger):
    proofs = [_proof_plain(ledger, amount=4, secret="a")]
    outs = [_blinded_output(ledger, amount=8, label="too-big")]
    with pytest.raises(TransactionError, match="less than output amounts"):
        ledger._verify_inputs_and_outputs_together(proofs, outs)


def test_together_fails_equation_unbalanced(ledger: Ledger):
    proofs = [_proof_plain(ledger, amount=8, secret="a")]
    outs = [_blinded_output(ledger, amount=1, label="unbal")]
    with patch.object(
        ledger, "_verify_input_output_spending_conditions", return_value=True
    ):
        with pytest.raises(TransactionError, match="not balanced"):
            ledger._verify_inputs_and_outputs_together(proofs, outs)


def test_together_fails_mixed_input_units_in_equation(ledger: Ledger):
    sat_id, usd_id = _keysets_by_unit(ledger)
    if sat_id is None or usd_id is None:
        pytest.skip("ledger needs both sat and usd keysets")
    # pytest.skip is not NoReturn for mypy; narrow explicitly for Proof.id: str
    assert sat_id is not None and usd_id is not None
    p1 = _proof_plain(ledger, secret="a")
    p1.id = sat_id
    p2 = _proof_plain(ledger, secret="b")
    p2.id = usd_id
    outs = [_blinded_output(ledger, label="mix-u")]
    with pytest.raises(
        TransactionMultipleUnitsError, match="inputs have different units"
    ):
        ledger._verify_inputs_and_outputs_together([p1, p2], outs)


def test_together_fails_unit_mismatch_sat_proof_usd_output(ledger: Ledger):
    sat_id, usd_id = _keysets_by_unit(ledger)
    if sat_id is None or usd_id is None:
        pytest.skip("ledger needs both sat and usd keysets")
    assert sat_id is not None and usd_id is not None

    proofs = [_proof_plain(ledger, secret="a")]
    proofs[0].id = sat_id
    outs = [_blinded_output(ledger, label="usd-out")]
    outs[0] = outs[0].model_copy(update={"id": usd_id})
    fee = ledger.get_fees_for_proofs(proofs)
    outs[0] = outs[0].model_copy(update={"amount": proofs[0].amount - fee})
    with pytest.raises(TransactionUnitMismatchError):
        ledger._verify_inputs_and_outputs_together(proofs, outs)


def test_together_fails_sig_all_secrets_not_equal(ledger: Ledger):
    kid = ledger.keyset.id
    a = PrivateKey()
    b = PrivateKey()
    sa = _p2pk_sig_all_secret(a.public_key.format().hex())
    sb = _p2pk_sig_all_secret(b.public_key.format().hex())
    p1 = Proof(
        id=kid,
        amount=8,
        secret=sa,
        C="02" + secrets.token_hex(32),
        witness=None,
    )
    p2 = Proof(
        id=kid,
        amount=8,
        secret=sb,
        C="02" + secrets.token_hex(32),
        witness=None,
    )
    fee = ledger.get_fees_for_proofs([p1, p2])
    outs = [
        _blinded_output(ledger, amount=p1.amount + p2.amount - fee, label="sigall-bad")
    ]
    with pytest.raises(TransactionError, match="not all secrets are equal"):
        ledger._verify_inputs_and_outputs_together([p1, p2], outs)


def test_together_sig_all_fails_wrong_signature(ledger: Ledger):
    kid = ledger.keyset.id
    signer = PrivateKey()
    pub = signer.public_key.format().hex()
    secret_str = _p2pk_sig_all_secret(pub)
    p = Proof(
        id=kid,
        amount=16,
        secret=secret_str,
        C="02" + secrets.token_hex(32),
        witness=None,
    )
    fee = ledger.get_fees_for_proofs([p])
    outs = [_blinded_output(ledger, amount=p.amount - fee, label="sigall-bad-sig")]
    p.witness = P2PKWitness(signatures=["00" * 64]).model_dump_json()
    with pytest.raises(TransactionError, match="signature threshold not met"):
        ledger._verify_inputs_and_outputs_together([p], outs)


def test_together_sig_all_succeeds_when_signed(ledger: Ledger):
    kid = ledger.keyset.id
    signer = PrivateKey()
    pub = signer.public_key.format().hex()
    secret_str = _p2pk_sig_all_secret(pub)
    p = Proof(
        id=kid,
        amount=16,
        secret=secret_str,
        C="02" + secrets.token_hex(32),
        witness=None,
    )
    fee = ledger.get_fees_for_proofs([p])
    outs = [_blinded_output(ledger, amount=p.amount - fee, label="sigall-ok")]
    msg = "".join([p.secret] + [o.B_ for o in outs])
    sig = schnorr_sign(msg.encode("utf-8"), signer).hex()
    p.witness = P2PKWitness(signatures=[sig]).model_dump_json()
    ledger._verify_inputs_and_outputs_together([p], outs)


# --- verify_inputs_and_outputs: orchestration & error propagation ---


@pytest.mark.asyncio
async def test_vio_duplicate_inputs_raises(ledger: Ledger):
    p = _proof_plain(ledger, secret="dup")
    with (
        patch.object(ledger, "_verify_proof_bdhke", return_value=True),
        patch.object(
            ledger.db_read,
            "_verify_proofs_spendable",
            AsyncMock(return_value=True),
        ),
        patch.object(ledger, "_verify_input_spending_conditions", return_value=True),
    ):
        with pytest.raises(TransactionDuplicateInputsError):
            await ledger.verify_inputs_and_outputs(
                proofs=[p, p.model_copy()], outputs=None
            )


@pytest.mark.asyncio
async def test_vio_empty_proofs_raises(ledger: Ledger):
    await assert_err(
        ledger.verify_inputs_and_outputs(proofs=[], outputs=None),
        TransactionError(),
    )


@pytest.mark.asyncio
async def test_vio_propagates_not_allowed_from_inputs(ledger: Ledger):
    p = _proof_plain(ledger, amount=-1)
    with pytest.raises(NotAllowedError):
        await ledger.verify_inputs_and_outputs(proofs=[p], outputs=None)


@pytest.mark.asyncio
async def test_vio_propagates_no_secret_from_inputs(ledger: Ledger):
    p = _proof_plain(ledger, secret="")
    with pytest.raises(NoSecretInProofsError):
        await ledger.verify_inputs_and_outputs(proofs=[p], outputs=None)


@pytest.mark.asyncio
async def test_vio_propagates_proofs_already_spent_from_inputs(ledger: Ledger):
    p = _proof_plain(ledger)
    with (
        patch.object(ledger, "_verify_proof_bdhke", return_value=True),
        patch.object(ledger, "_verify_input_spending_conditions", return_value=True),
        patch.object(
            ledger.db_read,
            "_verify_proofs_spendable",
            AsyncMock(side_effect=ProofsAlreadySpentError()),
        ),
    ):
        with pytest.raises(ProofsAlreadySpentError):
            await ledger.verify_inputs_and_outputs(proofs=[p], outputs=None)


@pytest.mark.asyncio
async def test_vio_outputs_none_success_with_mocked_inputs(ledger: Ledger):
    p = _proof_plain(ledger)
    with (
        patch.object(ledger, "_verify_proof_bdhke", return_value=True),
        patch.object(ledger, "_verify_input_spending_conditions", return_value=True),
        patch.object(
            ledger.db_read,
            "_verify_proofs_spendable",
            AsyncMock(return_value=True),
        ),
    ):
        await ledger.verify_inputs_and_outputs(proofs=[p], outputs=None)


@pytest.mark.asyncio
async def test_vio_forwards_conn_to_verify_outputs(ledger: Ledger):
    outs = [_blinded_output(ledger, label="conn-fwd")]
    mock_conn = MagicMock()
    captured: dict = {}

    async def vo(outputs, skip_amount_check=False, conn=None):
        captured["outputs"] = outputs
        captured["skip"] = skip_amount_check
        captured["conn"] = conn

    with (
        patch.object(ledger, "_verify_inputs", AsyncMock(return_value=None)),
        patch.object(ledger, "_verify_inputs_and_outputs_together", return_value=None),
        patch.object(ledger, "_verify_outputs", side_effect=vo),
    ):
        await ledger.verify_inputs_and_outputs(
            proofs=[MagicMock(spec=Proof)], outputs=outs, conn=mock_conn
        )
    assert captured["conn"] is mock_conn
    assert captured["outputs"] == outs
    assert captured["skip"] is False


@pytest.mark.asyncio
async def test_vio_does_not_call_together_when_outputs_fail(ledger: Ledger):
    with (
        patch.object(ledger, "_verify_inputs", AsyncMock(return_value=None)),
        patch.object(ledger, "_verify_inputs_and_outputs_together") as together,
    ):
        await assert_err(
            ledger.verify_inputs_and_outputs(
                proofs=[MagicMock(spec=Proof)], outputs=[]
            ),
            TransactionError(),
        )
    together.assert_not_called()


@pytest.mark.asyncio
async def test_vio_full_pipeline_order_outputs_then_together(ledger: Ledger):
    outs = [_blinded_output(ledger, label="order")]
    calls: list[str] = []

    async def vo(*args, **kwargs):
        calls.append("outputs")

    def together(*args, **kwargs):
        calls.append("together")

    with (
        patch.object(ledger, "_verify_inputs", AsyncMock(return_value=None)),
        patch.object(ledger, "_verify_outputs", side_effect=vo),
        patch.object(
            ledger, "_verify_inputs_and_outputs_together", side_effect=together
        ),
    ):
        await ledger.verify_inputs_and_outputs(
            proofs=[MagicMock(spec=Proof)], outputs=outs
        )
    assert calls == ["outputs", "together"]
