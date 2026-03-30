import time
from hashlib import sha256
from unittest.mock import patch

import pytest

from cashu.core.base import BlindedMessage, HTLCWitness, P2PKWitness, Proof
from cashu.core.crypto.secp import PrivateKey
from cashu.core.errors import InvalidProofsError, TransactionError
from cashu.core.p2pk import P2PKSecret, SigFlags, schnorr_sign
from cashu.core.secret import Secret, SecretKind, Tags
from cashu.mint.conditions import LedgerSpendingConditions
from cashu.mint.ledger import Ledger
from tests.helpers import assert_err


def _pubkey_and_sig(message: str):
    priv = PrivateKey()
    pub = priv.public_key.format().hex()
    sig = schnorr_sign(message.encode("utf-8"), priv).hex()
    return pub, sig


def _secret(
    *,
    kind: SecretKind,
    data: str,
    sigflag: SigFlags | None = None,
    extra_tags: list[list[str]] | None = None,
) -> str:
    tags = []
    if sigflag:
        tags.append(["sigflag", sigflag.value])
    if extra_tags:
        tags.extend(extra_tags)
    return Secret(
        kind=kind.value, data=data, tags=Tags(tags=tags), nonce="0" * 32
    ).serialize()


def _proof(
    secret: str, signatures: list[str] | None = None, htlc_preimage: str | None = None
):
    witness = None
    if signatures is not None:
        witness = P2PKWitness(signatures=signatures).model_dump_json()
    if htlc_preimage is not None:
        witness = HTLCWitness(preimage=htlc_preimage).model_dump_json()
    return Proof(id="ks", amount=1, C="00", secret=secret, witness=witness)


def test_verify_p2pk_signatures_valid_threshold():
    cond = LedgerSpendingConditions()
    message = "msg-1"
    pub1, sig1 = _pubkey_and_sig(message)
    pub2, sig2 = _pubkey_and_sig(message)
    assert cond._verify_p2pk_signatures(message, [pub1, pub2], [sig1, sig2], 2)


def test_verify_p2pk_signatures_reject_duplicate_pubkeys():
    cond = LedgerSpendingConditions()
    message = "msg-dup-pubkeys"
    pub, sig = _pubkey_and_sig(message)
    with pytest.raises(TransactionError, match="pubkeys must be unique"):
        cond._verify_p2pk_signatures(message, [pub, pub], [sig], 1)


def test_verify_p2pk_signatures_reject_duplicate_signatures():
    cond = LedgerSpendingConditions()
    message = "msg-dup-sigs"
    pub, sig = _pubkey_and_sig(message)
    with pytest.raises(TransactionError, match="signatures must be unique"):
        cond._verify_p2pk_signatures(message, [pub], [sig, sig], 1)


def test_verify_p2pk_signatures_reject_missing_signatures():
    cond = LedgerSpendingConditions()
    pub, _ = _pubkey_and_sig("msg-empty")
    with pytest.raises(TransactionError, match="no signatures in proof"):
        cond._verify_p2pk_signatures("msg-empty", [pub], [], 1)


def test_verify_p2pk_signatures_reject_threshold_not_met():
    cond = LedgerSpendingConditions()
    message = "msg-threshold"
    pub1, sig1 = _pubkey_and_sig(message)
    pub2, _ = _pubkey_and_sig(message)
    with pytest.raises(
        TransactionError, match=r"not enough pubkeys \(2\) or signatures \(1\)"
    ):
        cond._verify_p2pk_signatures(message, [pub1, pub2], [sig1], 2)


def test_verify_p2pk_sig_inputs_skips_for_non_input_sigflag():
    cond = LedgerSpendingConditions()
    pub, _ = _pubkey_and_sig("msg-sig-all")
    secret_str = _secret(kind=SecretKind.P2PK, data=pub, sigflag=SigFlags.SIG_ALL)
    proof = _proof(secret_str)
    p2pk_secret = P2PKSecret.from_secret(Secret.deserialize(secret_str))
    assert cond._verify_p2pk_sig_inputs(proof, p2pk_secret)


def test_verify_p2pk_sig_inputs_main_path_valid():
    cond = LedgerSpendingConditions()
    signer = PrivateKey()
    pub = signer.public_key.format().hex()
    secret_str = _secret(kind=SecretKind.P2PK, data=pub)
    sig = schnorr_sign(secret_str.encode("utf-8"), signer).hex()
    proof = _proof(secret_str, signatures=[sig])
    assert cond._verify_input_spending_conditions(proof)


def test_verify_p2pk_sig_inputs_refund_path_after_locktime():
    cond = LedgerSpendingConditions()
    main_pub = PrivateKey().public_key.format().hex()
    refund_signer = PrivateKey()
    refund_pub = refund_signer.public_key.format().hex()
    past = str(int(time.time()) - 5)
    secret_str = _secret(
        kind=SecretKind.P2PK,
        data=main_pub,
        extra_tags=[["locktime", past], ["refund", refund_pub]],
    )
    refund_sig = schnorr_sign(secret_str.encode("utf-8"), refund_signer).hex()
    proof = _proof(secret_str, signatures=[refund_sig])
    assert cond._verify_input_spending_conditions(proof)


def test_verify_p2pk_sig_inputs_allows_anyone_after_locktime_without_refund_pubkeys():
    cond = LedgerSpendingConditions()
    pub, _ = _pubkey_and_sig("msg-no-refund-pubkeys")
    past = str(int(time.time()) - 5)
    secret_str = _secret(
        kind=SecretKind.P2PK,
        data=pub,
        extra_tags=[["locktime", past]],
    )
    proof = _proof(secret_str)
    assert cond._verify_input_spending_conditions(proof)


def test_verify_input_spending_conditions_rejects_witness_without_condition():
    cond = LedgerSpendingConditions()
    proof = _proof("plain-secret", signatures=["ab" * 64])
    with pytest.raises(TransactionError, match="witness data not allowed"):
        cond._verify_input_spending_conditions(proof)


def test_verify_input_spending_conditions_accepts_valid_htlc_preimage():
    cond = LedgerSpendingConditions()
    preimage = "11" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret_str = _secret(kind=SecretKind.HTLC, data=digest)
    proof = _proof(secret_str, htlc_preimage=preimage)
    assert cond._verify_input_spending_conditions(proof)


def test_inputs_require_sigall_detects_any_sigall():
    cond = LedgerSpendingConditions()
    pub_a, _ = _pubkey_and_sig("msg-a")
    pub_b, _ = _pubkey_and_sig("msg-b")
    inputs_only = _proof(
        _secret(kind=SecretKind.P2PK, data=pub_a, sigflag=SigFlags.SIG_INPUTS)
    )
    sig_all = _proof(
        _secret(kind=SecretKind.P2PK, data=pub_b, sigflag=SigFlags.SIG_ALL)
    )
    assert not cond._inputs_require_sigall([inputs_only])
    assert cond._inputs_require_sigall([inputs_only, sig_all])


def test_verify_all_secrets_equal_and_return_rejects_mismatch():
    cond = LedgerSpendingConditions()
    pub_a, _ = _pubkey_and_sig("msg-eq-a")
    pub_b, _ = _pubkey_and_sig("msg-eq-b")
    p1 = _proof(_secret(kind=SecretKind.P2PK, data=pub_a, sigflag=SigFlags.SIG_ALL))
    p2 = _proof(_secret(kind=SecretKind.P2PK, data=pub_b, sigflag=SigFlags.SIG_ALL))
    with pytest.raises(TransactionError, match="not all secrets are equal"):
        cond._verify_all_secrets_equal_and_return([p1, p2])


def test_verify_sigall_spending_conditions_valid():
    cond = LedgerSpendingConditions()
    outputs = [BlindedMessage(id="ks", amount=1, B_="abcd")]

    signer = PrivateKey()
    signer_pub = signer.public_key.format().hex()
    fixed_secret = _secret(
        kind=SecretKind.P2PK, data=signer_pub, sigflag=SigFlags.SIG_ALL
    )
    proofs = [_proof(fixed_secret), _proof(fixed_secret)]
    message_to_sign = "".join([p.secret for p in proofs] + [o.B_ for o in outputs])
    signature = schnorr_sign(message_to_sign.encode("utf-8"), signer).hex()
    proofs[0].witness = P2PKWitness(signatures=[signature]).model_dump_json()

    assert cond._verify_sigall_spending_conditions(proofs, outputs)


def test_verify_sigall_spending_conditions_returns_false_for_different_secrets():
    cond = LedgerSpendingConditions()
    pub_a, sig_a = _pubkey_and_sig("msg-mismatch")
    pub_b, _ = _pubkey_and_sig("msg-mismatch")
    p1 = _proof(
        _secret(kind=SecretKind.P2PK, data=pub_a, sigflag=SigFlags.SIG_ALL), [sig_a]
    )
    p2 = _proof(
        _secret(kind=SecretKind.P2PK, data=pub_b, sigflag=SigFlags.SIG_ALL), [sig_a]
    )
    outputs = [BlindedMessage(id="ks", amount=1, B_="a1")]
    assert cond._verify_sigall_spending_conditions([p1, p2], outputs) is False


def test_verify_sigall_spending_conditions_rejects_duplicate_witness_signatures():
    cond = LedgerSpendingConditions()
    signer = PrivateKey()
    pub = signer.public_key.format().hex()
    secret_str = _secret(kind=SecretKind.P2PK, data=pub, sigflag=SigFlags.SIG_ALL)
    proofs = [_proof(secret_str), _proof(secret_str)]
    outputs = [BlindedMessage(id="ks", amount=1, B_="a2")]
    message_to_sign = "".join([p.secret for p in proofs] + [o.B_ for o in outputs])
    sig = schnorr_sign(message_to_sign.encode("utf-8"), signer).hex()
    proofs[0].witness = P2PKWitness(signatures=[sig, sig]).model_dump_json()

    with pytest.raises(TransactionError, match="signatures must be unique"):
        cond._verify_sigall_spending_conditions(proofs, outputs)


def test_verify_input_output_spending_conditions_requires_equal_secrets_with_sigall():
    cond = LedgerSpendingConditions()
    pub_a, _ = _pubkey_and_sig("msg-io-a")
    pub_b, _ = _pubkey_and_sig("msg-io-b")
    p1 = _proof(_secret(kind=SecretKind.P2PK, data=pub_a, sigflag=SigFlags.SIG_ALL))
    p2 = _proof(_secret(kind=SecretKind.P2PK, data=pub_b, sigflag=SigFlags.SIG_ALL))
    outputs = [BlindedMessage(id="ks", amount=1, B_="b1")]
    with pytest.raises(TransactionError, match="not all secrets are equal"):
        cond._verify_input_output_spending_conditions([p1, p2], outputs)


@pytest.mark.asyncio
async def test_verify_inputs_and_outputs_p2pk_custom_sigflag_fails_without_outputs(
    ledger: Ledger,
):
    """Unsupported sigflag must not pass melt-style verification (outputs=None)."""
    kid = next(iter(ledger.keysets.keys()))
    signer = PrivateKey()
    pub = signer.public_key.format().hex()
    secret_str = _secret(
        kind=SecretKind.P2PK, data=pub, extra_tags=[["sigflag", "CUSTOM"]]
    )
    sig = schnorr_sign(secret_str.encode("utf-8"), signer).hex()
    proof = _proof(secret_str, signatures=[sig])
    proof.id = kid

    with (
        patch.object(ledger, "_verify_proof_bdhke", return_value=True),
        patch.object(ledger.db_read, "_verify_proofs_spendable", return_value=True),
    ):
        await assert_err(
            ledger.verify_inputs_and_outputs(proofs=[proof], outputs=None),
            InvalidProofsError(),
        )


@pytest.mark.asyncio
async def test_verify_inputs_and_outputs_htlc_custom_sigflag_fails_without_outputs(
    ledger: Ledger,
):
    """Unsupported sigflag must not pass melt-style verification (outputs=None)."""
    kid = next(iter(ledger.keysets.keys()))
    preimage = "22" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret_str = _secret(
        kind=SecretKind.HTLC, data=digest, extra_tags=[["sigflag", "CUSTOM"]]
    )
    proof = _proof(secret_str, htlc_preimage=preimage)
    proof.id = kid

    with (
        patch.object(ledger, "_verify_proof_bdhke", return_value=True),
        patch.object(ledger.db_read, "_verify_proofs_spendable", return_value=True),
    ):
        await assert_err(
            ledger.verify_inputs_and_outputs(proofs=[proof], outputs=None),
            InvalidProofsError(),
        )
