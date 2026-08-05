import pytest

from cashu.core.base import BlindedMessage, P2PKWitness
from cashu.core.crypto.secp import PrivateKey
from cashu.core.nuts import nut11
from cashu.core.p2pk import SigFlags, schnorr_sign
from cashu.core.secret import SecretKind
from cashu.mint.conditions import LedgerSpendingConditions
from tests.mint.spending_conditions_test_helpers import (
    proof,
    pubkey_and_sig,
    secret_str,
)


def test_inputs_require_sigall_detects_any_sigall():
    cond = LedgerSpendingConditions()
    pub_a, _ = pubkey_and_sig("msg-a")
    pub_b, _ = pubkey_and_sig("msg-b")
    inputs_only = proof(
        secret_str(kind=SecretKind.P2PK, data=pub_a, sigflag=SigFlags.SIG_INPUTS)
    )
    sig_all = proof(
        secret_str(kind=SecretKind.P2PK, data=pub_b, sigflag=SigFlags.SIG_ALL)
    )
    assert not cond._at_least_one_proof_has_sig_all([inputs_only])
    assert cond._at_least_one_proof_has_sig_all([inputs_only, sig_all])


def test_verify_all_secrets_equal_and_return_rejects_mismatch():
    cond = LedgerSpendingConditions()
    pub_a, _ = pubkey_and_sig("msg-eq-a")
    pub_b, _ = pubkey_and_sig("msg-eq-b")
    p1 = proof(secret_str(kind=SecretKind.P2PK, data=pub_a, sigflag=SigFlags.SIG_ALL))
    p2 = proof(secret_str(kind=SecretKind.P2PK, data=pub_b, sigflag=SigFlags.SIG_ALL))
    with pytest.raises(Exception, match="not all secrets are equal"):
        cond._verify_all_secrets_equal_and_return([p1, p2])


def test_verify_sigall_spending_conditions_valid():
    cond = LedgerSpendingConditions()
    outputs = [BlindedMessage(id="ks", amount=1, B_="abcd")]
    signer = PrivateKey()
    signer_pub = signer.public_key.format().hex()
    raw_secret = secret_str(
        kind=SecretKind.P2PK, data=signer_pub, sigflag=SigFlags.SIG_ALL
    )
    proofs = [proof(raw_secret), proof(raw_secret)]
    message_to_sign = nut11.sigall_message_to_sign(proofs, outputs)
    signature = schnorr_sign(message_to_sign.encode("utf-8"), signer).hex()
    proofs[0].witness = P2PKWitness(signatures=[signature]).model_dump_json()
    assert cond._verify_sigall_spending_conditions(proofs, outputs)


def test_verify_sigall_spending_conditions_rejects_different_secrets():
    cond = LedgerSpendingConditions()
    pub_a, sig_a = pubkey_and_sig("msg-mismatch")
    pub_b, _ = pubkey_and_sig("msg-mismatch")
    p1 = proof(
        secret_str(kind=SecretKind.P2PK, data=pub_a, sigflag=SigFlags.SIG_ALL), [sig_a]
    )
    p2 = proof(
        secret_str(kind=SecretKind.P2PK, data=pub_b, sigflag=SigFlags.SIG_ALL), [sig_a]
    )
    outputs = [BlindedMessage(id="ks", amount=1, B_="a1")]
    with pytest.raises(Exception, match="not all secrets are equal"):
        cond._verify_sigall_spending_conditions([p1, p2], outputs)


def test_verify_sigall_spending_conditions_allows_duplicate_witness_signatures_when_threshold_is_met():
    cond = LedgerSpendingConditions()
    signer = PrivateKey()
    pub = signer.public_key.format().hex()
    raw_secret = secret_str(kind=SecretKind.P2PK, data=pub, sigflag=SigFlags.SIG_ALL)
    proofs = [proof(raw_secret), proof(raw_secret)]
    outputs = [BlindedMessage(id="ks", amount=1, B_="a2")]
    message_to_sign = nut11.sigall_message_to_sign(proofs, outputs)
    sig = schnorr_sign(message_to_sign.encode("utf-8"), signer).hex()
    proofs[0].witness = P2PKWitness(signatures=[sig, sig]).model_dump_json()
    assert cond._verify_sigall_spending_conditions(proofs, outputs)


def test_verify_input_output_spending_conditions_requires_equal_secrets_with_sigall():
    cond = LedgerSpendingConditions()
    pub_a, _ = pubkey_and_sig("msg-io-a")
    pub_b, _ = pubkey_and_sig("msg-io-b")
    p1 = proof(secret_str(kind=SecretKind.P2PK, data=pub_a, sigflag=SigFlags.SIG_ALL))
    p2 = proof(secret_str(kind=SecretKind.P2PK, data=pub_b, sigflag=SigFlags.SIG_ALL))
    outputs = [BlindedMessage(id="ks", amount=1, B_="b1")]
    with pytest.raises(Exception, match="not all secrets are equal"):
        cond._verify_input_output_spending_conditions([p1, p2], outputs)
