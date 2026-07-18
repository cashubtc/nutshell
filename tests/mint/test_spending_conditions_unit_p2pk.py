import time
from hashlib import sha256

import pytest

from cashu.core.crypto.secp import PrivateKey
from cashu.core.errors import TransactionError
from cashu.core.p2pk import P2PKSecret, SigFlags, schnorr_sign
from cashu.core.secret import Secret, SecretKind
from cashu.mint.conditions import LedgerSpendingConditions
from tests.mint.spending_conditions_test_helpers import (
    proof,
    pubkey_and_sig,
    secret_str,
)


def test_verify_p2pk_signatures_valid_threshold():
    cond = LedgerSpendingConditions()
    message = "msg-1"
    pub1, sig1 = pubkey_and_sig(message)
    pub2, sig2 = pubkey_and_sig(message)
    assert cond._verify_p2pk_signatures(message, [pub1, pub2], [sig1, sig2], 2)


def test_verify_p2pk_signatures_reject_duplicate_pubkeys():
    cond = LedgerSpendingConditions()
    message = "msg-dup-pubkeys"
    pub, sig = pubkey_and_sig(message)
    with pytest.raises(Exception, match="pubkeys must be unique"):
        cond._verify_p2pk_signatures(message, [pub, pub], [sig], 1)


def test_verify_p2pk_signatures_allows_duplicate_signatures_when_threshold_is_met():
    cond = LedgerSpendingConditions()
    message = "msg-dup-sigs"
    pub, sig = pubkey_and_sig(message)
    assert cond._verify_p2pk_signatures(message, [pub], [sig, sig], 1)


def test_verify_p2pk_signatures_reject_missing_signatures():
    cond = LedgerSpendingConditions()
    pub, _ = pubkey_and_sig("msg-empty")
    with pytest.raises(Exception, match="no signatures in proof"):
        cond._verify_p2pk_signatures("msg-empty", [pub], [], 1)


def test_verify_p2pk_signatures_reject_threshold_not_met():
    cond = LedgerSpendingConditions()
    message = "msg-threshold"
    pub1, sig1 = pubkey_and_sig(message)
    pub2, _ = pubkey_and_sig(message)
    with pytest.raises(
        Exception, match=r"not enough pubkeys \(2\) or signatures \(1\)"
    ):
        cond._verify_p2pk_signatures(message, [pub1, pub2], [sig1], 2)


def test_verify_p2pk_signatures_rejects_same_x_coord_different_prefix():
    cond = LedgerSpendingConditions()
    message = "msg-1"
    priv = PrivateKey()
    pubkey = priv.public_key.format().hex()
    if pubkey.startswith("02"):
        pub1 = pubkey
        pub2 = "03" + pubkey[2:]
    else:
        pub1 = pubkey
        pub2 = "02" + pubkey[2:]
    sig1 = priv.sign_schnorr(sha256(message.encode()).digest(), b"1" * 32).hex()
    sig2 = priv.sign_schnorr(sha256(message.encode()).digest(), b"2" * 32).hex()
    with pytest.raises(Exception, match="pubkeys must have unique x-coordinates"):
        cond._verify_p2pk_signatures(message, [pub1, pub2], [sig1, sig2], 2)


def test_verify_p2pk_sig_inputs_rejects_sig_all():
    cond = LedgerSpendingConditions()
    pub, _ = pubkey_and_sig("msg-sig-all")
    raw_secret = secret_str(kind=SecretKind.P2PK, data=pub, sigflag=SigFlags.SIG_ALL)
    p2pk_secret = P2PKSecret.from_secret(Secret.deserialize(raw_secret))
    with pytest.raises(TransactionError, match="SIG_ALL proofs must be verified"):
        cond._verify_p2pk_or_htlc_sig_inputs(proof(raw_secret), p2pk_secret)


def test_get_spending_requirements_p2pk_before_locktime():
    cond = LedgerSpendingConditions()
    main_pub, _ = pubkey_and_sig("msg-main-before")
    refund_pub, _ = pubkey_and_sig("msg-refund-before")
    future = str(int(time.time()) + 60)
    raw_secret = secret_str(
        kind=SecretKind.P2PK,
        data=main_pub,
        extra_tags=[["locktime", future], ["refund", refund_pub]],
    )
    secret = P2PKSecret.from_secret(Secret.deserialize(raw_secret))

    requirements = cond._get_spending_requirements(secret)
    assert requirements.preimage_hash is None
    assert requirements.primary_path.pubkeys == [main_pub.lower()]
    assert requirements.primary_path.required_sigs == 1
    assert requirements.refund_path is None


def test_get_spending_requirements_p2pk_after_locktime_keeps_primary_and_adds_refund():
    cond = LedgerSpendingConditions()
    main_pub, _ = pubkey_and_sig("msg-main-after")
    refund_pub, _ = pubkey_and_sig("msg-refund-after")
    past = str(int(time.time()) - 60)
    raw_secret = secret_str(
        kind=SecretKind.P2PK,
        data=main_pub,
        extra_tags=[["locktime", past], ["refund", refund_pub]],
    )
    secret = P2PKSecret.from_secret(Secret.deserialize(raw_secret))

    requirements = cond._get_spending_requirements(secret)
    assert requirements.preimage_hash is None
    assert requirements.primary_path.pubkeys == [main_pub.lower()]
    assert requirements.primary_path.required_sigs == 1
    assert requirements.refund_path is not None
    assert requirements.refund_path.pubkeys == [refund_pub.lower()]
    assert requirements.refund_path.required_sigs == 1


def test_get_spending_requirements_post_locktime_without_refund_is_anyone_can_spend():
    cond = LedgerSpendingConditions()
    pub, _ = pubkey_and_sig("msg-anyone-spend")
    past = str(int(time.time()) - 60)
    raw_secret = secret_str(
        kind=SecretKind.P2PK,
        data=pub,
        extra_tags=[["locktime", past]],
    )
    secret = P2PKSecret.from_secret(Secret.deserialize(raw_secret))

    requirements = cond._get_spending_requirements(secret)
    assert requirements.refund_path is not None
    assert requirements.refund_path.pubkeys == []
    assert requirements.refund_path.required_sigs == 0


def test_verify_p2pk_sig_inputs_main_path_valid():
    cond = LedgerSpendingConditions()
    signer = PrivateKey()
    pub = signer.public_key.format().hex()
    raw_secret = secret_str(kind=SecretKind.P2PK, data=pub)
    sig = schnorr_sign(raw_secret.encode("utf-8"), signer).hex()
    assert cond._verify_input_spending_conditions(proof(raw_secret, signatures=[sig]))


def test_verify_p2pk_sig_inputs_refund_path_after_locktime():
    cond = LedgerSpendingConditions()
    main_pub = PrivateKey().public_key.format().hex()
    refund_signer = PrivateKey()
    refund_pub = refund_signer.public_key.format().hex()
    past = str(int(time.time()) - 5)
    raw_secret = secret_str(
        kind=SecretKind.P2PK,
        data=main_pub,
        extra_tags=[["locktime", past], ["refund", refund_pub]],
    )
    refund_sig = schnorr_sign(raw_secret.encode("utf-8"), refund_signer).hex()
    assert cond._verify_input_spending_conditions(
        proof(raw_secret, signatures=[refund_sig])
    )


def test_verify_p2pk_sig_inputs_allows_anyone_after_locktime_without_refund_pubkeys():
    cond = LedgerSpendingConditions()
    pub, _ = pubkey_and_sig("msg-no-refund-pubkeys")
    past = str(int(time.time()) - 5)
    raw_secret = secret_str(
        kind=SecretKind.P2PK,
        data=pub,
        extra_tags=[["locktime", past]],
    )
    assert cond._verify_input_spending_conditions(proof(raw_secret))
