import time
from hashlib import sha256

import pytest

from cashu.core.htlc import HTLCSecret
from cashu.core.secret import Secret, SecretKind
from cashu.mint.conditions import LedgerSpendingConditions
from tests.mint.spending_conditions_test_helpers import (
    proof,
    pubkey_and_sig,
    secret_str,
)


def test_get_spending_requirements_htlc_before_locktime():
    cond = LedgerSpendingConditions()
    preimage = "22" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    pub, _ = pubkey_and_sig("msg-htlc-before")
    future = str(int(time.time()) + 60)
    raw_secret = secret_str(
        kind=SecretKind.HTLC,
        data=digest,
        extra_tags=[["locktime", future], ["pubkeys", pub]],
    )
    secret = HTLCSecret.from_secret(Secret.deserialize(raw_secret))

    requirements = cond._get_spending_requirements(secret)
    assert requirements.preimage_hash == digest
    assert requirements.primary_path.pubkeys == [pub.lower()]
    assert requirements.primary_path.required_sigs == 1
    assert requirements.refund_path is None


def test_get_spending_requirements_htlc_after_locktime_keeps_receiver_and_adds_refund():
    cond = LedgerSpendingConditions()
    preimage = "33" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    receiver_pub, _ = pubkey_and_sig("msg-htlc-receiver-after")
    refund_pub, _ = pubkey_and_sig("msg-htlc-refund-after")
    past = str(int(time.time()) - 60)
    raw_secret = secret_str(
        kind=SecretKind.HTLC,
        data=digest,
        extra_tags=[["locktime", past], ["pubkeys", receiver_pub], ["refund", refund_pub]],
    )
    secret = HTLCSecret.from_secret(Secret.deserialize(raw_secret))

    requirements = cond._get_spending_requirements(secret)
    assert requirements.preimage_hash == digest
    assert requirements.primary_path.pubkeys == [receiver_pub.lower()]
    assert requirements.primary_path.required_sigs == 1
    assert requirements.refund_path is not None
    assert requirements.refund_path.pubkeys == [refund_pub.lower()]
    assert requirements.refund_path.required_sigs == 1


def test_get_spending_requirements_htlc_no_pubkeys_requires_zero_signatures():
    cond = LedgerSpendingConditions()
    preimage = "44" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    raw_secret = secret_str(kind=SecretKind.HTLC, data=digest)
    secret = HTLCSecret.from_secret(Secret.deserialize(raw_secret))

    requirements = cond._get_spending_requirements(secret)
    assert requirements.preimage_hash == digest
    assert requirements.primary_path.pubkeys == []
    assert requirements.primary_path.required_sigs == 0
    assert requirements.refund_path is None


def test_verify_input_spending_conditions_accepts_valid_htlc_preimage():
    cond = LedgerSpendingConditions()
    preimage = "11" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    raw_secret = secret_str(kind=SecretKind.HTLC, data=digest)
    assert cond._verify_input_spending_conditions(proof(raw_secret, htlc_preimage=preimage))


def test_verify_htlc_preimage_rejects_missing_preimage():
    cond = LedgerSpendingConditions()
    preimage = "11" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret = HTLCSecret.from_secret(
        Secret.deserialize(secret_str(kind=SecretKind.HTLC, data=digest))
    )
    with pytest.raises(Exception, match="no HTLC preimage provided"):
        cond._verify_htlc_preimage(secret.data, None)


def test_verify_htlc_preimage_rejects_wrong_preimage():
    cond = LedgerSpendingConditions()
    right = "11" * 32
    wrong = "22" * 32
    digest = sha256(bytes.fromhex(right)).hexdigest()
    secret = HTLCSecret.from_secret(
        Secret.deserialize(secret_str(kind=SecretKind.HTLC, data=digest))
    )
    with pytest.raises(Exception, match="HTLC preimage does not match"):
        cond._verify_htlc_preimage(secret.data, wrong)
