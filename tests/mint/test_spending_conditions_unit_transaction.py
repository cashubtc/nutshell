import time
from hashlib import sha256

import pytest

from cashu.core.base import BlindedMessage, HTLCWitness, P2PKWitness
from cashu.core.crypto.secp import PrivateKey
from cashu.core.p2pk import (
    P2PKSecret,
    SigFlags,
    schnorr_sign,
    sig_all_melt_message,
    sig_all_swap_message,
)
from cashu.core.secret import Secret, SecretKind
from cashu.mint.conditions import LedgerSpendingConditions, WitnessForP2pkOrHtlc
from tests.mint.spending_conditions_test_helpers import proof, secret_str


def outputs_for_amounts(amounts: list[int]) -> list[BlindedMessage]:
    return [
        BlindedMessage(id="ks", amount=amount, B_=f"b{i:02x}")
        for i, amount in enumerate(amounts, start=1)
    ]


def p2pk_sig_inputs_signature(secret: str, signer: PrivateKey) -> str:
    return schnorr_sign(secret.encode("utf-8"), signer).hex()


def sig_all_signature(
    proofs: list,
    outputs: list[BlindedMessage],
    signer: PrivateKey,
) -> str:
    return schnorr_sign(
        sig_all_swap_message(proofs, outputs).encode("utf-8"), signer
    ).hex()


def sig_all_melt_signature(
    proofs: list,
    outputs: list[BlindedMessage],
    quote: str,
    signer: PrivateKey,
) -> str:
    return schnorr_sign(
        sig_all_melt_message(proofs, outputs, quote).encode("utf-8"), signer
    ).hex()


def test_transaction_p2pk_sig_inputs_unsigned_fails():
    cond = LedgerSpendingConditions()
    signer = PrivateKey()
    secret = secret_str(kind=SecretKind.P2PK, data=signer.public_key.format().hex())
    with pytest.raises(Exception, match="no signatures in proof"):
        cond._verify_input_output_spending_conditions(
            [proof(secret)],
            outputs_for_amounts([1]),
        )


def test_transaction_p2pk_sig_inputs_signed_succeeds():
    cond = LedgerSpendingConditions()
    signer = PrivateKey()
    secret = secret_str(kind=SecretKind.P2PK, data=signer.public_key.format().hex())
    sig = p2pk_sig_inputs_signature(secret, signer)
    assert cond._verify_input_output_spending_conditions(
        [proof(secret, signatures=[sig])],
        outputs_for_amounts([1]),
    )


def test_p2pk_requirements_ignore_stray_preimage_in_normalized_witness():
    cond = LedgerSpendingConditions()
    signer = PrivateKey()
    secret = secret_str(kind=SecretKind.P2PK, data=signer.public_key.format().hex())
    requirements = cond._get_spending_requirements(
        P2PKSecret.from_secret(Secret.deserialize(secret))
    )
    sig = p2pk_sig_inputs_signature(secret, signer)
    witness = WitnessForP2pkOrHtlc(preimage="11" * 32, signatures=[sig])
    assert cond._verify_p2pk_or_htlc_spending_requirements(
        requirements,
        witness,
        secret,
    )


def test_transaction_p2pk_sig_inputs_wrong_signer_fails():
    cond = LedgerSpendingConditions()
    signer = PrivateKey()
    wrong = PrivateKey()
    secret = secret_str(kind=SecretKind.P2PK, data=signer.public_key.format().hex())
    sig = p2pk_sig_inputs_signature(secret, wrong)
    with pytest.raises(Exception, match="signature threshold not met"):
        cond._verify_input_output_spending_conditions(
            [proof(secret, signatures=[sig])],
            outputs_for_amounts([1]),
        )


def test_transaction_p2pk_sig_inputs_multisig_2of3_succeeds():
    cond = LedgerSpendingConditions()
    alice = PrivateKey()
    bob = PrivateKey()
    carol = PrivateKey()
    secret = secret_str(
        kind=SecretKind.P2PK,
        data=alice.public_key.format().hex(),
        extra_tags=[
            ["pubkeys", bob.public_key.format().hex(), carol.public_key.format().hex()],
            ["n_sigs", "2"],
        ],
    )
    sig_a = p2pk_sig_inputs_signature(secret, alice)
    sig_b = p2pk_sig_inputs_signature(secret, bob)
    assert cond._verify_input_output_spending_conditions(
        [proof(secret, signatures=[sig_a, sig_b])],
        outputs_for_amounts([1]),
    )


def test_transaction_p2pk_sig_inputs_primary_still_works_after_locktime():
    cond = LedgerSpendingConditions()
    alice = PrivateKey()
    bob = PrivateKey()
    secret = secret_str(
        kind=SecretKind.P2PK,
        data=alice.public_key.format().hex(),
        extra_tags=[
            ["locktime", str(int(time.time()) - 5)],
            ["refund", bob.public_key.format().hex()],
        ],
    )
    sig = p2pk_sig_inputs_signature(secret, alice)
    assert cond._verify_input_output_spending_conditions(
        [proof(secret, signatures=[sig])],
        outputs_for_amounts([1]),
    )


def test_transaction_p2pk_refund_before_locktime_fails():
    cond = LedgerSpendingConditions()
    alice = PrivateKey()
    bob = PrivateKey()
    secret = secret_str(
        kind=SecretKind.P2PK,
        data=alice.public_key.format().hex(),
        extra_tags=[
            ["locktime", str(int(time.time()) + 60)],
            ["refund", bob.public_key.format().hex()],
        ],
    )
    sig = p2pk_sig_inputs_signature(secret, bob)
    with pytest.raises(Exception, match="signature threshold not met"):
        cond._verify_input_output_spending_conditions(
            [proof(secret, signatures=[sig])],
            outputs_for_amounts([1]),
        )


def test_transaction_p2pk_sig_inputs_anyone_can_spend_after_locktime():
    cond = LedgerSpendingConditions()
    alice = PrivateKey()
    secret = secret_str(
        kind=SecretKind.P2PK,
        data=alice.public_key.format().hex(),
        extra_tags=[["locktime", str(int(time.time()) - 5)]],
    )
    assert cond._verify_input_output_spending_conditions(
        [proof(secret)], outputs_for_amounts([1])
    )


def test_transaction_p2pk_refund_multisig_after_locktime_insufficient_signatures_fails():
    cond = LedgerSpendingConditions()
    alice = PrivateKey()
    bob = PrivateKey()
    carol = PrivateKey()
    secret = secret_str(
        kind=SecretKind.P2PK,
        data=alice.public_key.format().hex(),
        extra_tags=[
            ["locktime", str(int(time.time()) - 5)],
            ["refund", bob.public_key.format().hex(), carol.public_key.format().hex()],
            ["n_sigs_refund", "2"],
        ],
    )
    sig = p2pk_sig_inputs_signature(secret, bob)
    with pytest.raises(
        Exception, match=r"not enough pubkeys \(2\) or signatures \(1\)"
    ):
        cond._verify_input_output_spending_conditions(
            [proof(secret, signatures=[sig])],
            outputs_for_amounts([1]),
        )


def test_transaction_p2pk_refund_multisig_after_locktime_2of2_succeeds():
    cond = LedgerSpendingConditions()
    alice = PrivateKey()
    bob = PrivateKey()
    carol = PrivateKey()
    secret = secret_str(
        kind=SecretKind.P2PK,
        data=alice.public_key.format().hex(),
        extra_tags=[
            ["locktime", str(int(time.time()) - 5)],
            ["refund", bob.public_key.format().hex(), carol.public_key.format().hex()],
            ["n_sigs_refund", "2"],
        ],
    )
    sig_b = p2pk_sig_inputs_signature(secret, bob)
    sig_c = p2pk_sig_inputs_signature(secret, carol)
    assert cond._verify_input_output_spending_conditions(
        [proof(secret, signatures=[sig_b, sig_c])],
        outputs_for_amounts([1]),
    )


def test_transaction_htlc_preimage_only_no_pubkeys_succeeds():
    cond = LedgerSpendingConditions()
    preimage = "11" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret = secret_str(kind=SecretKind.HTLC, data=digest)
    assert cond._verify_input_output_spending_conditions(
        [proof(secret, htlc_preimage=preimage)],
        outputs_for_amounts([1]),
    )


def test_transaction_htlc_preimage_only_fails_when_pubkeys_required():
    cond = LedgerSpendingConditions()
    preimage = "11" * 32
    signer = PrivateKey()
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret = secret_str(
        kind=SecretKind.HTLC,
        data=digest,
        extra_tags=[["pubkeys", signer.public_key.format().hex()]],
    )
    with pytest.raises(Exception, match="no signatures in proof"):
        cond._verify_input_output_spending_conditions(
            [proof(secret, htlc_preimage=preimage)],
            outputs_for_amounts([1]),
        )


def test_transaction_htlc_signature_only_fails():
    cond = LedgerSpendingConditions()
    preimage = "11" * 32
    signer = PrivateKey()
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret = secret_str(
        kind=SecretKind.HTLC,
        data=digest,
        extra_tags=[["pubkeys", signer.public_key.format().hex()]],
    )
    sig = p2pk_sig_inputs_signature(secret, signer)
    with pytest.raises(Exception, match="no HTLC preimage provided"):
        cond._verify_input_output_spending_conditions(
            [proof(secret, signatures=[sig])],
            outputs_for_amounts([1]),
        )


def test_transaction_htlc_preimage_and_signature_succeeds():
    cond = LedgerSpendingConditions()
    preimage = "11" * 32
    signer = PrivateKey()
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret = secret_str(
        kind=SecretKind.HTLC,
        data=digest,
        extra_tags=[["pubkeys", signer.public_key.format().hex()]],
    )
    sig = p2pk_sig_inputs_signature(secret, signer)
    witness = HTLCWitness(preimage=preimage, signatures=[sig]).model_dump_json()
    p = proof(secret)
    p.witness = witness
    assert cond._verify_input_output_spending_conditions(
        [p],
        outputs_for_amounts([1]),
    )


def test_transaction_htlc_wrong_preimage_fails():
    cond = LedgerSpendingConditions()
    right_preimage = "11" * 32
    wrong_preimage = "22" * 32
    signer = PrivateKey()
    digest = sha256(bytes.fromhex(right_preimage)).hexdigest()
    secret = secret_str(
        kind=SecretKind.HTLC,
        data=digest,
        extra_tags=[["pubkeys", signer.public_key.format().hex()]],
    )
    sig = p2pk_sig_inputs_signature(secret, signer)
    p = proof(secret)
    p.witness = HTLCWitness(preimage=wrong_preimage, signatures=[sig]).model_dump_json()
    with pytest.raises(Exception, match="HTLC preimage does not match"):
        cond._verify_input_output_spending_conditions([p], outputs_for_amounts([1]))


def test_transaction_htlc_refund_after_locktime_succeeds():
    cond = LedgerSpendingConditions()
    receiver = PrivateKey()
    refund = PrivateKey()
    preimage = "11" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret = secret_str(
        kind=SecretKind.HTLC,
        data=digest,
        extra_tags=[
            ["pubkeys", receiver.public_key.format().hex()],
            ["locktime", str(int(time.time()) - 5)],
            ["refund", refund.public_key.format().hex()],
        ],
    )
    sig = p2pk_sig_inputs_signature(secret, refund)
    assert cond._verify_input_output_spending_conditions(
        [proof(secret, signatures=[sig])],
        outputs_for_amounts([1]),
    )


def test_transaction_htlc_valid_preimage_can_fall_back_to_refund_after_locktime():
    cond = LedgerSpendingConditions()
    receiver = PrivateKey()
    wrong_receiver = PrivateKey()
    refund = PrivateKey()
    preimage = "11" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret = secret_str(
        kind=SecretKind.HTLC,
        data=digest,
        extra_tags=[
            ["pubkeys", receiver.public_key.format().hex()],
            ["locktime", str(int(time.time()) - 5)],
            ["refund", refund.public_key.format().hex()],
        ],
    )
    wrong_sig = p2pk_sig_inputs_signature(secret, wrong_receiver)
    refund_sig = p2pk_sig_inputs_signature(secret, refund)
    p = proof(secret)
    p.witness = HTLCWitness(
        preimage=preimage,
        signatures=[wrong_sig, refund_sig],
    ).model_dump_json()
    assert cond._verify_input_output_spending_conditions([p], outputs_for_amounts([1]))


def test_transaction_htlc_wrong_preimage_can_fall_back_to_refund_after_locktime():
    cond = LedgerSpendingConditions()
    receiver = PrivateKey()
    refund = PrivateKey()
    right_preimage = "11" * 32
    wrong_preimage = "22" * 32
    digest = sha256(bytes.fromhex(right_preimage)).hexdigest()
    secret = secret_str(
        kind=SecretKind.HTLC,
        data=digest,
        extra_tags=[
            ["pubkeys", receiver.public_key.format().hex()],
            ["locktime", str(int(time.time()) - 5)],
            ["refund", refund.public_key.format().hex()],
        ],
    )
    refund_sig = p2pk_sig_inputs_signature(secret, refund)
    p = proof(secret)
    p.witness = HTLCWitness(
        preimage=wrong_preimage,
        signatures=[refund_sig],
    ).model_dump_json()
    assert cond._verify_input_output_spending_conditions([p], outputs_for_amounts([1]))


def test_transaction_htlc_multisig_2of3_succeeds():
    cond = LedgerSpendingConditions()
    alice = PrivateKey()
    bob = PrivateKey()
    carol = PrivateKey()
    preimage = "11" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret = secret_str(
        kind=SecretKind.HTLC,
        data=digest,
        extra_tags=[
            [
                "pubkeys",
                alice.public_key.format().hex(),
                bob.public_key.format().hex(),
                carol.public_key.format().hex(),
            ],
            ["n_sigs", "2"],
        ],
    )
    sig_a = p2pk_sig_inputs_signature(secret, alice)
    sig_b = p2pk_sig_inputs_signature(secret, bob)
    p = proof(secret)
    p.witness = HTLCWitness(
        preimage=preimage, signatures=[sig_a, sig_b]
    ).model_dump_json()
    assert cond._verify_input_output_spending_conditions([p], outputs_for_amounts([1]))


def test_transaction_htlc_receiver_path_still_valid_after_locktime():
    cond = LedgerSpendingConditions()
    receiver = PrivateKey()
    preimage = "11" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret = secret_str(
        kind=SecretKind.HTLC,
        data=digest,
        extra_tags=[
            ["pubkeys", receiver.public_key.format().hex()],
            ["locktime", str(int(time.time()) - 5)],
        ],
    )
    sig = p2pk_sig_inputs_signature(secret, receiver)
    witness = HTLCWitness(preimage=preimage, signatures=[sig]).model_dump_json()
    p = proof(secret)
    p.witness = witness
    assert cond._verify_input_output_spending_conditions([p], outputs_for_amounts([1]))


def test_transaction_p2pk_sigall_unsigned_fails():
    cond = LedgerSpendingConditions()
    signer = PrivateKey()
    secret = secret_str(
        kind=SecretKind.P2PK,
        data=signer.public_key.format().hex(),
        sigflag=SigFlags.SIG_ALL,
    )
    with pytest.raises(Exception, match="no witness in proof|no signatures in proof"):
        cond._verify_input_output_spending_conditions(
            [proof(secret)], outputs_for_amounts([1])
        )


def test_transaction_p2pk_mixed_sigflags_fails():
    cond = LedgerSpendingConditions()
    signer = PrivateKey()
    sig_inputs_secret = secret_str(
        kind=SecretKind.P2PK,
        data=signer.public_key.format().hex(),
        sigflag=SigFlags.SIG_INPUTS,
    )
    sig_all_secret = secret_str(
        kind=SecretKind.P2PK,
        data=signer.public_key.format().hex(),
        sigflag=SigFlags.SIG_ALL,
    )
    with pytest.raises(Exception, match="not all secrets are equal"):
        cond._verify_input_output_spending_conditions(
            [proof(sig_inputs_secret), proof(sig_all_secret)],
            outputs_for_amounts([1]),
        )


def test_transaction_p2pk_sigall_sig_inputs_fail():
    cond = LedgerSpendingConditions()
    signer = PrivateKey()
    secret = secret_str(
        kind=SecretKind.P2PK,
        data=signer.public_key.format().hex(),
        sigflag=SigFlags.SIG_ALL,
    )
    sig = p2pk_sig_inputs_signature(secret, signer)
    with pytest.raises(Exception, match="signature threshold not met"):
        cond._verify_input_output_spending_conditions(
            [proof(secret, signatures=[sig])],
            outputs_for_amounts([1]),
        )


def test_transaction_p2pk_sigall_multisig_2of3_succeeds():
    cond = LedgerSpendingConditions()
    alice = PrivateKey()
    bob = PrivateKey()
    carol = PrivateKey()
    secret = secret_str(
        kind=SecretKind.P2PK,
        data=alice.public_key.format().hex(),
        sigflag=SigFlags.SIG_ALL,
        extra_tags=[
            ["pubkeys", bob.public_key.format().hex(), carol.public_key.format().hex()],
            ["n_sigs", "2"],
        ],
    )
    proofs = [proof(secret), proof(secret)]
    outputs = outputs_for_amounts([1, 1])
    sig_a = sig_all_signature(proofs, outputs, alice)
    sig_b = sig_all_signature(proofs, outputs, bob)
    proofs[0].witness = P2PKWitness(signatures=[sig_a, sig_b]).model_dump_json()
    assert cond._verify_input_output_spending_conditions(proofs, outputs)


def test_transaction_p2pk_sigall_wrong_signer_fails():
    cond = LedgerSpendingConditions()
    signer = PrivateKey()
    wrong = PrivateKey()
    secret = secret_str(
        kind=SecretKind.P2PK,
        data=signer.public_key.format().hex(),
        sigflag=SigFlags.SIG_ALL,
    )
    proofs = [proof(secret)]
    outputs = outputs_for_amounts([1])
    sig = sig_all_signature(proofs, outputs, wrong)
    proofs[0].witness = P2PKWitness(signatures=[sig]).model_dump_json()
    with pytest.raises(Exception, match="signature threshold not met"):
        cond._verify_input_output_spending_conditions(proofs, outputs)


def test_transaction_p2pk_sigall_duplicate_signatures_do_not_count_twice():
    cond = LedgerSpendingConditions()
    alice = PrivateKey()
    bob = PrivateKey()
    secret = secret_str(
        kind=SecretKind.P2PK,
        data=alice.public_key.format().hex(),
        sigflag=SigFlags.SIG_ALL,
        extra_tags=[["pubkeys", bob.public_key.format().hex()], ["n_sigs", "2"]],
    )
    proofs = [proof(secret)]
    outputs = outputs_for_amounts([1])
    sig = sig_all_signature(proofs, outputs, alice)
    proofs[0].witness = P2PKWitness(signatures=[sig, sig]).model_dump_json()
    with pytest.raises(Exception, match="signature threshold not met"):
        cond._verify_input_output_spending_conditions(proofs, outputs)


def test_transaction_p2pk_sigall_valid_succeeds():
    cond = LedgerSpendingConditions()
    signer = PrivateKey()
    secret = secret_str(
        kind=SecretKind.P2PK,
        data=signer.public_key.format().hex(),
        sigflag=SigFlags.SIG_ALL,
    )
    proofs = [proof(secret), proof(secret)]
    outputs = outputs_for_amounts([1, 1])
    sig = sig_all_signature(proofs, outputs, signer)
    proofs[0].witness = P2PKWitness(signatures=[sig]).model_dump_json()
    assert cond._verify_input_output_spending_conditions(proofs, outputs)


def test_transaction_p2pk_sigall_primary_before_locktime_works_and_refund_rejected():
    cond = LedgerSpendingConditions()
    alice = PrivateKey()
    bob = PrivateKey()
    secret = secret_str(
        kind=SecretKind.P2PK,
        data=alice.public_key.format().hex(),
        sigflag=SigFlags.SIG_ALL,
        extra_tags=[
            ["locktime", str(int(time.time()) + 60)],
            ["refund", bob.public_key.format().hex()],
        ],
    )
    outputs = outputs_for_amounts([1])

    primary_proofs = [proof(secret)]
    primary_sig = sig_all_signature(primary_proofs, outputs, alice)
    primary_proofs[0].witness = P2PKWitness(signatures=[primary_sig]).model_dump_json()
    assert cond._verify_input_output_spending_conditions(primary_proofs, outputs)

    refund_proofs = [proof(secret)]
    refund_sig = sig_all_signature(refund_proofs, outputs, bob)
    refund_proofs[0].witness = P2PKWitness(signatures=[refund_sig]).model_dump_json()
    with pytest.raises(Exception, match="signature threshold not met"):
        cond._verify_input_output_spending_conditions(refund_proofs, outputs)


def test_transaction_p2pk_sigall_primary_still_works_after_locktime():
    cond = LedgerSpendingConditions()
    alice = PrivateKey()
    bob = PrivateKey()
    secret = secret_str(
        kind=SecretKind.P2PK,
        data=alice.public_key.format().hex(),
        sigflag=SigFlags.SIG_ALL,
        extra_tags=[
            ["locktime", str(int(time.time()) - 5)],
            ["refund", bob.public_key.format().hex()],
        ],
    )
    proofs = [proof(secret)]
    outputs = outputs_for_amounts([1])
    sig = sig_all_signature(proofs, outputs, alice)
    proofs[0].witness = P2PKWitness(signatures=[sig]).model_dump_json()
    assert cond._verify_input_output_spending_conditions(proofs, outputs)


def test_transaction_p2pk_sigall_anyone_can_spend_after_locktime():
    cond = LedgerSpendingConditions()
    alice = PrivateKey()
    secret = secret_str(
        kind=SecretKind.P2PK,
        data=alice.public_key.format().hex(),
        sigflag=SigFlags.SIG_ALL,
        extra_tags=[["locktime", str(int(time.time()) - 5)]],
    )
    assert cond._verify_input_output_spending_conditions(
        [proof(secret)], outputs_for_amounts([1])
    )


def test_transaction_p2pk_sigall_multisig_primary_still_works_after_locktime():
    cond = LedgerSpendingConditions()
    alice = PrivateKey()
    bob = PrivateKey()
    carol = PrivateKey()
    refund = PrivateKey()
    secret = secret_str(
        kind=SecretKind.P2PK,
        data=alice.public_key.format().hex(),
        sigflag=SigFlags.SIG_ALL,
        extra_tags=[
            ["locktime", str(int(time.time()) - 5)],
            ["pubkeys", bob.public_key.format().hex(), carol.public_key.format().hex()],
            ["n_sigs", "2"],
            ["refund", refund.public_key.format().hex()],
        ],
    )
    proofs = [proof(secret)]
    outputs = outputs_for_amounts([1])
    sig_a = sig_all_signature(proofs, outputs, alice)
    sig_b = sig_all_signature(proofs, outputs, bob)
    proofs[0].witness = P2PKWitness(signatures=[sig_a, sig_b]).model_dump_json()
    assert cond._verify_input_output_spending_conditions(proofs, outputs)


def test_transaction_p2pk_sigall_output_amounts_swapped_fail():
    cond = LedgerSpendingConditions()
    signer = PrivateKey()
    secret = secret_str(
        kind=SecretKind.P2PK,
        data=signer.public_key.format().hex(),
        sigflag=SigFlags.SIG_ALL,
    )
    proofs = [proof(secret), proof(secret)]
    outputs = outputs_for_amounts([8, 2])
    sig = sig_all_signature(proofs, outputs, signer)
    proofs[0].witness = P2PKWitness(signatures=[sig]).model_dump_json()
    outputs[0].amount, outputs[1].amount = outputs[1].amount, outputs[0].amount
    with pytest.raises(Exception, match="signature threshold not met"):
        cond._verify_input_output_spending_conditions(proofs, outputs)


def test_transaction_p2pk_sigall_mixed_kind_fails():
    cond = LedgerSpendingConditions()
    signer = PrivateKey()
    p2pk_secret = secret_str(
        kind=SecretKind.P2PK,
        data=signer.public_key.format().hex(),
        sigflag=SigFlags.SIG_ALL,
    )
    preimage = "22" * 32
    htlc_secret = secret_str(
        kind=SecretKind.HTLC,
        data=sha256(bytes.fromhex(preimage)).hexdigest(),
        sigflag=SigFlags.SIG_ALL,
    )
    with pytest.raises(Exception, match="not all secrets are equal"):
        cond._verify_input_output_spending_conditions(
            [proof(p2pk_secret), proof(htlc_secret)],
            outputs_for_amounts([1]),
        )


def test_transaction_p2pk_sigall_mixed_tags_fails():
    cond = LedgerSpendingConditions()
    signer = PrivateKey()
    plain_secret = secret_str(
        kind=SecretKind.P2PK,
        data=signer.public_key.format().hex(),
        sigflag=SigFlags.SIG_ALL,
    )
    tagged_secret = secret_str(
        kind=SecretKind.P2PK,
        data=signer.public_key.format().hex(),
        sigflag=SigFlags.SIG_ALL,
        extra_tags=[["refund", PrivateKey().public_key.format().hex()]],
    )
    with pytest.raises(Exception, match="not all secrets are equal"):
        cond._verify_input_output_spending_conditions(
            [proof(plain_secret), proof(tagged_secret)],
            outputs_for_amounts([1]),
        )


def test_transaction_htlc_sigall_preimage_only_no_pubkeys_succeeds():
    cond = LedgerSpendingConditions()
    preimage = "33" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret = secret_str(kind=SecretKind.HTLC, data=digest, sigflag=SigFlags.SIG_ALL)
    assert cond._verify_input_output_spending_conditions(
        [proof(secret, htlc_preimage=preimage)],
        outputs_for_amounts([1]),
    )


def test_transaction_htlc_sigall_preimage_only_fails_when_pubkeys_required():
    cond = LedgerSpendingConditions()
    preimage = "33" * 32
    signer = PrivateKey()
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret = secret_str(
        kind=SecretKind.HTLC,
        data=digest,
        sigflag=SigFlags.SIG_ALL,
        extra_tags=[["pubkeys", signer.public_key.format().hex()]],
    )
    with pytest.raises(Exception, match="no signatures in proof"):
        cond._verify_input_output_spending_conditions(
            [proof(secret, htlc_preimage=preimage)],
            outputs_for_amounts([1]),
        )


def test_transaction_htlc_sigall_signature_only_fails():
    cond = LedgerSpendingConditions()
    preimage = "33" * 32
    signer = PrivateKey()
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret = secret_str(
        kind=SecretKind.HTLC,
        data=digest,
        sigflag=SigFlags.SIG_ALL,
        extra_tags=[["pubkeys", signer.public_key.format().hex()]],
    )
    proofs = [proof(secret)]
    outputs = outputs_for_amounts([1])
    sig = sig_all_signature(proofs, outputs, signer)
    proofs[0].witness = HTLCWitness(signatures=[sig]).model_dump_json()
    with pytest.raises(Exception, match="no HTLC preimage provided"):
        cond._verify_input_output_spending_conditions(proofs, outputs)


def test_transaction_htlc_sigall_valid_succeeds():
    cond = LedgerSpendingConditions()
    preimage = "33" * 32
    signer = PrivateKey()
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret = secret_str(
        kind=SecretKind.HTLC,
        data=digest,
        sigflag=SigFlags.SIG_ALL,
        extra_tags=[["pubkeys", signer.public_key.format().hex()]],
    )
    proofs = [proof(secret)]
    outputs = outputs_for_amounts([1])
    sig = sig_all_signature(proofs, outputs, signer)
    proofs[0].witness = HTLCWitness(
        preimage=preimage, signatures=[sig]
    ).model_dump_json()
    assert cond._verify_input_output_spending_conditions(proofs, outputs)


def test_transaction_htlc_sigall_grouped_preimage_only_first_witness_succeeds():
    cond = LedgerSpendingConditions()
    preimage = "33" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret = secret_str(kind=SecretKind.HTLC, data=digest, sigflag=SigFlags.SIG_ALL)
    proofs = [proof(secret), proof(secret)]
    proofs[0].witness = HTLCWitness(preimage=preimage).model_dump_json()
    assert cond._verify_input_output_spending_conditions(
        proofs, outputs_for_amounts([1, 1])
    )


def test_transaction_htlc_sigall_refund_after_locktime_succeeds():
    cond = LedgerSpendingConditions()
    receiver = PrivateKey()
    refund = PrivateKey()
    preimage = "33" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret = secret_str(
        kind=SecretKind.HTLC,
        data=digest,
        sigflag=SigFlags.SIG_ALL,
        extra_tags=[
            ["pubkeys", receiver.public_key.format().hex()],
            ["locktime", str(int(time.time()) - 5)],
            ["refund", refund.public_key.format().hex()],
        ],
    )
    proofs = [proof(secret)]
    outputs = outputs_for_amounts([1])
    sig = sig_all_signature(proofs, outputs, refund)
    proofs[0].witness = HTLCWitness(signatures=[sig]).model_dump_json()
    assert cond._verify_input_output_spending_conditions(proofs, outputs)


def test_transaction_htlc_sigall_grouped_wrong_preimage_fails():
    cond = LedgerSpendingConditions()
    right_preimage = "33" * 32
    wrong_preimage = "44" * 32
    signer = PrivateKey()
    digest = sha256(bytes.fromhex(right_preimage)).hexdigest()
    secret = secret_str(
        kind=SecretKind.HTLC,
        data=digest,
        sigflag=SigFlags.SIG_ALL,
        extra_tags=[["pubkeys", signer.public_key.format().hex()]],
    )
    proofs = [proof(secret), proof(secret)]
    outputs = outputs_for_amounts([1, 1])
    sig = sig_all_signature(proofs, outputs, signer)
    proofs[0].witness = HTLCWitness(
        preimage=wrong_preimage, signatures=[sig]
    ).model_dump_json()
    with pytest.raises(Exception, match="HTLC preimage does not match"):
        cond._verify_input_output_spending_conditions(proofs, outputs)


def test_transaction_htlc_sigall_grouped_multisig_2of3_succeeds():
    cond = LedgerSpendingConditions()
    alice = PrivateKey()
    bob = PrivateKey()
    carol = PrivateKey()
    preimage = "33" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret = secret_str(
        kind=SecretKind.HTLC,
        data=digest,
        sigflag=SigFlags.SIG_ALL,
        extra_tags=[
            [
                "pubkeys",
                alice.public_key.format().hex(),
                bob.public_key.format().hex(),
                carol.public_key.format().hex(),
            ],
            ["n_sigs", "2"],
        ],
    )
    proofs = [proof(secret), proof(secret)]
    outputs = outputs_for_amounts([1, 1])
    sig_a = sig_all_signature(proofs, outputs, alice)
    sig_b = sig_all_signature(proofs, outputs, bob)
    proofs[0].witness = HTLCWitness(
        preimage=preimage, signatures=[sig_a, sig_b]
    ).model_dump_json()
    assert cond._verify_input_output_spending_conditions(proofs, outputs)


def test_transaction_htlc_sigall_receiver_path_still_valid_after_locktime():
    cond = LedgerSpendingConditions()
    receiver = PrivateKey()
    preimage = "33" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    secret = secret_str(
        kind=SecretKind.HTLC,
        data=digest,
        sigflag=SigFlags.SIG_ALL,
        extra_tags=[
            ["pubkeys", receiver.public_key.format().hex()],
            ["locktime", str(int(time.time()) - 5)],
        ],
    )
    proofs = [proof(secret)]
    outputs = outputs_for_amounts([1])
    sig = sig_all_signature(proofs, outputs, receiver)
    proofs[0].witness = HTLCWitness(
        preimage=preimage, signatures=[sig]
    ).model_dump_json()
    assert cond._verify_input_output_spending_conditions(proofs, outputs)


def test_transaction_p2pk_sigall_melt_message_wrong_quote_fails():
    cond = LedgerSpendingConditions()
    signer = PrivateKey()
    secret = secret_str(
        kind=SecretKind.P2PK,
        data=signer.public_key.format().hex(),
        sigflag=SigFlags.SIG_ALL,
    )
    proofs = [proof(secret)]
    outputs = outputs_for_amounts([1])
    sig = sig_all_melt_signature(proofs, outputs, "quote-a", signer)
    proofs[0].witness = P2PKWitness(signatures=[sig]).model_dump_json()
    with pytest.raises(Exception, match="signature threshold not met"):
        cond._verify_input_output_spending_conditions(proofs, outputs, "quote-b")


def test_transaction_htlc_sigall_melt_message_valid_succeeds():
    cond = LedgerSpendingConditions()
    signer = PrivateKey()
    preimage = "44" * 32
    secret = secret_str(
        kind=SecretKind.HTLC,
        data=sha256(bytes.fromhex(preimage)).hexdigest(),
        sigflag=SigFlags.SIG_ALL,
        extra_tags=[["pubkeys", signer.public_key.format().hex()]],
    )
    proofs = [proof(secret)]
    outputs = outputs_for_amounts([1])
    sig = sig_all_melt_signature(proofs, outputs, "quote-a", signer)
    proofs[0].witness = HTLCWitness(
        preimage=preimage, signatures=[sig]
    ).model_dump_json()
    assert cond._verify_input_output_spending_conditions(proofs, outputs, "quote-a")
