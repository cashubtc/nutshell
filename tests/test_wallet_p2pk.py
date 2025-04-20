import asyncio
import copy
import hashlib
import json
import secrets
from typing import List

import pytest
import pytest_asyncio
from coincurve import PrivateKey as CoincurvePrivateKey

from cashu.core.base import P2PKWitness, Proof
from cashu.core.crypto.secp import PrivateKey, PublicKey
from cashu.core.migrations import migrate_databases
from cashu.core.p2pk import P2PKSecret, SigFlags
from cashu.core.secret import Secret, SecretKind, Tags
from cashu.wallet import migrations
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from cashu.wallet.wallet import Wallet as Wallet2
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import is_deprecated_api_only, pay_if_regtest


async def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        if msg not in str(exc.args[0]):
            raise Exception(f"Expected error: {msg}, got: {exc.args[0]}")
        return
    raise Exception(f"Expected error: {msg}, got no error")


def assert_amt(proofs: List[Proof], expected: int):
    """Assert amounts the proofs contain."""
    assert [p.amount for p in proofs] == expected


@pytest_asyncio.fixture(scope="function")
async def wallet1():
    wallet1 = await Wallet1.with_db(
        SERVER_ENDPOINT, "test_data/wallet_p2pk_1", "wallet1"
    )
    await migrate_databases(wallet1.db, migrations)
    await wallet1.load_mint()
    yield wallet1


@pytest_asyncio.fixture(scope="function")
async def wallet2():
    wallet2 = await Wallet2.with_db(
        SERVER_ENDPOINT, "test_data/wallet_p2pk_2", "wallet2"
    )
    await migrate_databases(wallet2.db, migrations)
    wallet2.private_key = PrivateKey(secrets.token_bytes(32), raw=True)
    await wallet2.load_mint()
    yield wallet2


@pytest.mark.asyncio
async def test_create_p2pk_pubkey(wallet1: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    pubkey = await wallet1.create_p2pk_pubkey()
    PublicKey(bytes.fromhex(pubkey), raw=True)


@pytest.mark.asyncio
async def test_p2pk(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(pubkey_wallet2)  # sender side
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    await wallet2.redeem(send_proofs)

    proof_states = await wallet2.check_proof_state(send_proofs)
    assert all([p.spent for p in proof_states.states])

    if not is_deprecated_api_only:
        for state in proof_states.states:
            assert state.witness is not None
            witness_obj = json.loads(state.witness)
            assert len(witness_obj["signatures"]) == 1
            assert len(witness_obj["signatures"][0]) == 128


@pytest.mark.asyncio
async def test_p2pk_sig_all(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, sig_all=True
    )  # sender side
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    await wallet2.redeem(send_proofs)


@pytest.mark.asyncio
async def test_p2pk_receive_with_wrong_private_key(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # receiver side
    # sender side
    secret_lock = await wallet1.create_p2pk_lock(pubkey_wallet2)  # sender side
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # receiver side: wrong private key
    wallet2.private_key = PrivateKey()  # wrong private key
    await assert_err(
        wallet2.redeem(send_proofs),
        "",
    )


@pytest.mark.asyncio
async def test_p2pk_short_locktime_receive_with_wrong_private_key(
    wallet1: Wallet, wallet2: Wallet
):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # receiver side
    # sender side
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, locktime_seconds=2
    )  # sender side
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # receiver side: wrong private key
    wallet2.private_key = PrivateKey()  # wrong private key
    send_proofs_copy = copy.deepcopy(send_proofs)
    await assert_err(
        wallet2.redeem(send_proofs),
        "",
    )
    await asyncio.sleep(2)
    # should succeed because even with the wrong private key we
    # can redeem the tokens after the locktime
    await wallet2.redeem(send_proofs_copy)


@pytest.mark.asyncio
async def test_p2pk_locktime_with_refund_pubkey(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # receiver side
    # sender side
    garbage_pubkey = PrivateKey().pubkey
    assert garbage_pubkey
    secret_lock = await wallet1.create_p2pk_lock(
        garbage_pubkey.serialize().hex(),  # create lock to unspendable pubkey
        locktime_seconds=2,  # locktime
        tags=Tags([["refund", pubkey_wallet2]]),  # refund pubkey
    )  # sender side
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    send_proofs_copy = copy.deepcopy(send_proofs)
    # receiver side: can't redeem since we used a garbage pubkey
    # and locktime has not passed
    await assert_err(
        wallet2.redeem(send_proofs),
        "",
    )
    await asyncio.sleep(2)
    # we can now redeem because of the refund locktime
    await wallet2.redeem(send_proofs_copy)


@pytest.mark.asyncio
async def test_p2pk_locktime_with_wrong_refund_pubkey(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    await wallet2.create_p2pk_pubkey()  # receiver side
    # sender side
    garbage_pubkey = PrivateKey().pubkey
    garbage_pubkey_2 = PrivateKey().pubkey
    assert garbage_pubkey
    assert garbage_pubkey_2
    secret_lock = await wallet1.create_p2pk_lock(
        garbage_pubkey.serialize().hex(),  # create lock to unspendable pubkey
        locktime_seconds=2,  # locktime
        tags=Tags([["refund", garbage_pubkey_2.serialize().hex()]]),  # refund pubkey
    )  # sender side
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    send_proofs_copy = copy.deepcopy(send_proofs)
    # receiver side: can't redeem since we used a garbage pubkey
    # and locktime has not passed
    await assert_err(
        wallet2.redeem(send_proofs),
        "",
    )
    await asyncio.sleep(2)
    # we still can't redeem it because we used garbage_pubkey_2 as a refund pubkey
    await assert_err(
        wallet2.redeem(send_proofs_copy),
        "",
    )


@pytest.mark.asyncio
async def test_p2pk_locktime_with_second_refund_pubkey(
    wallet1: Wallet, wallet2: Wallet
):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()  # receiver side
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # receiver side
    # sender side
    garbage_pubkey = PrivateKey().pubkey
    assert garbage_pubkey
    secret_lock = await wallet1.create_p2pk_lock(
        garbage_pubkey.serialize().hex(),  # create lock to unspendable pubkey
        locktime_seconds=2,  # locktime
        tags=Tags(
            [["refund", pubkey_wallet2, pubkey_wallet1]]
        ),  # multiple refund pubkeys
    )  # sender side
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    send_proofs_copy = copy.deepcopy(send_proofs)
    # receiver side: can't redeem since we used a garbage pubkey
    # and locktime has not passed
    # WALLET WILL ADD A SIGNATURE BECAUSE IT SEES ITS REFUND PUBKEY (it adds a signature even though the locktime hasn't passed)
    await assert_err(
        wallet1.redeem(send_proofs),
        "Mint Error: signature threshold not met. 0 < 1.",
    )
    await asyncio.sleep(2)
    # we can now redeem because of the refund locktime
    await wallet1.redeem(send_proofs_copy)


@pytest.mark.asyncio
async def test_p2pk_locktime_with_2_of_2_refund_pubkeys(
    wallet1: Wallet, wallet2: Wallet
):
    """Testing the case where we expect a 2-of-2 signature from the refund pubkeys"""
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()  # receiver side
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # receiver side
    # sender side
    garbage_pubkey = PrivateKey().pubkey
    assert garbage_pubkey
    secret_lock = await wallet1.create_p2pk_lock(
        garbage_pubkey.serialize().hex(),  # create lock to unspendable pubkey
        locktime_seconds=2,  # locktime
        tags=Tags(
            [["refund", pubkey_wallet2, pubkey_wallet1], ["n_sigs_refund", "2"]],
        ),  # multiple refund pubkeys
    )  # sender side
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # we need to copy the send_proofs because the redeem function
    # modifies the send_proofs in place by adding the signatures
    send_proofs_copy = copy.deepcopy(send_proofs)
    send_proofs_copy2 = copy.deepcopy(send_proofs)
    # receiver side: can't redeem since we used a garbage pubkey
    # and locktime has not passed
    await assert_err(
        wallet1.redeem(send_proofs),
        "Mint Error: signature threshold not met. 0 < 1.",
    )
    await asyncio.sleep(2)

    # now is the refund time, but we can't redeem it because we need 2 signatures
    await assert_err(
        wallet1.redeem(send_proofs_copy),
        "not enough pubkeys (2) or signatures (1) present for n_sigs (2)",
    )

    # let's add the second signature
    send_proofs_copy2 = wallet2.sign_p2pk_sig_inputs(send_proofs_copy2)

    # now we can redeem it
    await wallet1.redeem(send_proofs_copy2)


@pytest.mark.asyncio
async def test_p2pk_multisig_2_of_2(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    assert pubkey_wallet1 != pubkey_wallet2
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, tags=Tags([["pubkeys", pubkey_wallet1]]), n_sigs=2
    )

    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # add signatures of wallet1
    send_proofs = wallet1.sign_p2pk_sig_inputs(send_proofs)
    # here we add the signatures of wallet2
    await wallet2.redeem(send_proofs)


@pytest.mark.asyncio
async def test_p2pk_multisig_duplicate_signature(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    assert pubkey_wallet1 != pubkey_wallet2
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, tags=Tags([["pubkeys", pubkey_wallet1]]), n_sigs=2
    )

    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # add signatures of wallet2 – this is a duplicate signature
    send_proofs = wallet2.sign_p2pk_sig_inputs(send_proofs)
    # wallet does not add a second signature if it finds its own signature already in the witness
    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: not enough pubkeys (2) or signatures (1) present for n_sigs (2).",
    )


@pytest.mark.asyncio
async def test_p2pk_multisig_two_signatures_same_pubkey(
    wallet1: Wallet, wallet2: Wallet
):
    # we generate two different signatures from the same private key
    mint_quote = await wallet2.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet2.mint(64, quote_id=mint_quote.quote)
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    assert pubkey_wallet1 != pubkey_wallet2
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, tags=Tags([["pubkeys", pubkey_wallet1]]), n_sigs=2
    )

    _, send_proofs = await wallet2.swap_to_send(
        wallet2.proofs, 1, secret_lock=secret_lock
    )
    assert len(send_proofs) == 1
    proof = send_proofs[0]
    # create coincurve private key so we can sign the message
    coincurve_privatekey2 = CoincurvePrivateKey(
        bytes.fromhex(wallet2.private_key.serialize())
    )
    # check if private keys are the same
    assert coincurve_privatekey2.to_hex() == wallet2.private_key.serialize()

    msg = hashlib.sha256(proof.secret.encode("utf-8")).digest()
    coincurve_signature = coincurve_privatekey2.sign_schnorr(msg)

    # add signatures of wallet2 – this is a duplicate signature
    send_proofs = wallet2.sign_p2pk_sig_inputs(send_proofs)

    # the signatures from coincurve are not the same as the ones from wallet2
    assert coincurve_signature.hex() != proof.p2pksigs[0]

    # verify both signatures:
    assert PublicKey(bytes.fromhex(pubkey_wallet2), raw=True).schnorr_verify(
        msg, bytes.fromhex(proof.p2pksigs[0]), None, raw=True
    )
    assert PublicKey(bytes.fromhex(pubkey_wallet2), raw=True).schnorr_verify(
        msg, coincurve_signature, None, raw=True
    )

    # add coincurve signature, and the wallet2 signature will be added during .redeem
    send_proofs[0].witness = P2PKWitness(signatures=[coincurve_signature.hex()]).json()

    # here we add the signatures of wallet2
    await assert_err(
        wallet2.redeem(send_proofs), "Mint Error: signature threshold not met. 1 < 2."
    )


@pytest.mark.asyncio
async def test_p2pk_multisig_quorum_not_met_1_of_2(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    assert pubkey_wallet1 != pubkey_wallet2
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, tags=Tags([["pubkeys", pubkey_wallet1]]), n_sigs=2
    )
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: not enough pubkeys (2) or signatures (1) present for n_sigs (2)",
    )


@pytest.mark.asyncio
async def test_p2pk_multisig_quorum_not_met_2_of_3(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    garbage_pubkey = PrivateKey().pubkey
    assert garbage_pubkey
    assert pubkey_wallet1 != pubkey_wallet2
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2,
        tags=Tags([["pubkeys", pubkey_wallet1, garbage_pubkey.serialize().hex()]]),
        n_sigs=3,
    )
    # create locked proofs
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # add signatures of wallet1
    send_proofs = wallet1.sign_p2pk_sig_inputs(send_proofs)
    # here we add the signatures of wallet2
    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: not enough pubkeys (3) or signatures (2) present for n_sigs (3)",
    )


@pytest.mark.asyncio
async def test_p2pk_multisig_with_duplicate_publickey(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, tags=Tags([["pubkeys", pubkey_wallet2]]), n_sigs=2
    )
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    await assert_err(wallet2.redeem(send_proofs), "Mint Error: pubkeys must be unique.")


@pytest.mark.asyncio
async def test_p2pk_multisig_with_wrong_first_private_key(
    wallet1: Wallet, wallet2: Wallet
):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    wrong_pubklic_key = PrivateKey().pubkey
    assert wrong_pubklic_key
    wrong_public_key_hex = wrong_pubklic_key.serialize().hex()

    assert wrong_public_key_hex != pubkey_wallet2

    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, tags=Tags([["pubkeys", wrong_public_key_hex]]), n_sigs=2
    )
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: not enough pubkeys (2) or signatures (1) present for n_sigs (2).",
    )


def test_tags():
    tags = Tags(
        [["key1", "value1"], ["key2", "value2", "value2_1"], ["key2", "value3"]]
    )
    assert tags.get_tag("key1") == "value1"
    assert tags["key1"] == "value1"
    assert tags.get_tag("key2") == "value2"
    assert tags["key2"] == "value2"
    assert tags.get_tag("key3") is None
    assert tags["key3"] is None
    assert tags.get_tag_all("key2") == ["value2", "value2_1", "value3"]

    # set multiple values of the same key
    tags["key3"] = "value3"
    assert tags.get_tag_all("key3") == ["value3"]
    tags["key4"] = ["value4", "value4_2"]
    assert tags.get_tag_all("key4") == ["value4", "value4_2"]


@pytest.mark.asyncio
async def test_secret_initialized_with_tags(wallet1: Wallet):
    tags = Tags([["locktime", "100"], ["n_sigs", "3"], ["sigflag", "SIG_ALL"]])
    pubkey = PrivateKey().pubkey
    assert pubkey
    secret = await wallet1.create_p2pk_lock(
        data=pubkey.serialize().hex(),
        tags=tags,
    )
    assert secret.locktime == 100
    assert secret.n_sigs == 3
    assert secret.sigflag == SigFlags.SIG_ALL


@pytest.mark.asyncio
async def test_secret_initialized_with_arguments(wallet1: Wallet):
    pubkey = PrivateKey().pubkey
    assert pubkey
    secret = await wallet1.create_p2pk_lock(
        data=pubkey.serialize().hex(),
        locktime_seconds=100,
        n_sigs=3,
        sig_all=True,
    )
    assert secret.locktime
    assert secret.locktime > 1689000000
    assert secret.n_sigs == 3
    assert secret.sigflag == SigFlags.SIG_ALL


@pytest.mark.asyncio
async def test_wallet_verify_is_p2pk_input(wallet1: Wallet1):
    """Test the wallet correctly identifies P2PK inputs."""
    # Mint tokens to the wallet
    mint_quote = await wallet1.request_mint(64)
    await wallet1.get_mint_quote(mint_quote.quote)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create a p2pk lock with wallet's own public key
    pubkey = await wallet1.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey)

    # Use swap_to_send to create p2pk locked proofs
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 32, secret_lock=secret_lock
    )

    # Now get a proof and check if it's detected as P2PK
    proof = send_proofs[0]

    # This tests the internal method that recognizes a P2PK input
    secret = Secret.deserialize(proof.secret)
    assert secret.kind == SecretKind.P2PK.value, "Secret should be of kind P2PK"

    # We can verify that we can convert it to a P2PKSecret
    p2pk_secret = P2PKSecret.from_secret(secret)
    assert p2pk_secret.data == pubkey, "P2PK secret data should contain the pubkey"


@pytest.mark.asyncio
async def test_wallet_verify_p2pk_sigflag_is_sig_inputs(wallet1: Wallet1):
    """Test the wallet correctly identifies the SIG_INPUTS flag."""
    # Mint tokens to the wallet
    mint_quote = await wallet1.request_mint(64)
    await wallet1.get_mint_quote(mint_quote.quote)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create a p2pk lock with SIG_INPUTS (default)
    pubkey = await wallet1.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey, sig_all=False)

    # Use swap_to_send to create p2pk locked proofs
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 32, secret_lock=secret_lock
    )

    # Check if sigflag is correctly identified as SIG_INPUTS
    proof = send_proofs[0]
    secret = Secret.deserialize(proof.secret)
    p2pk_secret = P2PKSecret.from_secret(secret)

    assert p2pk_secret.sigflag == SigFlags.SIG_INPUTS, "Sigflag should be SIG_INPUTS"


@pytest.mark.asyncio
async def test_wallet_verify_p2pk_sigflag_is_sig_all(wallet1: Wallet1):
    """Test the wallet correctly identifies the SIG_ALL flag."""
    # Mint tokens to the wallet
    mint_quote = await wallet1.request_mint(64)
    await wallet1.get_mint_quote(mint_quote.quote)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create a p2pk lock with SIG_ALL
    pubkey = await wallet1.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey, sig_all=True)

    # Use swap_to_send to create p2pk locked proofs
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 32, secret_lock=secret_lock
    )

    # Check if sigflag is correctly identified as SIG_ALL
    proof = send_proofs[0]
    secret = Secret.deserialize(proof.secret)
    p2pk_secret = P2PKSecret.from_secret(secret)

    assert p2pk_secret.sigflag == SigFlags.SIG_ALL, "Sigflag should be SIG_ALL"
