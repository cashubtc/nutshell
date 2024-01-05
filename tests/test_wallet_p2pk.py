import asyncio
import copy
import json
import secrets
from typing import List

import pytest
import pytest_asyncio

from cashu.core.base import Proof, SpentState
from cashu.core.crypto.secp import PrivateKey, PublicKey
from cashu.core.migrations import migrate_databases
from cashu.core.p2pk import SigFlags
from cashu.core.secret import Tags
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
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)
    pubkey = await wallet1.create_p2pk_pubkey()
    PublicKey(bytes.fromhex(pubkey), raw=True)


@pytest.mark.asyncio
async def test_p2pk(wallet1: Wallet, wallet2: Wallet):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(pubkey_wallet2)  # sender side
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    await wallet2.redeem(send_proofs)

    proof_states = await wallet2.check_proof_state(send_proofs)
    assert all([p.state == SpentState.spent for p in proof_states.states])

    if not is_deprecated_api_only:
        for state in proof_states.states:
            assert state.witness is not None
            witness_obj = json.loads(state.witness)
            assert len(witness_obj["signatures"]) == 1
            assert len(witness_obj["signatures"][0]) == 128


@pytest.mark.asyncio
async def test_p2pk_sig_all(wallet1: Wallet, wallet2: Wallet):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, sig_all=True
    )  # sender side
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    await wallet2.redeem(send_proofs)


@pytest.mark.asyncio
async def test_p2pk_receive_with_wrong_private_key(wallet1: Wallet, wallet2: Wallet):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # receiver side
    # sender side
    secret_lock = await wallet1.create_p2pk_lock(pubkey_wallet2)  # sender side
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # receiver side: wrong private key
    wallet2.private_key = PrivateKey()  # wrong private key
    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: no valid signature provided for input.",
    )


@pytest.mark.asyncio
async def test_p2pk_short_locktime_receive_with_wrong_private_key(
    wallet1: Wallet, wallet2: Wallet
):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # receiver side
    # sender side
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, locktime_seconds=2
    )  # sender side
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # receiver side: wrong private key
    wallet2.private_key = PrivateKey()  # wrong private key
    send_proofs_copy = copy.deepcopy(send_proofs)
    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: no valid signature provided for input.",
    )
    await asyncio.sleep(2)
    # should succeed because even with the wrong private key we
    # can redeem the tokens after the locktime
    await wallet2.redeem(send_proofs_copy)


@pytest.mark.asyncio
async def test_p2pk_locktime_with_refund_pubkey(wallet1: Wallet, wallet2: Wallet):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # receiver side
    # sender side
    garbage_pubkey = PrivateKey().pubkey
    assert garbage_pubkey
    secret_lock = await wallet1.create_p2pk_lock(
        garbage_pubkey.serialize().hex(),  # create lock to unspendable pubkey
        locktime_seconds=2,  # locktime
        tags=Tags([["refund", pubkey_wallet2]]),  # refund pubkey
    )  # sender side
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    send_proofs_copy = copy.deepcopy(send_proofs)
    # receiver side: can't redeem since we used a garbage pubkey
    # and locktime has not passed
    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: no valid signature provided for input.",
    )
    await asyncio.sleep(2)
    # we can now redeem because of the refund locktime
    await wallet2.redeem(send_proofs_copy)


@pytest.mark.asyncio
async def test_p2pk_locktime_with_wrong_refund_pubkey(wallet1: Wallet, wallet2: Wallet):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)
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
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    send_proofs_copy = copy.deepcopy(send_proofs)
    # receiver side: can't redeem since we used a garbage pubkey
    # and locktime has not passed
    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: no valid signature provided for input.",
    )
    await asyncio.sleep(2)
    # we still can't redeem it because we used garbage_pubkey_2 as a refund pubkey
    await assert_err(
        wallet2.redeem(send_proofs_copy),
        "Mint Error: no valid signature provided for input.",
    )


@pytest.mark.asyncio
async def test_p2pk_locktime_with_second_refund_pubkey(
    wallet1: Wallet, wallet2: Wallet
):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()  # receiver side
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # receiver side
    # sender side
    garbage_pubkey = PrivateKey().pubkey
    assert garbage_pubkey
    secret_lock = await wallet1.create_p2pk_lock(
        garbage_pubkey.serialize().hex(),  # create lock to unspendable pubkey
        locktime_seconds=2,  # locktime
        tags=Tags([
            ["refund", pubkey_wallet2, pubkey_wallet1]
        ]),  # multiple refund pubkeys
    )  # sender side
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    send_proofs_copy = copy.deepcopy(send_proofs)
    # receiver side: can't redeem since we used a garbage pubkey
    # and locktime has not passed
    await assert_err(
        wallet1.redeem(send_proofs),
        "Mint Error: no valid signature provided for input.",
    )
    await asyncio.sleep(2)
    # we can now redeem because of the refund locktime
    await wallet1.redeem(send_proofs_copy)


@pytest.mark.asyncio
async def test_p2pk_multisig_2_of_2(wallet1: Wallet, wallet2: Wallet):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    assert pubkey_wallet1 != pubkey_wallet2
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, tags=Tags([["pubkeys", pubkey_wallet1]]), n_sigs=2
    )

    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # add signatures of wallet1
    send_proofs = await wallet1.add_p2pk_witnesses_to_proofs(send_proofs)
    # here we add the signatures of wallet2
    await wallet2.redeem(send_proofs)


@pytest.mark.asyncio
async def test_p2pk_multisig_duplicate_signature(wallet1: Wallet, wallet2: Wallet):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    assert pubkey_wallet1 != pubkey_wallet2
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, tags=Tags([["pubkeys", pubkey_wallet1]]), n_sigs=2
    )

    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # add signatures of wallet2 – this is a duplicate signature
    send_proofs = await wallet2.add_p2pk_witnesses_to_proofs(send_proofs)
    # here we add the signatures of wallet2
    await assert_err(
        wallet2.redeem(send_proofs), "Mint Error: p2pk signatures must be unique."
    )


@pytest.mark.asyncio
async def test_p2pk_multisig_quorum_not_met_1_of_2(wallet1: Wallet, wallet2: Wallet):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    assert pubkey_wallet1 != pubkey_wallet2
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, tags=Tags([["pubkeys", pubkey_wallet1]]), n_sigs=2
    )
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: not enough signatures provided: 1 < 2.",
    )


@pytest.mark.asyncio
async def test_p2pk_multisig_quorum_not_met_2_of_3(wallet1: Wallet, wallet2: Wallet):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    assert pubkey_wallet1 != pubkey_wallet2
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, tags=Tags([["pubkeys", pubkey_wallet1]]), n_sigs=3
    )

    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # add signatures of wallet1
    send_proofs = await wallet1.add_p2pk_witnesses_to_proofs(send_proofs)
    # here we add the signatures of wallet2
    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: not enough signatures provided: 2 < 3.",
    )


@pytest.mark.asyncio
async def test_p2pk_multisig_with_duplicate_publickey(wallet1: Wallet, wallet2: Wallet):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, tags=Tags([["pubkeys", pubkey_wallet2]]), n_sigs=2
    )
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    await assert_err(wallet2.redeem(send_proofs), "Mint Error: pubkeys must be unique.")


@pytest.mark.asyncio
async def test_p2pk_multisig_with_wrong_first_private_key(
    wallet1: Wallet, wallet2: Wallet
):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)
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
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # add signatures of wallet1
    send_proofs = await wallet1.add_p2pk_witnesses_to_proofs(send_proofs)
    await assert_err(
        wallet2.redeem(send_proofs), "Mint Error: signature threshold not met. 1 < 2."
    )


def test_tags():
    tags = Tags([
        ["key1", "value1"], ["key2", "value2", "value2_1"], ["key2", "value3"]
    ])
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
        pubkey=pubkey.serialize().hex(),
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
        pubkey=pubkey.serialize().hex(),
        locktime_seconds=100,
        n_sigs=3,
        sig_all=True,
    )
    assert secret.locktime
    assert secret.locktime > 1689000000
    assert secret.n_sigs == 3
    assert secret.sigflag == SigFlags.SIG_ALL
