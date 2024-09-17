import json
import time
from hashlib import sha256
from random import getrandbits, randint, shuffle
from typing import List, Union

import pytest
import pytest_asyncio
from loguru import logger
from secp256k1 import PrivateKey

from cashu.core.base import (
    DiscreetLogContract,
    DlcOutcome,
    DlcPayoutForm,
    DlcPayoutWitness,
    DlcSettlement,
    Proof,
    SCTWitness,
    TokenV4,
    Unit,
)
from cashu.core.crypto.b_dhke import hash_to_curve
from cashu.core.crypto.dlc import (
    list_hash,
    merkle_root,
    merkle_verify,
    sign_dlc,
    sorted_merkle_hash,
    verify_dlc_signature,
)
from cashu.core.errors import CashuError
from cashu.core.models import (
    PostDlcPayoutRequest,
    PostDlcRegistrationRequest,
    PostDlcSettleRequest,
)
from cashu.core.secret import Secret, SecretKind
from cashu.mint.ledger import Ledger
from cashu.wallet.helpers import send
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import pay_if_regtest


@pytest_asyncio.fixture(scope="function")
async def wallet():
    wallet = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet",
        name="wallet",
    )
    await wallet.load_mint()
    yield wallet

async def assert_err(f, msg: Union[str, CashuError]):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        error_message: str = str(exc.args[0])
        if isinstance(msg, CashuError):
            if msg.detail not in error_message:
                raise Exception(
                    f"CashuError. Expected error: {msg.detail}, got: {error_message}"
                )
            return
        if msg not in error_message:
            raise Exception(f"Expected error: {msg}, got: {error_message}")
        return
    raise Exception(f"Expected error: {msg}, got no error")


@pytest.mark.asyncio
async def test_merkle_hash():
    data = [b'\x01', b'\x02']
    target = '25dfd29c09617dcc9852281c030e5b3037a338a4712a42a21c907f259c6412a0'
    h = sorted_merkle_hash(data[1], data[0])
    assert h.hex() == target, f'sorted_merkle_hash test fail: {h.hex() = }'
    h = sorted_merkle_hash(data[0], data[1])
    assert h.hex() == target, f'sorted_merkle_hash reverse test fail: {h.hex() = }'

@pytest.mark.asyncio
async def test_merkle_root():
    target = '0ee849f3b077380cd2cf5c76c6d63bcaa08bea89c1ef9914e5bc86c174417cb3'
    leafs = [sha256(i.to_bytes(32, 'big')).digest() for i in range(16)]
    root, _ = merkle_root(leafs)
    assert root.hex() == target, f"merkle_root test fail: {root.hex() = }"

@pytest.mark.asyncio
async def test_merkle_verify():
    leafs = [sha256(i.to_bytes(32, 'big')).digest() for i in range(16)]
    root, branch_hashes = merkle_root(leafs, 0)
    assert merkle_verify(root, leafs[0], branch_hashes), "merkle_verify test fail"

    leafs = [sha256(i.to_bytes(32, 'big')).digest() for i in range(53)]
    root, branch_hashes = merkle_root(leafs, 0)
    assert merkle_verify(root, leafs[0], branch_hashes), "merkle_verify test fail"

    leafs = [sha256(i.to_bytes(32, 'big')).digest() for i in range(18)]
    shuffle(leafs)
    index = randint(0, len(leafs)-1)
    root, branch_hashes = merkle_root(leafs, index)
    assert merkle_verify(root, leafs[index], branch_hashes), "merkle_verify test fail"

@pytest.mark.asyncio
async def test_dlc_signatures():
    dlc_root = sha256("TESTING".encode()).hexdigest()
    funding_amount = 1000
    privkey = PrivateKey()

    # sign
    signature = sign_dlc(dlc_root, funding_amount, privkey)
    # verify
    assert verify_dlc_signature(dlc_root, funding_amount, signature, privkey.pubkey), \
        "Could not verify funding proof signature"


@pytest.mark.asyncio
async def test_swap_for_dlc_locked(wallet: Wallet):
    invoice = await wallet.request_mint(64)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(64, id=invoice.id)
    root_hash = sha256("TESTING".encode()).hexdigest()
    threshold = 1000
    _, dlc_locked = await wallet.split(minted, 64, dlc_data=(root_hash, threshold))
    print(f"{dlc_locked = }")
    assert wallet.balance == 64
    assert wallet.available_balance == 64
    assert all([Secret.deserialize(p.secret).kind == SecretKind.SCT.value for p in dlc_locked])

@pytest.mark.asyncio
async def test_unlock_dlc_locked(wallet: Wallet):
    invoice = await wallet.request_mint(64)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(64, id=invoice.id)
    root_hash = sha256("TESTING".encode()).hexdigest()
    threshold = 1000
    _, dlc_locked = await wallet.split(minted, 64, dlc_data=(root_hash, threshold))
    _, unlocked = await wallet.split(dlc_locked, 64)
    print(f"{unlocked = }")
    assert wallet.balance == 64
    assert wallet.available_balance == 64
    assert all([bytes.fromhex(p.secret) for p in unlocked])

@pytest.mark.asyncio
async def test_partial_swap_for_dlc_locked(wallet: Wallet):
    invoice = await wallet.request_mint(64)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(64, id=invoice.id)
    root_hash = sha256("TESTING".encode()).hexdigest()
    threshold = 1000
    kept, dlc_locked = await wallet.split(minted, 15, dlc_data=(root_hash, threshold))
    assert wallet.balance == 64
    assert wallet.available_balance == 64
    assert all([bytes.fromhex(p.secret) for p in kept])
    assert all([Secret.deserialize(p.secret).kind == SecretKind.SCT.value for p in dlc_locked])

@pytest.mark.asyncio
async def test_wrong_merkle_proof(wallet: Wallet):
    invoice = await wallet.request_mint(64)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(64, id=invoice.id)
    root_hash = sha256("TESTING".encode()).hexdigest()
    threshold = 1000
    _, dlc_locked = await wallet.split(minted, 64, dlc_data=(root_hash, threshold))

    async def add_sct_witnesses_to_proofs(
        self,
        proofs: List[Proof],
        backup: bool = False
    ) -> List[Proof]:
        """Add SCT witness data to proofs"""
        logger.debug(f"Unlocking {len(proofs)} proofs locked to DLC root {proofs[0].dlc_root}")
        for p in proofs:
            all_spending_conditions = p.all_spending_conditions
            assert all_spending_conditions is not None, "add_sct_witnesses_to_proof: What the duck is going on here"
            leaf_hashes = list_hash(all_spending_conditions)
            # We are assuming the backup secret is the last (and second) entry
            merkle_root_bytes, merkle_proof_bytes = merkle_root(
                leaf_hashes,
                len(leaf_hashes)-1,
            )
            # If this check fails we are in deep trouble
            assert merkle_proof_bytes is not None, "add_sct_witnesses_to_proof: What the duck is going on here"
            #assert merkle_root_bytes.hex() == Secret.deserialize(p.secret).data, "add_sct_witnesses_to_proof: What the duck is going on here"
            backup_secret = all_spending_conditions[-1]
            p.witness = SCTWitness(
                leaf_secret=backup_secret,
                merkle_proof=[m.hex() for m in merkle_proof_bytes]
            ).json()
        return proofs
    # Monkey patching
    saved = Wallet.add_sct_witnesses_to_proofs
    Wallet.add_sct_witnesses_to_proofs = add_sct_witnesses_to_proofs

    for p in dlc_locked:
        p.all_spending_conditions = [p.all_spending_conditions[0]]
    try:
        strerror = "Mint Error: SCT secret merkle proof verification failed (Code: 11000)"
        await assert_err(wallet.split(dlc_locked, 64), strerror)
    finally:
        Wallet.add_sct_witnesses_to_proofs = saved

@pytest.mark.asyncio
async def test_no_witness_data(wallet: Wallet):
    invoice = await wallet.request_mint(64)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(64, id=invoice.id)
    root_hash = sha256("TESTING".encode()).hexdigest()
    threshold = 1000
    _, dlc_locked = await wallet.split(minted, 64, dlc_data=(root_hash, threshold))

    async def add_sct_witnesses_to_proofs(
        self,
        proofs: List[Proof],
        backup: bool = False
    ) -> List[Proof]:
        return proofs
    # Monkey patching
    saved = Wallet.add_sct_witnesses_to_proofs
    Wallet.add_sct_witnesses_to_proofs = add_sct_witnesses_to_proofs

    try:
        strerror = "Mint Error: missing SCT secret witness (Code: 11000)"
        await assert_err(wallet.split(dlc_locked, 64), strerror)
    finally:
        Wallet.add_sct_witnesses_to_proofs = saved

@pytest.mark.asyncio
async def test_cheating1(wallet: Wallet):
    # We pretend we don't know the backup secret
    # and try to spend DLC locked proofs with the DLC secret
    # and its proof of inclusion in the merkle tree
    invoice = await wallet.request_mint(64)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(64, id=invoice.id)
    root_hash = sha256("TESTING".encode()).hexdigest()
    threshold = 1000
    _, dlc_locked = await wallet.split(minted, 64, dlc_data=(root_hash, threshold))

    async def add_sct_witnesses_to_proofs(
        self,
        proofs: List[Proof],
        backup: bool = False
    ) -> List[Proof]:
        """Add SCT witness data to proofs"""
        logger.debug(f"Unlocking {len(proofs)} proofs locked to DLC root {proofs[0].dlc_root}")
        for p in proofs:
            all_spending_conditions = p.all_spending_conditions
            assert all_spending_conditions is not None, "add_sct_witnesses_to_proof: What the duck is going on here"
            leaf_hashes = list_hash(all_spending_conditions)
            # We are pretending we don't know the backup secret
            merkle_root_bytes, merkle_proof_bytes = merkle_root(
                leaf_hashes,
                0,
            )
            assert merkle_proof_bytes is not None, "add_sct_witnesses_to_proof: What the duck is going on here"
            assert merkle_root_bytes.hex() == Secret.deserialize(p.secret).data, "add_sct_witnesses_to_proof: What the duck is going on here"
            dlc_secret = all_spending_conditions[0]
            p.witness = SCTWitness(
                leaf_secret=dlc_secret,
                merkle_proof=[m.hex() for m in merkle_proof_bytes]
            ).json()
        return proofs
    # Monkey patching
    saved = Wallet.add_sct_witnesses_to_proofs
    Wallet.add_sct_witnesses_to_proofs = add_sct_witnesses_to_proofs

    try:
        strerror = "Mint Error: cannot spend secret kind DLC unless funding a DLC (Code: 11000)"
        await assert_err(wallet.split(dlc_locked, 64), strerror)
    finally:
        Wallet.add_sct_witnesses_to_proofs = saved

@pytest.mark.asyncio
async def test_send_funding_token(wallet: Wallet):
    invoice = await wallet.request_mint(64)
    await pay_if_regtest(invoice.bolt11)
    _ = await wallet.mint(64, id=invoice.id)
    available_before = wallet.available_balance
    # Send
    root_hash = sha256("TESTING".encode()).hexdigest()
    available_now, token = await send(wallet, amount=56, lock=None, legacy=False, dlc_data=(root_hash, 1000))
    assert available_now < available_before
    deserialized_token = TokenV4.deserialize(token)
    assert deserialized_token.dlc_root == root_hash
    proofs = deserialized_token.proofs
    assert all([Secret.deserialize(p.secret).kind == SecretKind.SCT.value for p in proofs])
    witnesses = [SCTWitness.from_witness(p.witness) for p in proofs]
    assert all([Secret.deserialize(w.leaf_secret).kind == SecretKind.DLC.value for w in witnesses])

@pytest.mark.asyncio
async def test_registration_vanilla_proofs(wallet: Wallet, ledger: Ledger):
    invoice = await wallet.request_mint(64)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(64, id=invoice.id)

    # Get public key the mint uses to sign
    keysets = await wallet._get_keys()
    active_keyset_for_unit = next(filter(lambda k: k.active and k.unit == Unit["sat"], keysets))
    pubkey = next(iter(active_keyset_for_unit.public_keys.values()))

    dlc_root = sha256("TESTING".encode()).hexdigest()
    dlc = DiscreetLogContract(
        funding_amount=64,
        unit="sat",
        dlc_root=dlc_root,
        inputs=minted,
    )

    request = PostDlcRegistrationRequest(registrations=[dlc])
    response = await ledger.register_dlc(request)
    assert len(response.funded) == 1, "Funding proofs len != 1"

    ack = response.funded[0]
    assert verify_dlc_signature(dlc_root, 64, bytes.fromhex(ack.funding_proof.signature), pubkey),\
        "Could not verify funding proof"

@pytest.mark.asyncio
async def test_registration_dlc_locked_proofs(wallet: Wallet, ledger: Ledger):
    invoice = await wallet.request_mint(64)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(64, id=invoice.id)

    # Get locked proofs
    dlc_root = sha256("TESTING".encode()).hexdigest()
    _, locked = await wallet.split(minted, 64, dlc_data=(dlc_root, 32))
    assert len(_) == 0

    # Add witnesses to proofs
    locked = await wallet.add_sct_witnesses_to_proofs(locked)

    # Get public key the mint uses to sign
    keysets = await wallet._get_keys()
    active_keyset_for_unit = next(filter(lambda k: k.active and k.unit == Unit["sat"], keysets))
    pubkey = next(iter(active_keyset_for_unit.public_keys.values()))

    dlc = DiscreetLogContract(
        funding_amount=64,
        unit="sat",
        dlc_root=dlc_root,
        inputs=locked,
    )

    request = PostDlcRegistrationRequest(registrations=[dlc])
    response = await ledger.register_dlc(request)
    assert response.errors is None, f"Funding proofs error: {response.errors[0].bad_inputs}"
    assert len(response.funded) == 1, "Funding proofs len != 1"

    ack = response.funded[0]
    assert verify_dlc_signature(dlc_root, 64, bytes.fromhex(ack.funding_proof.signature), pubkey), \
        "Could not verify funding proof"


@pytest.mark.asyncio
async def test_registration_threshold(wallet: Wallet, ledger: Ledger):
    invoice = await wallet.request_mint(64)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(64, id=invoice.id)

    # Get locked proofs
    dlc_root = sha256("TESTING".encode()).hexdigest()
    _, locked = await wallet.split(minted, 64, dlc_data=(dlc_root, 128))
    assert len(_) == 0

    # Add witnesses to proofs
    locked = await wallet.add_sct_witnesses_to_proofs(locked)

    dlc = DiscreetLogContract(
        funding_amount=64,
        unit="sat",
        dlc_root=dlc_root,
        inputs=locked,
    )

    request = PostDlcRegistrationRequest(registrations=[dlc])
    response = await ledger.register_dlc(request)
    assert response.errors and response.errors[0].bad_inputs[0].detail == "DLC funding_amount does not satisfy DLC secret threshold tag"

@pytest.mark.asyncio
async def test_fund_same_dlc_twice(wallet: Wallet, ledger: Ledger):
    invoice = await wallet.request_mint(128)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(128, id=invoice.id)

    dlc_root = sha256("TESTING".encode()).hexdigest()
    proofs2, proofs1 = await wallet.split(minted, 64)

    dlc1 = DiscreetLogContract(
        funding_amount=64,
        unit="sat",
        dlc_root=dlc_root,
        inputs=proofs1,
    )
    dlc2 = DiscreetLogContract(
        funding_amount=64,
        unit="sat",
        dlc_root=dlc_root,
        inputs=proofs2,
    )
    request = PostDlcRegistrationRequest(registrations=[dlc1])
    response = await ledger.register_dlc(request)
    assert response.errors is None, f"Funding proofs error: {response.errors[0].bad_inputs}"
    request = PostDlcRegistrationRequest(registrations=[dlc2])
    response = await ledger.register_dlc(request)
    assert response.errors and response.errors[0].bad_inputs[0].detail == "dlc already registered"

@pytest.mark.asyncio
async def test_fund_same_dlc_twice_same_batch(wallet: Wallet, ledger: Ledger):
    invoice = await wallet.request_mint(128)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(128, id=invoice.id)

    dlc_root = sha256("TESTING".encode()).hexdigest()
    proofs2, proofs1 = await wallet.split(minted, 64)

    dlc1 = DiscreetLogContract(
        funding_amount=64,
        unit="sat",
        dlc_root=dlc_root,
        inputs=proofs1,
    )
    dlc2 = DiscreetLogContract(
        funding_amount=64,
        unit="sat",
        dlc_root=dlc_root,
        inputs=proofs2,
    )
    request = PostDlcRegistrationRequest(registrations=[dlc1, dlc2])
    response = await ledger.register_dlc(request)
    assert response.errors and len(response.errors) == 1, f"Funding proofs error: {response.errors[0].bad_inputs}"

@pytest.mark.asyncio
async def test_get_dlc_status(wallet: Wallet, ledger: Ledger):
    invoice = await wallet.request_mint(128)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(128, id=invoice.id)

    dlc_root = sha256("TESTING".encode()).hexdigest()
    dlc1 = DiscreetLogContract(
        funding_amount=64,
        unit="sat",
        dlc_root=dlc_root,
        inputs=minted,
    )
    request = PostDlcRegistrationRequest(registrations=[dlc1])
    response = await ledger.register_dlc(request)
    assert response.errors is None, f"Funding proofs error: {response.errors[0].bad_inputs}"
    response = await ledger.status_dlc(dlc_root)
    assert response.debts is None and \
           response.settled is False and \
           response.funding_amount == 128 and \
           response.unit == "sat", \
        "GetDlcStatusResponse with unexpected fields"

privkey1 = PrivateKey()
privkey2 = PrivateKey()
pubkey1 = privkey1.pubkey.serialize(True).hex()
pubkey2 = privkey2.pubkey.serialize(True).hex()

payouts = [
    # pubkey 1 wins
    {
        pubkey1: 1,
        pubkey2: 0
    },
    # pubkey 2 wins
    {
        pubkey1: 0,
        pubkey2: 1
    },
    # timeout
    {
        pubkey1: 1,
        pubkey2: 1
    }
]

'''
We are not blinding the locking points and attestation secrets, but it's equivalent.
'''
@pytest.mark.asyncio
async def test_settle_dlc(wallet: Wallet, ledger: Ledger):
    invoice = await wallet.request_mint(128)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(128, id=invoice.id)

    timeout = int(time.time()) + 3600               # TIMEOUT chosen by the parties
    K_t = hash_to_curve(timeout.to_bytes(8, 'big')) # TIMEOUT locking point
    secret1 = getrandbits(256).to_bytes(32, 'big')  # ORACLE secret attestation
    K_1 = PrivateKey(secret1, raw=True).pubkey      # ORACLE locking point
    secret2 = getrandbits(256).to_bytes(32, 'big')  # ORACLE secret attestation
    K_2 = PrivateKey(secret2, raw=True).pubkey      # ORACLE locking point

    leaves = [
        sha256(K_1.serialize(True)+json.dumps(payouts[0]).encode()).digest(),
        sha256(K_2.serialize(True)+json.dumps(payouts[1]).encode()).digest(),
        sha256(K_t.serialize(True)+json.dumps(payouts[2]).encode()).digest(),
    ]

    # We try to settle the second outcome (pubkey2 wins)
    dlc_root, merkle_proof = merkle_root(leaves, 1)
    assert merkle_verify(dlc_root, leaves[1], merkle_proof)

    dlc = DiscreetLogContract(
        funding_amount=127,
        unit="sat",
        dlc_root=dlc_root.hex(),
        inputs=minted,
    )

    request = PostDlcRegistrationRequest(registrations=[dlc])
    response = await ledger.register_dlc(request)
    assert response.errors is None, f"Funding proofs error: {response.errors[0].bad_inputs}"

    outcome = DlcOutcome(
        P=json.dumps(payouts[1]),
        k=secret2.hex()
    )
    merkle_proof_hex = [p.hex() for p in merkle_proof]
    settlement = DlcSettlement(
        dlc_root=dlc_root.hex(),
        outcome=outcome,
        merkle_proof=merkle_proof_hex,
    )
    request = PostDlcSettleRequest(settlements=[settlement])
    response = await ledger.settle_dlc(request)

    assert response.errors is None, f"Response contains errors: {response.errors}"
    assert len(response.settled) > 0, "Response contains zero settlements."

@pytest.mark.asyncio
async def test_settle_dlc_timeout(wallet: Wallet, ledger: Ledger):
    invoice = await wallet.request_mint(128)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(128, id=invoice.id)

    timeout = int(time.time())             # TIMEOUT chosen by the parties
    K_t = hash_to_curve(timeout.to_bytes(8, 'big')) # TIMEOUT locking point
    secret1 = getrandbits(256).to_bytes(32, 'big')  # ORACLE secret attestation
    K_1 = PrivateKey(secret1, raw=True).pubkey      # ORACLE locking point
    secret2 = getrandbits(256).to_bytes(32, 'big')  # ORACLE secret attestation
    K_2 = PrivateKey(secret2, raw=True).pubkey      # ORACLE locking point

    leaves = [
        sha256(K_1.serialize(True)+json.dumps(payouts[0]).encode()).digest(),
        sha256(K_2.serialize(True)+json.dumps(payouts[1]).encode()).digest(),
        sha256(K_t.serialize(True)+json.dumps(payouts[2]).encode()).digest(),
    ]

    # We try the timeout settlement
    dlc_root, merkle_proof = merkle_root(leaves, 2)
    assert merkle_verify(dlc_root, leaves[2], merkle_proof)

    dlc = DiscreetLogContract(
        funding_amount=127,
        unit="sat",
        dlc_root=dlc_root.hex(),
        inputs=minted,
    )

    request = PostDlcRegistrationRequest(registrations=[dlc])
    response = await ledger.register_dlc(request)
    assert response.errors is None, f"Funding proofs error: {response.errors[0].bad_inputs}"

    outcome = DlcOutcome(
        P=json.dumps(payouts[2]),
        t=timeout
    )
    merkle_proof_hex = [p.hex() for p in merkle_proof]
    settlement = DlcSettlement(
        dlc_root=dlc_root.hex(),
        outcome=outcome,
        merkle_proof=merkle_proof_hex,
    )
    request = PostDlcSettleRequest(settlements=[settlement])
    response = await ledger.settle_dlc(request)

    assert response.errors is None, f"Response contains errors: {response.errors}"
    assert len(response.settled) > 0, "Response contains zero settlements."

@pytest.mark.asyncio
async def test_payout_dlc(wallet: Wallet, ledger: Ledger):
    invoice = await wallet.request_mint(128)
    await pay_if_regtest(invoice.bolt11)
    minted = await wallet.mint(128, id=invoice.id)

    # ORACLE GENERATES
    k1 = PrivateKey()  # ORACLE secret attestation for event `x` (nobody knows this)
    k2 = PrivateKey()  # ORACLE secret attestation for event `y` (nobody knows this)

    # Choose blinding factor `b`
    # This is common knownledge to all parties involved with the DLC (except the mint ofc)
    b = PrivateKey()

    timeout = int(time.time())                                # TIMEOUT chosen by the parties
    K_t = hash_to_curve(timeout.to_bytes(8, 'big'))           # TIMEOUT locking point (no blinding)
    K_1 = k1.pubkey + b.pubkey                                # Blinded locking point
    K_2 = k2.pubkey + b.pubkey                                # Blinded locking point

    leaves = [
        sha256(K_1.serialize(True)+json.dumps(payouts[0]).encode()).digest(),
        sha256(K_2.serialize(True)+json.dumps(payouts[1]).encode()).digest(),
        sha256(K_t.serialize(True)+json.dumps(payouts[2]).encode()).digest(),
    ]
    
    # Funding (Registering) the contract

    # TUPLE: first is the dlc root, second is the merkle proof for the leaf we required
    dlc_root, merkle_proof = merkle_root(leaves, 0)
    assert merkle_verify(dlc_root, leaves[0], merkle_proof)
    dlc = DiscreetLogContract(
        funding_amount=127,
        unit="sat",
        dlc_root=dlc_root.hex(),
        inputs=minted,
    )

    request = PostDlcRegistrationRequest(registrations=[dlc])
    response = await ledger.register_dlc(request)
    assert response.errors is None, f"Funding proofs error: {response.errors[0].bad_inputs}"

    # NOW suppose event `x` occurs:
    #   * Oracle reveals `secret1`
    #   * We blind `secret1` with our blinding factor `b`
    #   * Anybody can settle the DLC
    print(f"{len(b.private_key) = }")
    k = k1.tweak_add(b.private_key)
    outcome = DlcOutcome(
        P=json.dumps(payouts[0]),
        k=k.hex(),
    )
    merkle_proof_hex = [p.hex() for p in merkle_proof]
    settlement = DlcSettlement(
        dlc_root=dlc_root.hex(),
        outcome=outcome,
        merkle_proof=merkle_proof_hex,
    )
    request = PostDlcSettleRequest(settlements=[settlement])
    response = await ledger.settle_dlc(request)

    assert response.errors is None, f"Response contains errors: {response.errors}"
    assert len(response.settled) > 0, "Response contains zero settlements."

    # CLAIMING our victorious payout
    # Generating outputs
    amounts = [128]
    secrets, rs, dpaths = await wallet.generate_n_secrets(
        len(amounts), skip_bump=True
    )
    outputs, rs = wallet._construct_outputs(amounts, secrets, rs)

    payout = DlcPayoutForm(
        dlc_root=dlc_root.hex(),
        pubkey=pubkey1,
        outputs=outputs,
        witness=DlcPayoutWitness(
            signature=privkey1.schnorr_sign(dlc_root, None, raw=True).hex()
        )
    )

    request = PostDlcPayoutRequest(payouts=[payout])
    response = await ledger.payout_dlc(request)

    assert response.errors is None, f"Payout failed: {response.errors[0].detail}"
    assert len(response.paid) > 0, "Payout failed: paid list is empty"
    assert response.paid[0].dlc_root == dlc_root.hex()
    assert len(response.paid[0].outputs) == len(amounts)

    proofs = await wallet._construct_proofs(response.paid[0].outputs, secrets, rs, dpaths)