import time
from hashlib import sha256

import pytest
import pytest_asyncio

from cashu.core.base import (
    BlindedMessage,
    HTLCWitness,
    P2PKWitness,
    Proof,
    ProofSpentState,
    ProofState,
)
from cashu.core.crypto.secp import PrivateKey
from cashu.core.errors import TransactionError
from cashu.core.migrations import migrate_databases
from cashu.core.nuts.nut03 import derive_tweak, tweak_outputs
from cashu.core.nuts.nut11 import rerandomized_sigall_digest, sigall_message_to_sign
from cashu.core.p2pk import SigFlags, schnorr_sign
from cashu.core.secret import SecretKind
from cashu.mint import migrations as mint_migrations
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import pay_if_regtest
from tests.mint.spending_conditions_test_helpers import proof, secret_str

GENERATOR = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


@pytest.mark.asyncio
async def test_shared_writer_supports_auth_schema(tmp_path):
    from cashu.core.db import Database
    from cashu.mint.auth import migrations
    from cashu.mint.auth.server import AuthLedger

    db = Database("auth", str(tmp_path))
    await migrate_databases(db, migrations)
    ledger = AuthLedger(
        db=db, seed="test-only-seed", amounts=[1], derivation_path="m/0'/999'/0'"
    )
    await ledger.init_keysets()
    spent = Proof(id=ledger.keyset.id, amount=1, secret="test", C=GENERATOR)
    await ledger.crud.invalidate_proof_with_r(db=db, proof=spent)
    rows = await ledger.crud.get_proofs_used(db=db, Ys=[spent.Y])
    assert len(rows) == 1 and rows[0].rerandomization_r is None
    await db.engine.dispose()


@pytest.mark.asyncio
async def test_legacy_crud_defaults_reject_r_without_calling_writer():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from cashu.mint.crud import LedgerCrud

    legacy = SimpleNamespace(invalidate_proof=AsyncMock())
    assert not LedgerCrud.supports_output_rerandomization(legacy)
    await LedgerCrud.invalidate_proof_with_r(legacy, db=None, proof=None)
    legacy.invalidate_proof.assert_awaited_once_with(
        db=None, proof=None, quote_id=None, conn=None
    )
    with pytest.raises(NotImplementedError):
        await LedgerCrud.invalidate_proof_with_r(
            legacy, db=None, proof=None, rerandomization_r="42" * 32
        )
    assert legacy.invalidate_proof.await_count == 1


def test_absent_recovery_field_is_never_serialized():
    from cashu.core.models.check import PostCheckStateResponse
    from cashu.core.models.swap import PostSwapResponse

    for state in ProofSpentState:
        value = ProofState(Y=GENERATOR, state=state)
        assert "rerandomization_r" not in value.model_dump()
        assert (
            "rerandomization_r"
            not in PostCheckStateResponse(states=[value]).model_dump_json()
        )
    assert "rerandomization_r" not in PostSwapResponse(signatures=[]).model_dump_json()


@pytest.mark.asyncio
async def test_rerandomized_insert_conflict_retries(wallet1, ledger, monkeypatch):
    locked, outputs = await prepare_swap(wallet1, ledger)
    first, second = bytes([0x42]) * 32, bytes([0x43]) * 32
    await ledger._store_blinded_messages(tweak_outputs(outputs, first))
    values = iter([first, second])
    monkeypatch.setattr("cashu.mint.ledger.secrets.token_bytes", lambda _: next(values))

    async def no_precheck(*args, **kwargs):
        return []

    monkeypatch.setattr(ledger, "_check_outputs_pending_or_issued_before", no_precheck)
    _, randomness = await ledger.swap(proofs=locked, outputs=outputs, rerandomize=True)
    assert randomness == second.hex()


@pytest.mark.asyncio
async def test_non_collision_integrity_failure_is_not_retried(
    wallet1, ledger, monkeypatch
):
    from sqlalchemy.exc import IntegrityError

    locked, outputs = await prepare_swap(wallet1, ledger)
    calls = 0

    async def invalid_insert(blinded, keyset, conn):
        nonlocal calls
        calls += 1
        await ledger.crud.store_blinded_message(
            db=ledger.db, amount=None, b_=blinded[0].B_, id=blinded[0].id, conn=conn
        )

    monkeypatch.setattr(ledger, "_store_blinded_messages", invalid_insert)
    with pytest.raises(IntegrityError):
        await ledger.swap(proofs=locked, outputs=outputs, rerandomize=True)
    assert calls == 1
    states = await ledger.db_read.get_proofs_states([p.Y for p in locked])
    assert all(state.unspent and state.rerandomization_r is None for state in states)


@pytest_asyncio.fixture
async def wallet1(ledger: Ledger, tmp_path) -> Wallet:
    wallet = await Wallet.with_db(
        url=SERVER_ENDPOINT, db=str(tmp_path / "wallet"), name="rerandomized-wallet"
    )
    await wallet.load_mint()
    return wallet


def test_rerandomized_vectors_and_domains():
    randomness = bytes([0x42]) * 32
    assert (
        derive_tweak(randomness).hex()
        == "ea8bfdd0711f5a0cdd1377930ed729ca779722a8a5f97156242fcef09965eeb5"
    )
    output = BlindedMessage(id="ks", amount=1, B_=GENERATOR)
    tag = sha256(b"Cashu_SigAllRerandomized_v1").digest()
    digest = rerandomized_sigall_digest([], [output])
    assert (
        digest.hex()
        == "2e96fda9957222af5e1a8e8c581ab12ed8b5180108a554bdb934d661d9bc2c71"
    )
    assert (
        digest
        == sha256(
            tag
            + tag
            + b"\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x21"
            + bytes.fromhex(GENERATOR)
        ).digest()
    )
    tweaked = tweak_outputs([output], randomness)[0]
    assert tweaked.B_ != output.B_
    assert tweaked.amount == output.amount


def test_rerandomized_sigall_excludes_ordinary_signatures():
    signer = PrivateKey()
    raw_secret = secret_str(
        kind=SecretKind.P2PK,
        data=signer.public_key.format().hex(),
        sigflag=SigFlags.SIG_ALL,
    )
    inputs = [proof(raw_secret)]
    # The helper uses an invalid C for ordinary unit tests; override it to
    # construct the valid compressed-point byte format required by framing.
    inputs[0].C = GENERATOR
    outputs = [BlindedMessage(id="ks", amount=1, B_=GENERATOR)]
    inputs[0].witness = P2PKWitness(
        signatures=[
            schnorr_sign(sigall_message_to_sign(inputs, outputs).encode(), signer).hex()
        ]
    ).model_dump_json()
    from cashu.mint.conditions import LedgerSpendingConditions

    conditions = LedgerSpendingConditions()
    with pytest.raises(TransactionError, match="signature threshold not met"):
        conditions._verify_input_output_spending_conditions(
            inputs, outputs, rerandomize=True
        )
    inputs[0].witness = P2PKWitness(
        signatures=[
            signer.sign_schnorr(rerandomized_sigall_digest(inputs, outputs), None).hex()
        ]
    ).model_dump_json()
    assert conditions._verify_input_output_spending_conditions(
        inputs, outputs, rerandomize=True
    )
    with pytest.raises(TransactionError, match="signature threshold not met"):
        conditions._verify_input_output_spending_conditions(inputs, outputs)


def test_rerandomized_htlc_receiver_and_refund_paths():
    from cashu.mint.conditions import LedgerSpendingConditions

    receiver, refund = PrivateKey(), PrivateKey()
    preimage = bytes([0x42]) * 32
    raw_secret = secret_str(
        kind=SecretKind.HTLC,
        data=sha256(preimage).hexdigest(),
        sigflag=SigFlags.SIG_ALL,
        extra_tags=[
            ["pubkeys", receiver.public_key.format().hex()],
            ["refund", refund.public_key.format().hex()],
            ["locktime", str(int(time.time()) - 1)],
        ],
    )
    inputs = [proof(raw_secret)]
    inputs[0].C = GENERATOR
    outputs = [BlindedMessage(id="ks", amount=1, B_=GENERATOR)]
    digest = rerandomized_sigall_digest(inputs, outputs)
    conditions = LedgerSpendingConditions()
    for signer, presented_preimage in [(receiver, preimage.hex()), (refund, "")]:
        inputs[0].witness = HTLCWitness(
            preimage=presented_preimage,
            signatures=[signer.sign_schnorr(digest, None).hex()],
        ).model_dump_json()
        assert conditions._verify_input_output_spending_conditions(
            inputs, outputs, rerandomize=True
        )


def test_sigall_required_and_domains_cannot_mix_for_multisig():
    from cashu.mint.conditions import LedgerSpendingConditions

    cond = LedgerSpendingConditions()
    with pytest.raises(TransactionError, match="requires SIG_ALL"):
        cond._verify_input_output_spending_conditions(
            [proof("ordinary")], [], rerandomize=True
        )
    a, b = PrivateKey(), PrivateKey()
    inputs = [
        proof(
            secret_str(
                kind=SecretKind.P2PK,
                data=a.public_key.format().hex(),
                sigflag=SigFlags.SIG_ALL,
                extra_tags=[["pubkeys", b.public_key.format().hex()], ["n_sigs", "2"]],
            )
        )
    ]
    inputs[0].C = GENERATOR
    outputs = [BlindedMessage(id="ks", amount=1, B_=GENERATOR)]
    ordinary = schnorr_sign(sigall_message_to_sign(inputs, outputs).encode(), a).hex()
    tagged = b.sign_schnorr(rerandomized_sigall_digest(inputs, outputs), None).hex()
    inputs[0].witness = P2PKWitness(signatures=[ordinary, tagged]).model_dump_json()
    with pytest.raises(TransactionError, match="signature threshold not met"):
        cond._verify_input_output_spending_conditions(inputs, outputs, rerandomize=True)
    inputs[0].witness = P2PKWitness(
        signatures=[
            a.sign_schnorr(rerandomized_sigall_digest(inputs, outputs), None).hex(),
            tagged,
        ]
    ).model_dump_json()
    assert cond._verify_input_output_spending_conditions(
        inputs, outputs, rerandomize=True
    )


@pytest.mark.asyncio
async def test_capability_follows_crud(ledger, monkeypatch):
    assert ledger.mint_info.nuts[3] == {"rerandomize": True}
    monkeypatch.setattr(ledger.crud, "supports_output_rerandomization", lambda: False)
    assert 3 not in ledger.mint_info.nuts


@pytest.mark.asyncio
async def test_infinity_exhaustion_releases_inputs(wallet1, ledger, monkeypatch):
    from cashu.core.nuts.nut03 import SECP256K1_ORDER

    locked, outputs = await prepare_swap(wallet1, ledger)
    r = bytes([0x42]) * 32
    negative = SECP256K1_ORDER - int.from_bytes(derive_tweak(r), "big")
    outputs[0].B_ = PrivateKey(negative.to_bytes(32, "big")).public_key.format().hex()
    locked[0].witness = P2PKWitness(
        signatures=[
            wallet1.private_key.sign_schnorr(
                rerandomized_sigall_digest(locked, outputs), None
            ).hex()
        ]
    ).model_dump_json()
    calls = 0

    def random(_):
        nonlocal calls
        calls += 1
        return r

    monkeypatch.setattr("cashu.mint.ledger.secrets.token_bytes", random)
    with pytest.raises(TransactionError, match="could not reserve"):
        await ledger.swap(proofs=locked, outputs=outputs, rerandomize=True)
    assert calls == 16
    states = await ledger.db_read.get_proofs_states([p.Y for p in locked])
    assert all(s.unspent and s.rerandomization_r is None for s in states)


@pytest.mark.asyncio
async def test_rerandomized_swap_commits_recovery_data(
    wallet1: Wallet, ledger: Ledger, monkeypatch
):
    locked, outputs = await prepare_swap(wallet1, ledger)
    committed_events = []
    original_submit = ledger.events.submit

    async def observe(event):
        if isinstance(event, ProofState) and event.rerandomization_r is not None:
            persisted = await ledger.db_read.get_proofs_states([event.Y])
            assert persisted[0].rerandomization_r == event.rerandomization_r
            committed_events.append(event)
        await original_submit(event)

    monkeypatch.setattr(ledger.events, "submit", observe)
    signatures, r = await ledger.swap(proofs=locked, outputs=outputs, rerandomize=True)
    assert len(r) == 64
    assert len(committed_events) == len(locked)
    states = await ledger.db_read.get_proofs_states([p.Y for p in locked])
    assert all(
        state.state == ProofSpentState.spent and state.rerandomization_r == r
        for state in states
    )
    tweaked = tweak_outputs(outputs, bytes.fromhex(r))
    restored_outputs, restored = await ledger.restore(tweaked)
    assert restored_outputs == tweaked
    assert [signature.C_ for signature in restored] == [s.C_ for s in signatures]


async def prepare_swap(
    wallet1: Wallet, ledger: Ledger
) -> tuple[list[Proof], list[BlindedMessage]]:
    quote = await wallet1.request_mint(64)
    await pay_if_regtest(quote.request)
    await ledger.get_mint_quote(quote.quote)
    await wallet1.mint(64, quote_id=quote.quote)
    pubkey = await wallet1.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey, sig_all=True)
    _, locked = await wallet1.swap_to_send(wallet1.proofs, 32, secret_lock=secret_lock)
    secrets, blindings, _ = await wallet1.generate_n_secrets(1)
    outputs, _ = wallet1._construct_outputs([32], secrets, blindings)

    signature = wallet1.private_key.sign_schnorr(
        rerandomized_sigall_digest(locked, outputs), None
    ).hex()
    locked[0].witness = P2PKWitness(signatures=[signature]).model_dump_json()
    return locked, outputs


@pytest.mark.asyncio
async def test_rerandomized_signing_failure_rolls_back(
    wallet1: Wallet, ledger: Ledger, monkeypatch
):
    locked, outputs = await prepare_swap(wallet1, ledger)
    randomness = bytes([0x42]) * 32
    monkeypatch.setattr("cashu.mint.ledger.secrets.token_bytes", lambda n: randomness)

    async def fail_signing(*args, **kwargs):
        raise RuntimeError("test signing failure")

    monkeypatch.setattr(ledger, "_sign_blinded_messages", fail_signing)
    with pytest.raises(RuntimeError, match="test signing failure"):
        await ledger.swap(proofs=locked, outputs=outputs, rerandomize=True)

    states = await ledger.db_read.get_proofs_states([p.Y for p in locked])
    assert all(
        state.state == ProofSpentState.unspent and state.rerandomization_r is None
        for state in states
    )
    tweaked = tweak_outputs(outputs, randomness)
    restored_outputs, restored = await ledger.restore(tweaked)
    assert not restored_outputs and not restored


@pytest.mark.asyncio
async def test_rerandomized_swap_retries_occupied_tweaked_point(
    wallet1: Wallet, ledger: Ledger, monkeypatch
):
    locked, outputs = await prepare_swap(wallet1, ledger)
    randomness = iter([bytes([0x42]) * 32, bytes([0x43]) * 32])
    monkeypatch.setattr(
        "cashu.mint.ledger.secrets.token_bytes", lambda _: next(randomness)
    )
    actual_check = ledger._check_outputs_pending_or_issued_before
    checks = 0

    async def occupied_once(blinded, conn):
        nonlocal checks
        checks += 1
        if checks == 1:
            return [blinded[0].model_copy(update={"C_": GENERATOR})]
        return await actual_check(blinded, conn)

    monkeypatch.setattr(
        ledger, "_check_outputs_pending_or_issued_before", occupied_once
    )
    signatures, r = await ledger.swap(proofs=locked, outputs=outputs, rerandomize=True)
    assert len(signatures) == 1 and r == (bytes([0x43]) * 32).hex()
    assert checks == 2


@pytest.mark.asyncio
async def test_recovery_migration_preserves_existing_spent_proofs(
    wallet1: Wallet, ledger: Ledger
):
    await prepare_swap(wallet1, ledger)
    table = ledger.db.table_with_schema("proofs_used")
    async with ledger.db.connect() as conn:
        original = await conn.fetchone(f"SELECT y FROM {table} LIMIT 1")
        assert original is not None
        await conn.execute(f"ALTER TABLE {table} DROP COLUMN rerandomization_r")
        await conn.execute(
            f"UPDATE {ledger.db.table_with_schema('dbversions')} SET version=40 WHERE db='mint'"
        )
    await migrate_databases(ledger.db, mint_migrations)
    async with ledger.db.connect() as conn:
        migrated = await conn.fetchone(
            f"SELECT rerandomization_r FROM {table} WHERE y=:y", {"y": original["y"]}
        )
    assert migrated is not None and migrated["rerandomization_r"] is None
