import asyncio
import time

import pytest
import pytest_asyncio

from cashu.core.base import DLEQWallet, MeltQuoteState
from cashu.core.crypto import b_dhke
from cashu.core.db import COCKROACH, POSTGRES
from cashu.core.errors import NotAllowedError, TransactionError
from cashu.core.migrations import migrate_databases
from cashu.core.models import (
    PostMeltQuoteRequest,
    PostMintBatchRequest,
    PostMintQuoteRequest,
)
from cashu.core.settings import Settings, settings
from cashu.mint import migrations as mint_migrations
from cashu.mint.ledger import Ledger
from cashu.mint.startup import apply_panic_mode_environment
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import get_real_invoice, is_regtest, pay_if_regtest


@pytest_asyncio.fixture(scope="function")
async def wallet(ledger: Ledger):
    wallet = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet_panic",
        name="wallet_panic",
    )
    await wallet.load_mint()
    quote = await wallet.request_mint(64)
    await pay_if_regtest(quote.request)
    await wallet.mint(64, quote_id=quote.quote)
    yield wallet


@pytest.mark.asyncio
async def test_panic_state_is_persistent_and_blocks_swap(
    wallet: Wallet, ledger: Ledger
):
    state = await ledger.panic.set_state(
        enabled=True, reason="incident test", updated_by="pytest"
    )
    assert state.enabled
    assert (await ledger.panic.get_state()).revision == state.revision

    with pytest.raises(NotAllowedError, match="swapping"):
        await ledger.swap(proofs=wallet.proofs, outputs=[])

    await ledger.panic.set_state(
        enabled=False, reason="incident test complete", updated_by="pytest"
    )


@pytest.mark.asyncio
async def test_panic_verifies_original_blinding_factor(
    wallet: Wallet, ledger: Ledger
):
    proof = wallet.proofs[0]
    assert proof.dleq
    await ledger.panic.set_state(
        enabled=True, reason="verify issuance", updated_by="pytest"
    )

    await ledger.panic.verify_melt_inputs([proof])

    missing = proof.model_copy(update={"dleq": None})
    with pytest.raises(TransactionError, match="requires DLEQ"):
        await ledger.panic.verify_melt_inputs([missing])

    invalid = proof.model_copy(
        update={
            "dleq": DLEQWallet(
                e=proof.dleq.e,
                s=proof.dleq.s,
                r="01".zfill(64),
            )
        }
    )
    with pytest.raises(TransactionError, match="not eligible"):
        await ledger.panic.verify_melt_inputs([invalid])

    await ledger.panic.set_state(
        enabled=False, reason="incident test complete", updated_by="pytest"
    )


@pytest.mark.asyncio
async def test_time_range_selector_expands_and_blacklists_issuance(
    wallet: Wallet, ledger: Ledger
):
    now = int(time.time())
    preview = await ledger.panic.preview_selector(
        issued_from=now - 120,
        issued_until=now + 1,
        reason="known attacker",
        created_by="pytest",
    )
    proof = wallet.proofs[0]
    assert preview.promises

    await ledger.panic.commit_selector(
        preview, reason="known attacker", created_by="pytest"
    )
    await ledger.panic.set_state(
        enabled=True, reason="blacklist test", updated_by="pytest"
    )

    with pytest.raises(TransactionError, match="not eligible"):
        await ledger.panic.verify_melt_inputs([proof])

    await ledger.panic.set_state(
        enabled=False, reason="incident test complete", updated_by="pytest"
    )


@pytest.mark.asyncio
async def test_time_range_selector_expands_complete_mint_operation(
    wallet: Wallet, ledger: Ledger
):
    quote_id = wallet.proofs[0].mint_id
    assert quote_id
    rows = await ledger.crud.get_panic_signed_promises(db=ledger.db)
    operation_rows = [row for row in rows if row["mint_quote"] == quote_id]
    assert len(operation_rows) > 1
    now = int(time.time())
    async with ledger.db.connect() as conn:
        await conn.execute(
            f"""
            UPDATE {ledger.db.table_with_schema("promises")}
            SET signed_at = :outside
            """,
            {"outside": now - 100},
        )
        await conn.execute(
            f"""
            UPDATE {ledger.db.table_with_schema("promises")}
            SET signed_at = :inside
            WHERE b_ = :b_
            """,
            {"inside": now, "b_": operation_rows[0]["b_"]},
        )

    preview = await ledger.panic.preview_selector(
        issued_from=now - 1,
        issued_until=now + 2,
        reason="single row identifies complete operation",
    )
    assert {row["b_"] for row in preview.promises} == {
        row["b_"] for row in operation_rows
    }


@pytest.mark.asyncio
async def test_time_range_selector_expands_complete_swap_operation(
    wallet: Wallet, ledger: Ledger
):
    await wallet.split(wallet.proofs, 8)
    rows = await ledger.crud.get_panic_signed_promises(db=ledger.db)
    swap_ids = {row["swap_id"] for row in rows if row["swap_id"]}
    assert len(swap_ids) == 1
    swap_id = swap_ids.pop()
    operation_rows = [row for row in rows if row["swap_id"] == swap_id]
    assert len(operation_rows) > 1
    now = int(time.time())
    async with ledger.db.connect() as conn:
        await conn.execute(
            f"""
            UPDATE {ledger.db.table_with_schema("promises")}
            SET signed_at = :outside
            """,
            {"outside": now - 100},
        )
        await conn.execute(
            f"""
            UPDATE {ledger.db.table_with_schema("promises")}
            SET signed_at = :inside
            WHERE b_ = :b_
            """,
            {"inside": now, "b_": operation_rows[0]["b_"]},
        )

    preview = await ledger.panic.preview_selector(
        issued_from=now - 1,
        issued_until=now + 2,
        reason="single row identifies complete swap",
    )
    assert {row["b_"] for row in preview.promises} == {
        row["b_"] for row in operation_rows
    }


@pytest.mark.asyncio
async def test_operator_can_blacklist_exact_blinded_message(
    wallet: Wallet, ledger: Ledger
):
    proof = wallet.proofs[0]
    assert proof.dleq
    blinded_message, _ = b_dhke.step1_alice(
        proof.secret,
        blinding_factor=b_dhke.PrivateKey(bytes.fromhex(proof.dleq.r)),
    )
    b_ = blinded_message.format().hex()
    assert (
        await ledger.panic.blacklist_blinded_messages(
            [b_], reason="direct evidence", created_by="pytest"
        )
        == 1
    )
    await ledger.panic.set_state(
        enabled=True, reason="direct blacklist test", updated_by="pytest"
    )
    with pytest.raises(TransactionError, match="not eligible"):
        await ledger.panic.verify_melt_inputs([proof])


@pytest.mark.asyncio
async def test_invalid_selectors_and_blinded_messages(
    wallet: Wallet, ledger: Ledger
):
    with pytest.raises(ValueError, match="greater"):
        await ledger.panic.preview_selector(
            issued_from=10, issued_until=10, reason="invalid"
        )
    with pytest.raises(ValueError, match="greater"):
        await ledger.panic.preview_selector(
            issued_from=-1, issued_until=10, reason="invalid"
        )
    with pytest.raises(ValueError, match="invalid blinded"):
        await ledger.panic.blacklist_blinded_messages(
            ["not-a-point"], reason="invalid"
        )
    unknown, _ = b_dhke.step1_alice("unknown panic output")
    with pytest.raises(ValueError, match="not found"):
        await ledger.panic.blacklist_blinded_messages(
            [unknown.format().hex()], reason="unknown"
        )


@pytest.mark.asyncio
async def test_panic_rejects_all_non_melt_mutations(
    wallet: Wallet, ledger: Ledger
):
    internal_mint_quote = await ledger.mint_quote(
        PostMintQuoteRequest(amount=8, unit="sat")
    )
    internal_melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=internal_mint_quote.request)
    )
    await ledger.panic.set_state(
        enabled=True, reason="mutation rejection test", updated_by="pytest"
    )

    with pytest.raises(NotAllowedError, match="mint quote"):
        await ledger.mint_quote(PostMintQuoteRequest(amount=8, unit="sat"))
    with pytest.raises(NotAllowedError, match="minting"):
        await ledger.mint(outputs=[], quote_id="unused")
    with pytest.raises(NotAllowedError, match="batch minting"):
        await ledger.mint_batch(
            PostMintBatchRequest(quotes=[], outputs=[])
        )
    with pytest.raises(NotAllowedError, match="restoring"):
        await ledger.restore([])
    with pytest.raises(NotAllowedError, match="Internal settlement"):
        await ledger.melt_mint_settle_internally(
            internal_melt_quote, wallet.proofs
        )


@pytest.mark.asyncio
@pytest.mark.skipif(not is_regtest, reason="requires cashu-regtest backend")
async def test_successful_http_melt_in_panic_mode(
    wallet: Wallet, ledger: Ledger
):
    invoice = get_real_invoice(32)["payment_request"]
    quote = await wallet.melt_quote(invoice)
    await ledger.panic.set_state(
        enabled=True, reason="regtest panic melt", updated_by="pytest"
    )
    response = await wallet.melt(
        proofs=wallet.proofs,
        invoice=invoice,
        fee_reserve_sat=quote.fee_reserve,
        quote_id=quote.quote,
    )
    assert response.state == MeltQuoteState.paid.value


def test_environment_json_parsing(monkeypatch):
    monkeypatch.setenv("MINT_PANIC_MODE", "true")
    monkeypatch.setenv(
        "MINT_PANIC_BLACKLIST_BLINDED_MESSAGES", '["02abc", "03def"]'
    )
    monkeypatch.setenv(
        "MINT_PANIC_BLACKLIST_TIME_RANGES",
        '[{"issued_from":100,"issued_until":200,"reason":"incident"}]',
    )
    parsed = Settings(_env_file=None)
    assert parsed.mint_panic_mode is True
    assert parsed.mint_panic_blacklist_blinded_messages == ["02abc", "03def"]
    assert parsed.mint_panic_blacklist_time_ranges == [
        {"issued_from": 100, "issued_until": 200, "reason": "incident"}
    ]


@pytest.mark.asyncio
async def test_concurrent_activation_precedes_pending_transition(
    wallet: Wallet, ledger: Ledger, monkeypatch
):
    mint_quote = await ledger.mint_quote(
        PostMintQuoteRequest(amount=8, unit="sat")
    )
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=mint_quote.request)
    )
    proofs_without_dleq = [
        proof.model_copy(update={"dleq": None}) for proof in wallet.proofs
    ]
    verifier_entered = asyncio.Event()
    continue_verification = asyncio.Event()
    original_verify = ledger.panic.verify_melt_inputs

    async def delayed_verify(*args, **kwargs):
        verifier_entered.set()
        await continue_verification.wait()
        return await original_verify(*args, **kwargs)

    monkeypatch.setattr(ledger.panic, "verify_melt_inputs", delayed_verify)
    melt_task = asyncio.create_task(
        ledger._prepare_melt(
            proofs=proofs_without_dleq,
            quote=melt_quote.quote,
        )
    )
    await verifier_entered.wait()
    await ledger.panic.set_state(
        enabled=True, reason="concurrent activation", updated_by="pytest"
    )
    continue_verification.set()

    with pytest.raises(TransactionError, match="requires DLEQ"):
        await melt_task
    states = await ledger.db_read.get_proofs_states(
        [proof.Y for proof in proofs_without_dleq]
    )
    assert not any(state.pending or state.spent for state in states)


@pytest.mark.asyncio
async def test_panic_migration_preserves_populated_database(
    wallet: Wallet, ledger: Ledger
):
    promises_before = await ledger.crud.get_panic_signed_promises(db=ledger.db)
    assert promises_before
    async with ledger.db.connect() as conn:
        await conn.execute(
            f"DROP TABLE {ledger.db.table_with_schema('panic_blacklisted_promises')}"
        )
        await conn.execute(
            f"DROP TABLE {ledger.db.table_with_schema('panic_blacklist_selectors')}"
        )
        await conn.execute(
            f"DROP TABLE {ledger.db.table_with_schema('panic_state')}"
        )
        await conn.execute(
            f"""
            UPDATE {ledger.db.table_with_schema("dbversions")}
            SET version = 38
            WHERE db = 'mint'
            """
        )

    await migrate_databases(ledger.db, mint_migrations)
    promises_after = await ledger.crud.get_panic_signed_promises(db=ledger.db)
    assert {row["b_"] for row in promises_after} == {
        row["b_"] for row in promises_before
    }
    assert not (await ledger.panic.get_state()).enabled


@pytest.mark.asyncio
async def test_panic_transactions_on_postgres_and_cockroach(
    wallet: Wallet, ledger: Ledger
):
    if ledger.db.type not in {POSTGRES, COCKROACH}:
        pytest.skip("requires PostgreSQL or CockroachDB")

    state = await ledger.panic.set_state(
        enabled=True, reason="server database test", updated_by="pytest"
    )
    assert state.enabled
    with pytest.raises(TransactionError, match="requires DLEQ"):
        await ledger.panic.verify_melt_inputs(
            [wallet.proofs[0].model_copy(update={"dleq": None})]
        )
    disabled = await ledger.panic.set_state(
        enabled=False, reason="server database cleanup", updated_by="pytest"
    )
    assert not disabled.enabled


@pytest.mark.asyncio
async def test_environment_can_override_persistent_panic_state(
    wallet: Wallet, ledger: Ledger
):
    previous_mode = settings.mint_panic_mode
    previous_reason = settings.mint_panic_mode_reason
    previous_operator = settings.mint_panic_mode_operator
    previous_blinded = settings.mint_panic_blacklist_blinded_messages
    previous_time_ranges = settings.mint_panic_blacklist_time_ranges
    try:
        now = int(time.time())
        preview = await ledger.panic.preview_selector(
            issued_from=now - 120,
            issued_until=now + 1,
            reason="environment test",
        )
        assert preview.promises
        settings.mint_panic_mode = True
        settings.mint_panic_mode_reason = "environment test"
        settings.mint_panic_mode_operator = "pytest"
        settings.mint_panic_blacklist_blinded_messages = [
            preview.promises[0]["b_"]
        ]
        settings.mint_panic_blacklist_time_ranges = [
            {
                "issued_from": now - 120,
                "issued_until": now + 1,
                "reason": "environment test window",
            }
        ]
        await apply_panic_mode_environment()
        state = await ledger.panic.get_state()
        assert state.enabled
        assert state.reason == "environment test"

        revision = state.revision
        await apply_panic_mode_environment()
        assert (await ledger.panic.get_state()).revision == revision
        rows = await ledger.db.fetchall(
            f"""
            SELECT selector_id
            FROM {ledger.db.table_with_schema("panic_blacklist_selectors")}
            WHERE selector_id LIKE 'env-%'
            """
        )
        assert len(rows) == 2

        settings.mint_panic_mode = False
        await apply_panic_mode_environment()
        assert not (await ledger.panic.get_state()).enabled
    finally:
        settings.mint_panic_mode = previous_mode
        settings.mint_panic_mode_reason = previous_reason
        settings.mint_panic_mode_operator = previous_operator
        settings.mint_panic_blacklist_blinded_messages = previous_blinded
        settings.mint_panic_blacklist_time_ranges = previous_time_ranges
