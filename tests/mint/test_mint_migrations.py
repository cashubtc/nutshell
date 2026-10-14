import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from cashu.core.base import (
    MeltQuote,
    MeltQuoteState,
    MintKeyset,
    MintQuote,
    MintQuoteState,
    Proof,
)
from cashu.core.crypto.aes import AESCipher
from cashu.core.crypto.b_dhke import step1_alice, step2_bob, step3_alice, verify
from cashu.core.crypto.keys import derive_keyset_id
from cashu.core.crypto.secp import PublicKey
from cashu.core.db import Database
from cashu.core.migrations import migrate_databases
from cashu.core.settings import settings
from cashu.mint import migrations as mint_migrations
from cashu.mint.auth import migrations as auth_migrations
from cashu.mint.crud import LedgerCrudSqlite
from cashu.mint.db.write import DbWriteHelper


@pytest.mark.asyncio
async def test_current_quote_schema_loads_current_fields(tmp_path):
    db = Database("mint", str(tmp_path / "current_quote_schema"))
    await migrate_databases(db, mint_migrations)
    crud = LedgerCrudSqlite()

    async with db.connect() as conn:
        mint_columns = {
            row["name"]
            for row in await conn.fetchall(
                f"PRAGMA table_info({db.table_with_schema('mint_quotes')})"
            )
        }
        melt_columns = {
            row["name"]
            for row in await conn.fetchall(
                f"PRAGMA table_info({db.table_with_schema('melt_quotes')})"
            )
        }

    assert {"amount_paid", "amount_issued", "updated_at"} <= mint_columns
    assert "proof" in melt_columns
    assert "payment_preimage" not in melt_columns
    assert "outputs" not in melt_columns

    mint_quote = MintQuote(
        quote="mint-quote",
        method="bolt11",
        request="mint-request",
        checking_id="mint-checking-id",
        unit="sat",
        amount=100,
        state=MintQuoteState.paid,
        created_time=1000,
        paid_time=1200,
        amount_paid=40,
        amount_issued=20,
        updated_at=1500,
    )
    await crud.store_mint_quote(quote=mint_quote, db=db)
    loaded_mint_quote = await crud.get_mint_quote(quote_id=mint_quote.quote, db=db)
    assert loaded_mint_quote is not None
    assert loaded_mint_quote.amount_paid == 40
    assert loaded_mint_quote.amount_issued == 20
    assert loaded_mint_quote.updated_at == 1500

    melt_quote = MeltQuote(
        quote="melt-quote",
        method="bolt11",
        request="melt-request",
        checking_id="melt-checking-id",
        unit="sat",
        amount=100,
        fee_reserve=2,
        state=MeltQuoteState.paid,
        created_time=1000,
        paid_time=1200,
        fee_paid=1,
        payment_preimage="11" * 32,
        expiry=2000,
    )
    await crud.store_melt_quote(quote=melt_quote, db=db)
    loaded_melt_quote = await crud.get_melt_quote(quote_id=melt_quote.quote, db=db)
    assert loaded_melt_quote is not None
    assert loaded_melt_quote.payment_preimage == "11" * 32

    await db.engine.dispose()


def test_current_mint_quote_postgres_row_loads_accounting_fields():
    row = {
        "quote": "mint-quote",
        "method": "bolt11",
        "request": "mint-request",
        "checking_id": "mint-checking-id",
        "unit": "sat",
        "amount": 100,
        "state": MintQuoteState.paid.value,
        "created_time": datetime.fromtimestamp(1000, timezone.utc),
        "paid_time": datetime.fromtimestamp(1200, timezone.utc),
        "issued_time": None,
        "last_checked": None,
        "pubkey": None,
        "amount_paid": 40,
        "amount_issued": 20,
        "updated_at": datetime.fromtimestamp(1500, timezone.utc),
    }

    quote = MintQuote.from_row(row)  # type: ignore[arg-type]

    assert quote.amount_paid == 40
    assert quote.amount_issued == 20
    assert quote.updated_at == 1500


@pytest.mark.asyncio
async def test_m038_remove_dleq_from_promises(tmp_path):
    db = Database("mint", str(tmp_path / "mint"))
    await migrate_databases(db, mint_migrations)

    async with db.connect() as conn:
        columns = await conn.fetchall(
            f"PRAGMA table_info({db.table_with_schema('promises')})"
        )

    column_names = {column["name"] for column in columns}
    assert "dleq_e" not in column_names
    assert "dleq_s" not in column_names


@pytest.mark.asyncio
async def test_m039_migrates_existing_quote_and_rotates_attempt_nonce(tmp_path):
    db = Database("mint", str(tmp_path / "attempt_migration"))
    crud = LedgerCrudSqlite()
    try:
        async with db.connect() as conn:
            await conn.execute(
                f"""
                CREATE TABLE {db.table_with_schema("melt_quotes")} (
                    quote TEXT PRIMARY KEY,
                    method TEXT NOT NULL,
                    request TEXT NOT NULL,
                    checking_id TEXT NOT NULL,
                    unit TEXT NOT NULL,
                    amount INT NOT NULL,
                    fee_reserve INT NOT NULL,
                    created_time TIMESTAMP,
                    paid_time TIMESTAMP,
                    fee_paid INT,
                    proof TEXT,
                    state TEXT NOT NULL,
                    expiry TIMESTAMP
                )
                """
            )
            await conn.execute(
                f"""
                CREATE TABLE {db.table_with_schema("promises")} (
                    amount INT,
                    b_ TEXT,
                    c_ TEXT,
                    id TEXT,
                    created TIMESTAMP,
                    melt_quote TEXT,
                    order_index INT
                )
                """
            )

        quote = MeltQuote(
            quote="pre-m039-quote",
            method="bolt11",
            request="pre-m039-request",
            checking_id="pre-m039-checking-id",
            unit="sat",
            amount=100,
            fee_reserve=1,
            state=MeltQuoteState.unpaid,
        )
        await crud.store_melt_quote(quote=quote, db=db)

        await mint_migrations.m039_add_attempt_to_melt_quotes(db)

        loaded = await crud.get_melt_quote(quote_id=quote.quote, db=db)
        assert loaded is not None
        assert loaded.attempt == ""

        class Events:
            async def submit(self, event):
                pass

        db_write = DbWriteHelper(
            db=db,
            crud=crud,
            events=Events(),  # type: ignore[arg-type]
            db_read=SimpleNamespace(),  # type: ignore[arg-type]
        )
        first_attempt = await db_write._set_melt_quote_pending(loaded)
        parsed_attempt = uuid.UUID(first_attempt.attempt)
        assert parsed_attempt.version == 7
        assert parsed_attempt.variant == uuid.RFC_4122

        unpaid = await db_write._unset_melt_quote_pending(
            first_attempt, MeltQuoteState.unpaid
        )
        second_attempt = await db_write._set_melt_quote_pending(unpaid)
        assert second_attempt.attempt != first_attempt.attempt
        assert uuid.UUID(second_attempt.attempt).version == 7
    finally:
        await db.engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("table", ["proofs_used", "proofs_pending"])
@pytest.mark.parametrize("version", ["0.11.0", "0.14.0", "0.15.0", "0.21.0"])
async def test_m040_restores_exact_historical_signatures(
    tmp_path, monkeypatch, table, version
):
    db = Database("mint", str(tmp_path / "signature_backfill"))
    crud = LedgerCrudSqlite()
    monkeypatch.setattr(settings, "mint_seed_decryption_key", "test-decryption-key")
    monkeypatch.setattr(settings, "mint_private_key", "different-current-mint-seed")
    try:
        pre_m040 = SimpleNamespace(
            **{
                name: value
                for name, value in vars(mint_migrations).items()
                if name != "m040_reconstruct_missing_proof_signatures"
            }
        )
        await migrate_databases(db, pre_m040)
        keysets = [
            MintKeyset(
                seed="historical-mint-seed",
                derivation_path=f"m/0'/0'/{epoch}'",
                version=version,
                amounts=[1, 8],
                active=False,
            )
            for epoch in (0, 1)
        ]
        if keysets[1].version_tuple < (0, 15):
            assert keysets[1].public_keys is not None
            keysets[1].id = derive_keyset_id(keysets[1].public_keys)
        current = MintKeyset(
            seed="different-current-mint-seed",
            derivation_path="m/0'/0'/2'",
            version="0.21.0",
            amounts=[1, 8],
            active=True,
        )
        for keyset in [*keysets, current]:
            await crud.store_keyset(db=db, keyset=keyset)
        await db.execute(
            "UPDATE keysets SET seed = NULL, encrypted_seed = :seed WHERE id = :id",
            {
                "id": keysets[1].id,
                "seed": AESCipher(settings.mint_seed_decryption_key).encrypt(
                    b"historical-mint-seed"
                ),
            },
        )
        store = (
            crud.invalidate_proof if table == "proofs_used" else crud.set_proof_pending
        )
        expected = {}
        for epoch, keyset in enumerate(keysets):
            for amount in (1, 8):
                secret = f"historical-proof-{epoch}-{amount}-'"
                B_, r = step1_alice(secret)
                C_, _, _ = step2_bob(B_, keyset.private_keys[amount])
                assert keyset.public_keys is not None
                C = step3_alice(C_, r, keyset.public_keys[amount]).format().hex()
                proof = Proof(
                    id=keyset.id, amount=amount, secret=secret, C="", witness="witness"
                )
                await store(db=db, proof=proof)
                expected[secret] = C
        await store(
            db=db,
            proof=Proof(
                id=current.id,
                amount=8,
                secret="already-populated",
                C="preserve-existing-signature",
            ),
        )
        await db.execute(
            f"UPDATE {table} SET y = NULL WHERE secret = :secret",
            {"secret": "historical-proof-0-1-'"},
        )
        before = {
            row["secret"]: dict(row) for row in await db.fetchall(f"SELECT * FROM {table}")
        }
        keysets_before = await db.fetchall("SELECT * FROM keysets ORDER BY id")
        indexes_before = await db.fetchall(f"PRAGMA index_list({table})")
        # Simulate an interruption after the migration created its helper index.
        await db.execute(
            f"CREATE INDEX m040_{table}_empty_c_secret_idx ON {table}(secret) WHERE c = ''"
        )

        await migrate_databases(db, mint_migrations)

        after = {
            row["secret"]: dict(row) for row in await db.fetchall(f"SELECT * FROM {table}")
        }
        assert after == {
            secret: {**row, "c": expected.get(secret, row["c"])}
            for secret, row in before.items()
        }
        assert await db.fetchall("SELECT * FROM keysets ORDER BY id") == keysets_before
        assert await db.fetchall(f"PRAGMA index_list({table})") == indexes_before
        version_row = await db.fetchone("SELECT version FROM dbversions WHERE db = 'mint'")
        assert version_row is not None and version_row["version"] == 40

        await mint_migrations.m040_reconstruct_missing_proof_signatures(db)
        assert {
            row["secret"]: dict(row) for row in await db.fetchall(f"SELECT * FROM {table}")
        } == after
    finally:
        await db.engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("table", ["proofs_used", "proofs_pending"])
@pytest.mark.parametrize("decryption_key", ["", "wrong-decryption-key"])
async def test_m040_leaves_unavailable_keysets_and_denominations_empty(
    tmp_path, monkeypatch, table, decryption_key
):
    db = Database("mint", str(tmp_path / "unavailable_keysets"))
    crud = LedgerCrudSqlite()
    monkeypatch.setattr(settings, "mint_seed_decryption_key", decryption_key)
    try:
        await migrate_databases(db, mint_migrations)
        keysets = [
            MintKeyset(
                seed="test-seed",
                derivation_path=f"m/0'/0'/{epoch}'",
                version="0.21.0",
                amounts=[1, 8],
            )
            for epoch in range(6)
        ]
        for keyset in keysets:
            await crud.store_keyset(db=db, keyset=keyset)
        await db.execute(
            "UPDATE keysets SET seed = NULL WHERE id = :id", {"id": keysets[1].id}
        )
        await db.execute(
            "UPDATE keysets SET seed = NULL, encrypted_seed = :seed WHERE id = :id",
            {
                "id": keysets[2].id,
                "seed": AESCipher("correct-decryption-key").encrypt(b"test-seed"),
            },
        )
        await db.execute(
            "UPDATE keysets SET version = NULL WHERE id = :id", {"id": keysets[3].id}
        )
        await db.execute(
            "UPDATE keysets SET seed = 'wrong-seed' WHERE id = :id",
            {"id": keysets[4].id},
        )
        await db.execute(
            "UPDATE keysets SET amounts = '[1, 2, 8]' WHERE id = :id",
            {"id": keysets[5].id},
        )
        store = (
            crud.invalidate_proof if table == "proofs_used" else crud.set_proof_pending
        )
        for secret, keyset_id, amount in (
            ("unknown-keyset", "deleted-keyset", 8),
            ("empty-keyset-id", "", 8),
            ("missing-keyset-id", "", 8),
            ("missing-seed", keysets[1].id, 8),
            ("unavailable-encrypted-seed", keysets[2].id, 8),
            ("missing-version", keysets[3].id, 8),
            ("mismatched-seed", keysets[4].id, 8),
            ("mismatched-amounts", keysets[5].id, 8),
            ("missing-denomination", keysets[0].id, 3),
        ):
            await store(
                db=db,
                proof=Proof(id=keyset_id, amount=amount, secret=secret, C=""),
            )
        await db.execute(
            f"UPDATE {table} SET id = NULL WHERE secret = 'missing-keyset-id'"
        )
        B_, r = step1_alice("available-proof")
        C_, _, _ = step2_bob(B_, keysets[0].private_keys[8])
        assert keysets[0].public_keys is not None
        C = step3_alice(C_, r, keysets[0].public_keys[8]).format().hex()
        await store(
            db=db,
            proof=Proof(id=keysets[0].id, amount=8, secret="available-proof", C=""),
        )
        before = {
            row["secret"]: dict(row) for row in await db.fetchall(f"SELECT * FROM {table}")
        }

        await mint_migrations.m040_reconstruct_missing_proof_signatures(db)
        await mint_migrations.m040_reconstruct_missing_proof_signatures(db)

        assert {
            row["secret"]: dict(row) for row in await db.fetchall(f"SELECT * FROM {table}")
        } == {
            secret: {**row, "c": C if secret == "available-proof" else ""}
            for secret, row in before.items()
        }
    finally:
        await db.engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("table", ["proofs_used", "proofs_pending"])
@pytest.mark.parametrize("first_amount", [3, 8])
async def test_m040_batches_past_updated_or_unavailable_records(
    ledger, table, first_amount
):
    db = ledger.db
    async with db.connect() as conn:
        for index in range(10001):
            await conn.execute(
                f"INSERT INTO {db.table_with_schema(table)} (id, amount, secret, y, c) "
                "VALUES (:id, :amount, :secret, :y, '')",
                {
                    "id": ledger.keyset.id,
                    "amount": first_amount,
                    "secret": f"unavailable-{index:05d}",
                    "y": f"y-{index}",
                },
            )
    secret = "zz-available-proof"
    B_, r = step1_alice(secret)
    C_, _, _ = step2_bob(B_, ledger.keyset.private_keys[8])
    C = step3_alice(C_, r, ledger.keyset.public_keys[8]).format().hex()
    proof = Proof(id=ledger.keyset.id, amount=8, secret=secret, C="")
    store = (
        ledger.crud.invalidate_proof
        if table == "proofs_used"
        else ledger.crud.set_proof_pending
    )
    await store(db=db, proof=proof)

    await mint_migrations.m040_reconstruct_missing_proof_signatures(db)

    row = await db.fetchone(
        f"SELECT c FROM {db.table_with_schema(table)} WHERE y = :y", {"y": proof.Y}
    )
    assert row is not None and row["c"] == C
    missing = await db.fetchone(
        f"SELECT COUNT(*) AS count FROM {db.table_with_schema(table)} WHERE c = ''"
    )
    assert missing is not None
    assert missing["count"] == (10001 if first_amount == 3 else 0)


@pytest.mark.asyncio
async def test_m040_pending_signature_backfill_preserves_melt_change(ledger):
    db = ledger.db
    keyset = ledger.keyset
    await ledger.crud.bump_keyset_balance(db=db, keyset=keyset, amount=100)
    quotes = []
    proofs = []
    change_inputs = []
    for quote_index in range(2):
        quote = MeltQuote(
            quote=f"backfill-melt-{quote_index}",
            method="bolt11",
            request=f"backfill-request-{quote_index}",
            checking_id=f"backfill-checking-id-{quote_index}",
            unit="sat",
            state=MeltQuoteState.pending,
            amount=10,
            fee_reserve=6,
        )
        await ledger.crud.store_melt_quote(db=db, quote=quote)
        secret = f"backfill-input-{quote_index}"
        B_, r = step1_alice(secret)
        C_, _, _ = step2_bob(B_, keyset.private_keys[16])
        C = step3_alice(C_, r, keyset.public_keys[16]).format().hex()
        proof = Proof(id=keyset.id, amount=16, secret=secret, C=C)
        await ledger.db_write._verify_spent_proofs_and_set_pending(
            proofs=[proof], keysets=ledger.keysets, quote_id=quote.quote
        )
        outputs = []
        for order_index in range(3):
            secret = f"backfill-change-{quote_index}-{order_index}"
            B_, r = step1_alice(secret)
            await ledger.crud.store_blinded_message(
                db=db,
                id=keyset.id,
                amount=1,
                b_=B_.format().hex(),
                melt_id=quote.quote,
                order_index=order_index,
            )
            outputs.append((secret, r, B_.format().hex()))
        quotes.append(quote)
        proofs.append(proof)
        change_inputs.append(outputs)

    await db.execute(
        "UPDATE proofs_pending SET c = '' WHERE y = :y", {"y": proofs[0].Y}
    )
    pending_before = {
        row["y"]: dict(row) for row in await db.fetchall("SELECT * FROM proofs_pending")
    }
    promises_before = [
        dict(row) for row in await db.fetchall("SELECT * FROM promises ORDER BY b_")
    ]
    quotes_before = await db.fetchall("SELECT * FROM melt_quotes ORDER BY quote")
    balance_before, _ = await ledger.crud.get_balance(db=db, keyset=keyset)
    assert all(row["c_"] is None for row in promises_before)

    await mint_migrations.m040_reconstruct_missing_proof_signatures(db)

    assert {
        row["y"]: dict(row) for row in await db.fetchall("SELECT * FROM proofs_pending")
    } == {
        y: {**row, "c": proofs[0].C if y == proofs[0].Y else row["c"]}
        for y, row in pending_before.items()
    }
    assert [
        dict(row) for row in await db.fetchall("SELECT * FROM promises ORDER BY b_")
    ] == promises_before
    assert await db.fetchall("SELECT * FROM melt_quotes ORDER BY quote") == quotes_before
    balance_after, _ = await ledger.crud.get_balance(db=db, keyset=keyset)
    assert balance_after == balance_before
    states = await ledger.db_read.get_proofs_states([proof.Y for proof in proofs])
    assert all(state.pending for state in states)

    settled = await ledger._finalize_melt_paid(quotes[0].quote, fee_paid=1)

    assert settled.paid
    assert settled.change and [promise.amount for promise in settled.change] == [4, 1]
    signed = await ledger.crud.get_blinded_messages_melt_id(
        db=db, melt_id=quotes[0].quote, signed=True
    )
    assert [output.B_ for output in signed] == [
        inputs[2] for inputs in change_inputs[0][:2]
    ]
    for promise, (secret, r, _) in zip(settled.change, change_inputs[0]):
        C = step3_alice(
            PublicKey(bytes.fromhex(promise.C_)), r, keyset.public_keys[promise.amount]
        )
        assert verify(keyset.private_keys[promise.amount], C, secret)
    assert [
        dict(row)
        for row in await db.fetchall(
            "SELECT * FROM promises WHERE melt_quote = :quote ORDER BY b_",
            {"quote": quotes[1].quote},
        )
    ] == [row for row in promises_before if row["melt_quote"] == quotes[1].quote]
    pending_other = await ledger.crud.get_pending_proofs_for_quote(
        db=db, quote_id=quotes[1].quote
    )
    assert [proof.C for proof in pending_other] == [proofs[1].C]
    states = await ledger.db_read.get_proofs_states([proof.Y for proof in proofs])
    assert states[0].spent and states[1].pending
    used = await ledger.crud.get_proofs_used(db=db, Ys=[proofs[0].Y])
    assert [proof.C for proof in used] == [proofs[0].C]
    balance_after, _ = await ledger.crud.get_balance(db=db, keyset=keyset)
    assert balance_after.amount == balance_before.amount + 5
    retry = await ledger._finalize_melt_paid(quotes[0].quote, fee_paid=1)
    assert retry.change == settled.change


@pytest.mark.asyncio
async def test_m029_witness_cleanup(tmp_path):
    db = Database("mint", str(tmp_path / "mig_witness_cleanup"))

    # Ensure schema is at latest so tables exist
    await migrate_databases(db, mint_migrations)

    long_witness = "a" * 1025
    short_witness = "b" * 10

    async with db.connect() as conn:
        # Insert into proofs_used
        await conn.execute(
            f"""
            INSERT INTO {db.table_with_schema("proofs_used")} (amount, id, c, secret, y, witness, created, melt_quote)
            VALUES (1, 'kid', 'c_used_long', 's_used_long', 'y_used_long', :w, {db.timestamp_now}, NULL)
            """,
            {"w": long_witness},
        )
        await conn.execute(
            f"""
            INSERT INTO {db.table_with_schema("proofs_used")} (amount, id, c, secret, y, witness, created, melt_quote)
            VALUES (1, 'kid', 'c_used_short', 's_used_short', 'y_used_short', :w, {db.timestamp_now}, NULL)
            """,
            {"w": short_witness},
        )

        # Insert into proofs_pending
        await conn.execute(
            f"""
            INSERT INTO {db.table_with_schema("proofs_pending")} (amount, id, c, secret, y, witness, created, melt_quote)
            VALUES (1, 'kid', 'c_pend_long', 's_pend_long', 'y_pend_long', :w, {db.timestamp_now}, NULL)
            """,
            {"w": long_witness},
        )
        await conn.execute(
            f"""
            INSERT INTO {db.table_with_schema("proofs_pending")} (amount, id, c, secret, y, witness, created, melt_quote)
            VALUES (1, 'kid', 'c_pend_short', 's_pend_short', 'y_pend_short', :w, {db.timestamp_now}, NULL)
            """,
            {"w": short_witness},
        )

    # Run the migration under test directly
    await mint_migrations.m029_remove_overlong_witness_values(db)

    # Validate cleanup
    async with db.connect() as conn:
        row = await conn.fetchone(
            f"SELECT witness FROM {db.table_with_schema('proofs_used')} WHERE secret = 's_used_long'"
        )
        assert row["witness"] is None

        row = await conn.fetchone(
            f"SELECT witness FROM {db.table_with_schema('proofs_used')} WHERE secret = 's_used_short'"
        )
        assert row["witness"] == short_witness

        row = await conn.fetchone(
            f"SELECT witness FROM {db.table_with_schema('proofs_pending')} WHERE secret = 's_pend_long'"
        )
        assert row["witness"] is None

        row = await conn.fetchone(
            f"SELECT witness FROM {db.table_with_schema('proofs_pending')} WHERE secret = 's_pend_short'"
        )
        assert row["witness"] == short_witness


@pytest.mark.asyncio
async def test_auth_m003_migration():
    import os
    import shutil

    from cashu.core.base import MintKeyset
    from cashu.mint.auth import migrations as auth_migrations
    from cashu.mint.crud import LedgerCrudSqlite

    db_path = "./test_data/mig_auth"
    if os.path.exists(db_path):
        shutil.rmtree(db_path)
    db = Database("auth", db_path)

    # Migrate auth database to latest
    await migrate_databases(db, auth_migrations)

    # Verify that keysets table now has the final_expiry column
    async with db.connect() as conn:
        columns = await conn.fetchall(
            f"PRAGMA table_info({db.table_with_schema('keysets')})"
        )
        assert any(col["name"] == "final_expiry" for col in columns)

    # Verify that we can successfully store a keyset (which uses the final_expiry column)
    crud = LedgerCrudSqlite()
    keyset = MintKeyset(
        seed="test_seed",
        derivation_path="m/0'/0'/0'",
        version="0.15.0",
        final_expiry=123456789,
    )
    await crud.store_keyset(db=db, keyset=keyset)

    # Verify that the keyset was stored and final_expiry value is set correctly
    retrieved = await crud.get_keyset(db=db, id=keyset.id)
    assert len(retrieved) == 1
    assert retrieved[0].final_expiry == 123456789

    # Clean up
    if os.path.exists(db_path):
        shutil.rmtree(db_path)


@pytest.mark.asyncio
async def test_auth_promises_schema_supports_blinded_message_crud(tmp_path):
    """The auth ledger reuses LedgerCrudSqlite, so the auth promises table must carry
    the same columns the mint CRUD writes.
    """
    db = Database("auth", str(tmp_path / "auth_promises_schema"))
    await migrate_databases(db, auth_migrations)
    crud = LedgerCrudSqlite()

    async with db.connect() as conn:
        columns = {
            row["name"]: row
            for row in await conn.fetchall(
                f"PRAGMA table_info({db.table_with_schema('promises')})"
            )
        }

    assert {
        "mint_quote",
        "melt_quote",
        "swap_id",
        "signed_at",
        "order_index",
    } <= columns.keys()
    # blinded messages are stored before they are signed
    assert not columns["c_"]["notnull"]

    b_ = "02" + "aa" * 32
    c_ = "03" + "bb" * 32

    # this is the call AuthLedger.mint_blind_auth makes via Ledger._store_blinded_messages
    await crud.store_blinded_message(db=db, amount=1, b_=b_, id="keyset_id")
    assert await crud.get_blind_signature(db=db, b_=b_) is None

    await crud.update_blinded_message_signature(db=db, amount=1, b_=b_, c_=c_)
    signature = await crud.get_blind_signature(db=db, b_=b_)
    assert signature is not None
    assert signature.C_ == c_
    assert signature.amount == 1
    assert signature.id == "keyset_id"


@pytest.mark.asyncio
async def test_auth_m005_migration_preserves_existing_promises(tmp_path):
    """m005 rebuilds the SQLite promises table, so already-issued auth promises must
    survive the upgrade.
    """
    db = Database("auth", str(tmp_path / "auth_promises_upgrade"))

    # bring the database up to the pre-m005 state
    async with db.connect() as conn:
        await auth_migrations.m000_create_migrations_table(conn)
    for migration in (
        auth_migrations.m001_initial,
        auth_migrations.m002_add_balance_to_keysets_and_log_table,
        auth_migrations.m003_add_final_expiry_to_keysets,
        auth_migrations.m004_remove_dleq_from_promises,
    ):
        await migration(db)

    b_ = "02" + "cc" * 32
    c_ = "03" + "dd" * 32
    async with db.connect() as conn:
        await conn.execute(
            f"""
            INSERT INTO {db.table_with_schema('promises')} (id, amount, b_, c_, created)
            VALUES (:id, :amount, :b_, :c_, :created)
            """,
            {
                "id": "keyset_id",
                "amount": 1,
                "b_": b_,
                "c_": c_,
                "created": db.to_timestamp(db.timestamp_now_str()),
            },
        )

    await auth_migrations.m005_align_promises_with_mint_schema(db)

    signature = await LedgerCrudSqlite().get_blind_signature(db=db, b_=b_)
    assert signature is not None
    assert signature.C_ == c_
    assert signature.amount == 1
    assert signature.id == "keyset_id"
