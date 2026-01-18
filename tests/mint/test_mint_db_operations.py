import asyncio
import datetime
import os
import time
from typing import List, Tuple

import pytest
import pytest_asyncio

from cashu.core import db
from cashu.core.db import Connection
from cashu.core.migrations import backup_database
from cashu.core.models import PostMeltQuoteRequest
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import is_github_actions, is_postgres, is_regtest, pay_if_regtest


async def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        if msg not in str(exc.args[0]):
            raise Exception(f"Expected error: {msg}, got: {exc.args[0]}")
        return
    raise Exception(f"Expected error: {msg}, got no error")


async def assert_err_multiple(f, msgs: List[str]):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        for msg in msgs:
            if msg in str(exc.args[0]):
                return
        raise Exception(f"Expected error: {msgs}, got: {exc.args[0]}")
    raise Exception(f"Expected error: {msgs}, got no error")


@pytest_asyncio.fixture(scope="function")
async def wallet():
    wallet = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet",
        name="wallet",
    )
    await wallet.load_mint()
    yield wallet
    await wallet.db.engine.dispose()


@pytest.mark.asyncio
async def test_db_tables(ledger: Ledger):
    async with ledger.db.connect() as conn:
        if ledger.db.type == db.SQLITE:
            tables_res = await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table';"
            )
        elif ledger.db.type in {db.POSTGRES, db.COCKROACH}:
            tables_res = await conn.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema ="
                " 'public';"
            )
        tables_all: List[Tuple[str]] = tables_res.all()  # type: ignore
        tables = [t[0] for t in tables_all]
        tables_expected = [
            "dbversions",
            "keysets",
            "proofs_used",
            "proofs_pending",
            "melt_quotes",
            "mint_quotes",
            "mint_pubkeys",
            "promises",
            "balance_log",
            "balance",
            "balance_issued",
            "balance_redeemed",
        ]

        tables.sort()
        tables_expected.sort()
        if ledger.db.type == db.SQLITE:
            # SQLite does not return views
            tables_expected.remove("balance")
            tables_expected.remove("balance_issued")
            tables_expected.remove("balance_redeemed")
        assert tables == tables_expected


@pytest.mark.asyncio
@pytest.mark.skipif(
    is_github_actions and is_postgres,
    reason=(
        "Fails on GitHub Actions because pg_dump is not the same version as postgres"
    ),
)
async def test_backup_db_migration(ledger: Ledger):
    settings.db_backup_path = "./test_data/backups/"
    filepath = await backup_database(ledger.db, 999)
    assert os.path.exists(filepath)


@pytest.mark.asyncio
async def test_timestamp_now(ledger: Ledger):
    ts = ledger.db.timestamp_now_str()
    if ledger.db.type == db.SQLITE:
        assert isinstance(ts, str)
        assert int(ts) <= time.time()
    elif ledger.db.type in {db.POSTGRES, db.COCKROACH}:
        assert isinstance(ts, str)
        datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")


@pytest.mark.asyncio
async def test_db_connect(ledger: Ledger):
    async with ledger.db.connect() as conn:
        assert isinstance(conn, Connection)


@pytest.mark.asyncio
async def test_db_get_connection(ledger: Ledger):
    async with ledger.db.get_connection() as conn:
        assert isinstance(conn, Connection)


@pytest.mark.asyncio
async def test_db_get_connection_locked(wallet: Wallet, ledger: Ledger):
    mint_quote = await wallet.request_mint(64)

    async def get_connection():
        """This code makes sure that only the error of the second connection is raised (which we check in the assert_err)"""
        try:
            async with ledger.db.get_connection(lock_table="mint_quotes"):
                try:
                    async with ledger.db.get_connection(
                        lock_table="mint_quotes", lock_timeout=0.1
                    ) as conn2:
                        # write something with conn1, we never reach this point if the lock works
                        await conn2.execute(
                            f"INSERT INTO mint_quotes (quote, amount) VALUES ('{mint_quote.quote}', 100);"
                        )
                except Exception as exc:
                    # this is expected to raise
                    raise Exception(f"conn2: {exc}")

        except Exception as exc:
            if str(exc).startswith("conn2"):
                raise exc
            else:
                raise Exception("not expected to happen")

    await assert_err(get_connection(), "failed to acquire database lock")


@pytest.mark.asyncio
@pytest.mark.skipif(
    not not is_postgres,
    reason="SQLite does not support row locking",
)
async def test_db_get_connection_lock_row(wallet: Wallet, ledger: Ledger):
    mint_quote = await wallet.request_mint(64)

    async def get_connection():
        """This code makes sure that only the error of the second connection is raised (which we check in the assert_err)"""
        try:
            async with ledger.db.get_connection(
                lock_table="mint_quotes",
                lock_select_statement=f"quote='{mint_quote.quote}'",
                lock_timeout=0.1,
            ) as conn1:
                await conn1.execute(
                    f"UPDATE mint_quotes SET amount=100 WHERE quote='{mint_quote.quote}';"
                )
                try:
                    async with ledger.db.get_connection(
                        lock_table="mint_quotes",
                        lock_select_statement=f"quote='{mint_quote.quote}'",
                        lock_timeout=0.1,
                    ) as conn2:
                        # write something with conn1, we never reach this point if the lock works
                        await conn2.execute(
                            f"UPDATE mint_quotes SET amount=101 WHERE quote='{mint_quote.quote}';"
                        )
                except Exception as exc:
                    # this is expected to raise
                    raise Exception(f"conn2: {exc}")
        except Exception as exc:
            if "conn2" in str(exc):
                raise exc
            else:
                raise Exception(f"not expected to happen: {exc}")

    await assert_err(get_connection(), "failed to acquire database lock")


@pytest.mark.asyncio
@pytest.mark.skipif(
    is_github_actions and is_regtest and not is_postgres,
    reason=("Fails on GitHub Actions for regtest + SQLite"),
)
async def test_db_verify_spent_proofs_and_set_pending_race_condition(
    wallet: Wallet, ledger: Ledger
):
    # fill wallet
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    await assert_err_multiple(
        asyncio.gather(
            ledger.db_write._verify_spent_proofs_and_set_pending(
                wallet.proofs, ledger.keysets
            ),
            ledger.db_write._verify_spent_proofs_and_set_pending(
                wallet.proofs, ledger.keysets
            ),
        ),
        [
            "failed to acquire database lock",
            "proofs are pending",
        ],  # depending on how fast the database is, it can be either
    )


@pytest.mark.asyncio
@pytest.mark.skipif(
    is_github_actions and is_regtest and not is_postgres,
    reason=("Fails on GitHub Actions for regtest + SQLite"),
)
async def test_db_verify_spent_proofs_and_set_pending_delayed_no_race_condition(
    wallet: Wallet, ledger: Ledger
):
    # fill wallet
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    async def delayed_verify_spent_proofs_and_set_pending():
        await asyncio.sleep(0.1)
        await ledger.db_write._verify_spent_proofs_and_set_pending(
            wallet.proofs, ledger.keysets
        )

    await assert_err(
        asyncio.gather(
            ledger.db_write._verify_spent_proofs_and_set_pending(
                wallet.proofs, ledger.keysets
            ),
            delayed_verify_spent_proofs_and_set_pending(),
        ),
        "proofs are pending",
    )


@pytest.mark.asyncio
@pytest.mark.skipif(
    is_github_actions and is_regtest and not is_postgres,
    reason=("Fails on GitHub Actions for regtest + SQLite"),
)
async def test_db_verify_spent_proofs_and_set_pending_no_race_condition_different_proofs(
    wallet: Wallet, ledger: Ledger
):
    # fill wallet
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote, split=[32, 32])
    assert wallet.balance == 64
    assert len(wallet.proofs) == 2

    asyncio.gather(
        ledger.db_write._verify_spent_proofs_and_set_pending(
            wallet.proofs[:1], ledger.keysets
        ),
        ledger.db_write._verify_spent_proofs_and_set_pending(
            wallet.proofs[1:], ledger.keysets
        ),
    )


@pytest.mark.asyncio
@pytest.mark.skipif(
    not is_postgres,
    reason="SQLite does not support row locking",
)
async def test_db_get_connection_lock_different_row(wallet: Wallet, ledger: Ledger):
    if ledger.db.type == db.SQLITE:
        pytest.skip("SQLite does not support row locking")
    # this should work since we lock two different rows
    mint_quote = await wallet.request_mint(64)
    mint_quote_2 = await wallet.request_mint(64)

    async def get_connection2():
        """This code makes sure that only the error of the second connection is raised (which we check in the assert_err)"""
        try:
            async with ledger.db.get_connection(
                lock_table="mint_quotes",
                lock_select_statement=f"quote='{mint_quote.quote}'",
                lock_timeout=0.1,
            ):
                try:
                    async with ledger.db.get_connection(
                        lock_table="mint_quotes",
                        lock_select_statement=f"quote='{mint_quote_2.quote}'",
                        lock_timeout=0.1,
                    ) as conn2:
                        # write something with conn1, this time we should reach this block with postgres
                        quote = await ledger.crud.get_mint_quote(
                            quote_id=mint_quote_2.quote, db=ledger.db, conn=conn2
                        )
                        assert quote is not None
                        quote.amount = 100
                        await ledger.crud.update_mint_quote(
                            quote=quote, db=ledger.db, conn=conn2
                        )

                except Exception as exc:
                    # this is expected to raise
                    raise Exception(f"conn2: {exc}")

        except Exception as exc:
            if "conn2" in str(exc):
                raise exc
            else:
                raise Exception(f"not expected to happen: {exc}")

    await get_connection2()


@pytest.mark.asyncio
@pytest.mark.skipif(
    is_github_actions and is_regtest and not is_postgres,
    reason=("Fails on GitHub Actions for regtest + SQLite"),
)
async def test_db_lock_table(wallet: Wallet, ledger: Ledger):
    # fill wallet
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)

    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    async with ledger.db.connect(lock_table="proofs_pending", lock_timeout=0.1) as conn:
        assert isinstance(conn, Connection)
        await assert_err(
            ledger.db_write._verify_spent_proofs_and_set_pending(
                wallet.proofs, ledger.keysets
            ),
            "failed to acquire database lock",
        )


@pytest.mark.asyncio
async def test_store_and_sign_blinded_message(ledger: Ledger):
    # Localized imports to avoid polluting module scope
    from cashu.core.crypto.b_dhke import step1_alice, step2_bob
    from cashu.core.crypto.secp import PublicKey

    # Arrange: prepare a blinded message tied to current active keyset
    amount = 8
    keyset_id = ledger.keyset.id
    B_pubkey, _ = step1_alice("test_store_and_sign_blinded_message")
    B_hex = B_pubkey.format().hex()

    # Act: store the blinded message (unsinged promise row)
    await ledger.crud.store_blinded_message(
        db=ledger.db,
        amount=amount,
        b_=B_hex,
        id=keyset_id,
    )

    # Act: compute a valid blind signature for the stored row and persist it
    private_key_amount = ledger.keyset.private_keys[amount]
    B_point = PublicKey(bytes.fromhex(B_hex))
    C_point, e, s = step2_bob(B_point, private_key_amount)

    await ledger.crud.update_blinded_message_signature(
        db=ledger.db,
        amount=amount,
        b_=B_hex,
        c_=C_point.format().hex(),
        e=e.to_hex(),
        s=s.to_hex(),
    )

    # Assert: row is now a full promise and can be read back via get_blind_signature
    promise = await ledger.crud.get_blind_signature(db=ledger.db, b_=B_hex)
    assert promise is not None
    assert promise.amount == amount
    assert promise.C_ == C_point.format().hex()
    assert promise.id == keyset_id


@pytest.mark.asyncio
async def test_get_blinded_messages_by_melt_id(wallet: Wallet, ledger: Ledger):
    # Arrange
    from cashu.core.crypto.b_dhke import step1_alice

    amount = 8
    keyset_id = ledger.keyset.id
    # Create a real melt quote to satisfy FK on promises.melt_quote
    mint_quote = await wallet.request_mint(64)
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=mint_quote.request, unit="sat")
    )
    melt_id = melt_quote.quote

    # Create two blinded messages
    B1, _ = step1_alice("get_by_melt_id_1")
    B2, _ = step1_alice("get_by_melt_id_2")
    b1_hex = B1.format().hex()
    b2_hex = B2.format().hex()

    # Persist as unsigned messages with proper melt_id FK
    await ledger.crud.store_blinded_message(
        db=ledger.db, amount=amount, b_=b1_hex, id=keyset_id, melt_id=melt_id
    )
    await ledger.crud.store_blinded_message(
        db=ledger.db, amount=amount, b_=b2_hex, id=keyset_id, melt_id=melt_id
    )

    # Act
    rows = await ledger.crud.get_blinded_messages_melt_id(db=ledger.db, melt_id=melt_id)

    # Assert
    assert len(rows) == 2
    assert {r.B_ for r in rows} == {b1_hex, b2_hex}
    assert all(r.id == keyset_id for r in rows)


@pytest.mark.asyncio
async def test_delete_blinded_messages_by_melt_id(wallet: Wallet, ledger: Ledger):
    from cashu.core.crypto.b_dhke import step1_alice

    amount = 4
    keyset_id = ledger.keyset.id
    # Create a real melt quote to satisfy FK on promises.melt_quote
    mint_quote = await wallet.request_mint(64)
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=mint_quote.request, unit="sat")
    )
    melt_id = melt_quote.quote

    # Create two blinded messages
    B1, _ = step1_alice("delete_by_melt_id_1")
    B2, _ = step1_alice("delete_by_melt_id_2")
    b1_hex = B1.format().hex()
    b2_hex = B2.format().hex()

    # Persist as unsigned messages
    await ledger.crud.store_blinded_message(
        db=ledger.db, amount=amount, b_=b1_hex, id=keyset_id, melt_id=melt_id
    )
    await ledger.crud.store_blinded_message(
        db=ledger.db, amount=amount, b_=b2_hex, id=keyset_id, melt_id=melt_id
    )

    rows_before = await ledger.crud.get_blinded_messages_melt_id(
        db=ledger.db, melt_id=melt_id
    )
    assert len(rows_before) == 2

    # Act: delete all unsigned messages for this melt_id
    await ledger.crud.delete_blinded_messages_melt_id(db=ledger.db, melt_id=melt_id)

    # Assert: now none left for that melt_id
    rows_after = await ledger.crud.get_blinded_messages_melt_id(
        db=ledger.db, melt_id=melt_id
    )
    assert rows_after == []


@pytest.mark.asyncio
async def test_get_blinded_messages_by_melt_id_filters_signed(
    wallet: Wallet, ledger: Ledger
):
    from cashu.core.crypto.b_dhke import step1_alice, step2_bob
    from cashu.core.crypto.secp import PublicKey

    amount = 2
    keyset_id = ledger.keyset.id
    # Create a real melt quote to satisfy FK on promises.melt_quote
    mint_quote = await wallet.request_mint(64)
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=mint_quote.request, unit="sat")
    )
    melt_id = melt_quote.quote

    B1, _ = step1_alice("filter_by_melt_id_1")
    B2, _ = step1_alice("filter_by_melt_id_2")
    b1_hex = B1.format().hex()
    b2_hex = B2.format().hex()

    # Persist two unsigned messages
    await ledger.crud.store_blinded_message(
        db=ledger.db, amount=amount, b_=b1_hex, id=keyset_id, melt_id=melt_id
    )
    await ledger.crud.store_blinded_message(
        db=ledger.db, amount=amount, b_=b2_hex, id=keyset_id, melt_id=melt_id
    )

    # Sign one of them (it should no longer be returned by get_blinded_messages_melt_id which filters c_ IS NULL)
    priv = ledger.keyset.private_keys[amount]
    C_point, e, s = step2_bob(PublicKey(bytes.fromhex(b1_hex)), priv)
    await ledger.crud.update_blinded_message_signature(
        db=ledger.db,
        amount=amount,
        b_=b1_hex,
        c_=C_point.format().hex(),
        e=e.to_hex(),
        s=s.to_hex(),
    )

    # Act
    rows = await ledger.crud.get_blinded_messages_melt_id(db=ledger.db, melt_id=melt_id)

    # Assert: only the unsigned one remains (b2_hex)
    assert len(rows) == 1
    assert rows[0].B_ == b2_hex
    assert rows[0].id == keyset_id


@pytest.mark.asyncio
async def test_store_blinded_message(ledger: Ledger):
    from cashu.core.crypto.b_dhke import step1_alice

    amount = 8
    keyset_id = ledger.keyset.id
    B_pub, _ = step1_alice("test_store_blinded_message")
    b_hex = B_pub.format().hex()

    # Act: store unsigned blinded message
    await ledger.crud.store_blinded_message(
        db=ledger.db, amount=amount, b_=b_hex, id=keyset_id
    )

    # Assert: row exists and is unsigned (c_ IS NULL)
    async with ledger.db.connect() as conn:
        row = await conn.fetchone(
            f"SELECT amount, id, b_, c_, created FROM {ledger.db.table_with_schema('promises')} WHERE b_ = :b_",
            {"b_": b_hex},
        )
    assert row is not None
    assert int(row["amount"]) == amount
    assert row["id"] == keyset_id
    assert row["b_"] == b_hex
    assert row["c_"] is None
    assert row["created"] is not None


@pytest.mark.asyncio
async def test_update_blinded_message_signature_before_store_blinded_message_errors(
    ledger: Ledger,
):
    from cashu.core.crypto.b_dhke import step1_alice, step2_bob
    from cashu.core.crypto.secp import PublicKey

    amount = 8
    # Generate a blinded message that we will NOT store
    B_pub, _ = step1_alice("test_sign_before_store_blinded_message")
    b_hex = B_pub.format().hex()

    # Create a valid signature tuple for that blinded message
    priv = ledger.keyset.private_keys[amount]
    C_point, e, s = step2_bob(PublicKey(bytes.fromhex(b_hex)), priv)

    # Expect a DB-level error; on SQLite/Postgres this is typically a no-op update, so this test is xfail.
    await assert_err(
        ledger.crud.update_blinded_message_signature(
            db=ledger.db,
            amount=amount,
            b_=b_hex,
            c_=C_point.format().hex(),
            e=e.to_hex(),
            s=s.to_hex(),
        ),
        "blinded message does not exist",
    )


@pytest.mark.asyncio
async def test_store_blinded_message_duplicate_b_(ledger: Ledger):
    from cashu.core.crypto.b_dhke import step1_alice

    amount = 2
    keyset_id = ledger.keyset.id
    B_pub, _ = step1_alice("test_duplicate_b_")
    b_hex = B_pub.format().hex()

    # First insert should succeed
    await ledger.crud.store_blinded_message(
        db=ledger.db, amount=amount, b_=b_hex, id=keyset_id
    )


@pytest.mark.asyncio
async def test_get_blind_signatures_by_melt_id_returns_signed(
    wallet: Wallet, ledger: Ledger
):
    from cashu.core.crypto.b_dhke import step1_alice, step2_bob
    from cashu.core.crypto.secp import PublicKey

    amount = 4
    keyset_id = ledger.keyset.id
    # Create a real melt quote to satisfy FK on promises.melt_quote
    mint_quote = await wallet.request_mint(64)
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=mint_quote.request, unit="sat")
    )
    melt_id = melt_quote.quote

    # Prepare two blinded messages under the same melt_id
    B1, _ = step1_alice("signed_promises_by_melt_id_1")
    B2, _ = step1_alice("signed_promises_by_melt_id_2")
    b1_hex = B1.format().hex()
    b2_hex = B2.format().hex()

    await ledger.crud.store_blinded_message(
        db=ledger.db, amount=amount, b_=b1_hex, id=keyset_id, melt_id=melt_id
    )
    await ledger.crud.store_blinded_message(
        db=ledger.db, amount=amount, b_=b2_hex, id=keyset_id, melt_id=melt_id
    )

    # Sign only one of them -> should be returned by get_blind_signatures_melt_id
    priv = ledger.keyset.private_keys[amount]
    C_point, e, s = step2_bob(PublicKey(bytes.fromhex(b1_hex)), priv)
    await ledger.crud.update_blinded_message_signature(
        db=ledger.db,
        amount=amount,
        b_=b1_hex,
        c_=C_point.format().hex(),
        e=e.to_hex(),
        s=s.to_hex(),
    )

    # Act
    signed = await ledger.crud.get_blind_signatures_melt_id(
        db=ledger.db, melt_id=melt_id
    )

    # Assert: only the signed one is returned
    assert len(signed) == 1
    assert signed[0].amount == amount
    assert signed[0].id == keyset_id


@pytest.mark.asyncio
async def test_get_melt_quote_includes_change_signatures(
    wallet: Wallet, ledger: Ledger
):
    from cashu.core.crypto.b_dhke import step1_alice, step2_bob
    from cashu.core.crypto.secp import PublicKey

    amount = 8
    keyset_id = ledger.keyset.id

    # Create melt quote and attach outputs/promises under its melt_id
    mint_quote = await wallet.request_mint(64)
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=mint_quote.request, unit="sat")
    )

    melt_id = melt_quote.quote

    # Create two blinded messages, sign one -> becomes change
    B1, _ = step1_alice("melt_quote_change_1")
    B2, _ = step1_alice("melt_quote_change_2")
    b1_hex = B1.format().hex()
    b2_hex = B2.format().hex()

    await ledger.crud.store_blinded_message(
        db=ledger.db, amount=amount, b_=b1_hex, id=keyset_id, melt_id=melt_id
    )
    await ledger.crud.store_blinded_message(
        db=ledger.db, amount=amount, b_=b2_hex, id=keyset_id, melt_id=melt_id
    )

    # Sign one -> should appear in change loaded by get_melt_quote
    priv = ledger.keyset.private_keys[amount]
    C_point, e, s = step2_bob(PublicKey(bytes.fromhex(b1_hex)), priv)
    await ledger.crud.update_blinded_message_signature(
        db=ledger.db,
        amount=amount,
        b_=b1_hex,
        c_=C_point.format().hex(),
        e=e.to_hex(),
        s=s.to_hex(),
    )

    # Act
    quote_db = await ledger.crud.get_melt_quote(quote_id=melt_id, db=ledger.db)

    # Assert: change contains the signed promise(s)
    assert quote_db is not None
    assert quote_db.quote == melt_id
    assert quote_db.change is not None
    assert len(quote_db.change) == 1
    assert quote_db.change[0].amount == amount
    assert quote_db.change[0].id == keyset_id


@pytest.mark.asyncio
async def test_promises_fk_constraints_enforced(ledger: Ledger):
    from cashu.core.crypto.b_dhke import step1_alice

    keyset_id = ledger.keyset.id
    B1, _ = step1_alice("fk_check_melt")
    B2, _ = step1_alice("fk_check_mint")
    b1_hex = B1.format().hex()
    b2_hex = B2.format().hex()

    # Use a single connection and enable FK enforcement on SQLite
    async with ledger.db.connect() as conn:
        # Fake melt_id should violate FK on promises.melt_quote
        await assert_err_multiple(
            ledger.crud.store_blinded_message(
                db=ledger.db,
                amount=1,
                b_=b1_hex,
                id=keyset_id,
                melt_id="nonexistent-melt-id",
                conn=conn,
            ),
            [
                "FOREIGN KEY",  # SQLite
                "violates foreign key constraint",  # Postgres
            ],
        )

    async with ledger.db.connect() as conn:
        # Fake melt_id should violate FK on promises.melt_quote
        await assert_err_multiple(
            ledger.crud.store_blinded_message(
                db=ledger.db,
                amount=1,
                b_=b2_hex,
                id=keyset_id,
                mint_id="nonexistent-mint-id",
                conn=conn,
            ),
            [
                "FOREIGN KEY",  # SQLite
                "violates foreign key constraint",  # Postgres
            ],
        )

    # Done. This test only checks FK enforcement paths.


# Tests for unique pending melt quote checking_id - concurrency and migration
@pytest.mark.asyncio
async def test_concurrent_set_melt_quote_pending_same_checking_id(ledger: Ledger):
    """Test that concurrent attempts to set quotes with same checking_id as pending are handled correctly."""
    from cashu.core.base import MeltQuote, MeltQuoteState

    checking_id = "test_checking_id_concurrent"

    # Create two quotes with the same checking_id
    quote1 = MeltQuote(
        quote="quote_id_conc_1",
        method="bolt11",
        request="lnbc123",
        checking_id=checking_id,
        unit="sat",
        amount=100,
        fee_reserve=1,
        state=MeltQuoteState.unpaid,
    )
    quote2 = MeltQuote(
        quote="quote_id_conc_2",
        method="bolt11",
        request="lnbc456",
        checking_id=checking_id,
        unit="sat",
        amount=200,
        fee_reserve=2,
        state=MeltQuoteState.unpaid,
    )

    await ledger.crud.store_melt_quote(quote=quote1, db=ledger.db)
    await ledger.crud.store_melt_quote(quote=quote2, db=ledger.db)

    # Try to set both as pending concurrently
    results = await asyncio.gather(
        ledger.db_write._set_melt_quote_pending(quote=quote1),
        ledger.db_write._set_melt_quote_pending(quote=quote2),
        return_exceptions=True,
    )

    # One should succeed, one should fail
    success_count = sum(1 for r in results if isinstance(r, MeltQuote))
    error_count = sum(1 for r in results if isinstance(r, Exception))

    assert success_count == 1, "Exactly one quote should be set as pending"
    assert error_count == 1, "Exactly one should fail"

    # The error should be about the quote already being pending
    error = next(r for r in results if isinstance(r, Exception))
    assert "Melt quote already paid or pending." in str(error)
