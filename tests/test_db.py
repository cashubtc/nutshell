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
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import is_github_actions, is_postgres, pay_if_regtest


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
        ]
        for table in tables_expected:
            assert table in tables


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
    not settings.mint_database.startswith("postgres"),
    reason="SQLite does not support row locking ",
)
async def test_db_get_connection_lock_row(wallet: Wallet, ledger: Ledger):
    if ledger.db.type == db.SQLITE:
        pytest.skip("SQLite does not support row locking")

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
            ledger.db_write._verify_spent_proofs_and_set_pending(wallet.proofs),
            ledger.db_write._verify_spent_proofs_and_set_pending(wallet.proofs),
        ),
        [
            "failed to acquire database lock",
            "proofs are pending",
        ],  # depending on how fast the database is, it can be either
    )


@pytest.mark.asyncio
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
        await ledger.db_write._verify_spent_proofs_and_set_pending(wallet.proofs)

    await assert_err(
        asyncio.gather(
            ledger.db_write._verify_spent_proofs_and_set_pending(wallet.proofs),
            delayed_verify_spent_proofs_and_set_pending(),
        ),
        "proofs are pending",
    )


@pytest.mark.asyncio
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
        ledger.db_write._verify_spent_proofs_and_set_pending(wallet.proofs[:1]),
        ledger.db_write._verify_spent_proofs_and_set_pending(wallet.proofs[1:]),
    )


@pytest.mark.asyncio
@pytest.mark.skipif(
    not settings.mint_database.startswith("postgres"),
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
async def test_db_lock_table(wallet: Wallet, ledger: Ledger):
    # fill wallet
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)

    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    async with ledger.db.connect(lock_table="proofs_pending", lock_timeout=0.1) as conn:
        assert isinstance(conn, Connection)
        await assert_err(
            ledger.db_write._verify_spent_proofs_and_set_pending(wallet.proofs),
            "failed to acquire database lock",
        )
