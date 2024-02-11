import pytest
import pytest_asyncio

from cashu.core.base import PostMeltQuoteRequest
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import is_postgres


async def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        if msg not in str(exc.args[0]):
            raise Exception(f"Expected error: {msg}, got: {exc.args[0]}")
        return
    raise Exception(f"Expected error: {msg}, got no error")


@pytest_asyncio.fixture(scope="function")
async def wallet1(ledger: Ledger):
    wallet1 = await Wallet1.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet1",
        name="wallet1",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest.mark.asyncio
async def test_mint_quote(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(128)
    assert invoice is not None
    quote = await ledger.crud.get_mint_quote(quote_id=invoice.id, db=ledger.db)
    assert quote is not None
    assert quote.quote == invoice.id
    assert quote.amount == 128
    assert quote.unit == "sat"
    assert not quote.paid
    assert quote.checking_id == invoice.payment_hash
    assert quote.paid_time is None
    assert quote.created_time


@pytest.mark.asyncio
async def test_melt_quote(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(128)
    assert invoice is not None
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=invoice.bolt11, unit="sat")
    )
    quote = await ledger.crud.get_melt_quote(quote_id=melt_quote.quote, db=ledger.db)
    assert quote is not None
    assert quote.quote == melt_quote.quote
    assert quote.amount == 128
    assert quote.unit == "sat"
    assert not quote.paid
    assert quote.checking_id == invoice.payment_hash
    assert quote.paid_time is None
    assert quote.created_time


@pytest.mark.asyncio
@pytest.mark.skipif(not is_postgres, reason="only works with Postgres")
async def test_postgres_working():
    assert is_postgres
    assert True
