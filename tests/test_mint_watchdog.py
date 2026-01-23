import pytest
import pytest_asyncio

from cashu.core.base import Amount, Method, Unit
from cashu.mint.ledger import Ledger
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


@pytest.mark.asyncio
async def test_check_balances_and_abort(ledger: Ledger):
    ok = await ledger.check_balances_and_abort(
        ledger.backends[Method.bolt11][Unit.sat],
        None,
        Amount(Unit.sat, 0),
        Amount(Unit.sat, 0),
        Amount(Unit.sat, 0),
    )
    assert ok


@pytest.mark.asyncio
async def test_balance_update_on_mint(wallet: Wallet, ledger: Ledger):
    balance_before, fees_paid_before = await ledger.get_unit_balance_and_fees(
        Unit.sat, ledger.db
    )
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    balance_after, fees_paid_after = await ledger.get_unit_balance_and_fees(
        Unit.sat, ledger.db
    )
    assert balance_after == balance_before + 64
    assert fees_paid_after == fees_paid_before


