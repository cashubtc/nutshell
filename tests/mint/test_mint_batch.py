import pytest
import pytest_asyncio

from cashu.core.models import PostMintBatchRequest, PostMintQuoteCheckRequest
from cashu.core.nuts import nut20
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.helpers import pay_if_regtest

BASE_URL = "http://localhost:3337"


@pytest_asyncio.fixture(scope="function")
async def wallet(ledger: Ledger):
    wallet1 = await Wallet.with_db(
        url=BASE_URL,
        db="test_data/wallet_mint_api_batch",
        name="wallet_mint_api_batch",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest.fixture(autouse=True)
def setup_settings():
    settings.debug_mint_only_deprecated = False
    yield


@pytest.mark.asyncio
async def test_ledger_mint_quote_check(ledger: Ledger, wallet: Wallet):
    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)
    mint_quote2 = await wallet.request_mint(32)

    quotes = await ledger.mint_quote_check(
        PostMintQuoteCheckRequest(quotes=[mint_quote1.quote, mint_quote2.quote])
    )
    assert len(quotes) == 2
    assert quotes[0].quote == mint_quote1.quote
    assert quotes[0].amount == 64
    assert quotes[0].state.value in ["UNPAID", "PAID"]
    assert quotes[1].quote == mint_quote2.quote
    assert quotes[1].amount == 32
    assert quotes[1].state.value in ["UNPAID", "PAID"]


@pytest.mark.asyncio
async def test_ledger_mint_batch_success(ledger: Ledger, wallet: Wallet):
    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)
    mint_quote2 = await wallet.request_mint(32)

    await pay_if_regtest(mint_quote1.request)
    await pay_if_regtest(mint_quote2.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([64, 32], secrets, rs)

    assert mint_quote1.privkey
    assert mint_quote2.privkey

    sig1 = nut20.sign_mint_quote(mint_quote1.quote, outputs, mint_quote1.privkey)
    sig2 = nut20.sign_mint_quote(mint_quote2.quote, outputs, mint_quote2.privkey)

    promises = await ledger.mint_batch(
        PostMintBatchRequest(
            quotes=[mint_quote1.quote, mint_quote2.quote],
            quote_amounts=[64, 32],
            outputs=outputs,
            signatures=[sig1, sig2],
        )
    )

    assert len(promises) == 2
    assert promises[0].amount == 64
    assert promises[1].amount == 32


@pytest.mark.asyncio
async def test_ledger_mint_batch_wrong_amount(ledger: Ledger, wallet: Wallet):
    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote1.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)

    assert mint_quote1.privkey

    sig1 = nut20.sign_mint_quote(mint_quote1.quote, outputs, mint_quote1.privkey)

    try:
        await ledger.mint_batch(
            PostMintBatchRequest(
                quotes=[mint_quote1.quote],
                quote_amounts=[32],
                outputs=outputs,
                signatures=[sig1],
            )
        )
        assert False, "Expected Exception"
    except Exception as e:
        assert "does not match quote" in str(e)


@pytest.mark.asyncio
async def test_ledger_mint_batch_duplicate_quotes(ledger: Ledger, wallet: Wallet):
    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)

    try:
        await ledger.mint_batch(
            PostMintBatchRequest(
                quotes=[mint_quote1.quote, mint_quote1.quote],
                quote_amounts=[64, 64],
                outputs=[],
                signatures=[None, None],
            )
        )
        assert False, "Expected Exception"
    except Exception as e:
        assert "quotes must be unique" in str(e)
