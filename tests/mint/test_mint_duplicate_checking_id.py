
import pytest
import pytest_asyncio

from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    assert_err,
    get_real_invoice,
    is_fake,
    pay_if_regtest,
)

invoice_64_sat = "lnbcrt620n1pn0r3vepp5zljn7g09fsyeahl4rnhuy0xax2puhua5r3gspt7ttlfrley6valqdqqcqzzsxqyz5vqsp577h763sel3q06tfnfe75kvwn5pxn344sd5vnays65f9wfgx4fpzq9qxpqysgqg3re9afz9rwwalytec04pdhf9mvh3e2k4r877tw7dr4g0fvzf9sny5nlfggdy6nduy2dytn06w50ls34qfldgsj37x0ymxam0a687mspp0ytr8"

@pytest_asyncio.fixture(scope="function")
async def wallet(ledger: Ledger):
    wallet1 = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet_mint_api_deprecated",
        name="wallet_mint_api_deprecated",
    )
    await wallet1.load_mint()
    yield wallet1

@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_mint_pay_with_duplicate_checking_id(wallet):
    mint_quote1 = await wallet.request_mint(1024)
    mint_quote2 = await wallet.request_mint(1024)
    await pay_if_regtest(mint_quote1.request)
    await pay_if_regtest(mint_quote2.request)

    proofs1 = await wallet.mint(amount=1024, quote_id=mint_quote1.quote)
    proofs2 = await wallet.mint(amount=1024, quote_id=mint_quote2.quote)

    invoice = get_real_invoice(64)['payment_request']

    # Get two melt quotes for the same invoice
    melt_quote1 = await wallet.melt_quote(invoice)
    melt_quote2 = await wallet.melt_quote(invoice)

    response1 = await wallet.melt(
        proofs=proofs1, invoice=invoice, fee_reserve_sat=melt_quote1.fee_reserve, quote_id=melt_quote1.quote
    )    
    assert response1.state == 'PAID'

    assert_err(wallet.melt(
        proofs=proofs2, invoice=invoice, fee_reserve_sat=melt_quote2.fee_reserve, quote_id=melt_quote2.quote
    ), "Melt operation already SETTLED -- Reverting")
    
    #melt_quote2 = await wallet.get_melt_quote(melt_quote2.quote)
    #assert melt_quote2.state == MeltQuoteState.paid