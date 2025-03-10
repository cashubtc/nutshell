import httpx
import pytest
import pytest_asyncio

from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT, settings
from tests.helpers import (
    assert_err,
    get_real_invoice,
    is_cln,
    is_fake,
    is_lnd,
    pay_if_regtest,
)

invoice_no_amount = "lnbcrt1pnusdsqpp5fcxhgur2eewvsfy52q8xwanrjdglnf7htacp0ldeeakz6j62rj8sdqqcqzzsxqyz5vqsp5qk6l5dwhldy3gqjnr4806mtg22e25ekud4vdlf3p0hk89ud93lxs9qxpqysgq72fmgd460q04mvr5jetw7wys0vnt6ydl58gcg4jdy5jwx5d7epx8tr04et7a5yskwg4le54wrn6u6k0jjfehkc8n5spxkwxum239zxcqpuzakn"
normal_invoice = "lnbcrt10u1pnuakkapp5sgc2whvdcsl53cpmyvpvslrlgc3h9al42xpayw86ykl8nhp2j69sdqqcqzzsxqyz5vqsp52w4vs63hx264tqu3pq2dtkwg6c8eummmjsel8r46adp3ascthgvs9qxpqysgqdjjexqh6acf77gpvkf3usjs0t30w0ru8e2v6pv42j7tcdy5tjxtrkqak8wp6mnrslnrkxqfv4pxjapylnn37m367zsqx4uvzsa79dkqpzdg2ex"

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
@pytest.mark.skipif(
    not (is_cln or is_lnd or is_fake),
    reason="only run this test on fake, lnd or cln"
)
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_amountless_bolt11_invoice(wallet: Wallet):
    # make sure wallet knows the backend supports mpp
    assert wallet.mint_info.supports_amountless("bolt11", wallet.unit)

    # top up wallet
    topup_mint_quote = await wallet.request_mint(128)

    await pay_if_regtest(topup_mint_quote.request)
    proofs = await wallet.mint(128, quote_id=topup_mint_quote.quote)
    assert wallet.balance == 128

    amountless_invoice = invoice_no_amount if is_fake else get_real_invoice(0)['payment_request']

    melt_quote = await wallet.melt_quote(amountless_invoice, 100*1000)
    assert melt_quote.amount == 100

    await pay_if_regtest(amountless_invoice)

    result = await wallet.melt(proofs, amountless_invoice, melt_quote.fee_reserve, melt_quote.quote)
    assert result.state == "PAID"

@pytest.mark.asyncio
@pytest.mark.skipif(
    not (is_cln or is_lnd or is_fake),
    reason="only run this test on fake, lnd or cln"
)
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_cheating_attempt_amountless_bolt11_invoice(wallet: Wallet):
    # make sure wallet knows the backend supports mpp
    assert wallet.mint_info.supports_amountless("bolt11", wallet.unit)

    # top up wallet
    topup_mint_quote = await wallet.request_mint(128)

    await pay_if_regtest(topup_mint_quote.request)
    proofs = await wallet.mint(128, quote_id=topup_mint_quote.quote)
    assert wallet.balance == 128

    # We get an invoice for 1000 sats
    invoice = normal_invoice if is_fake else get_real_invoice(1000)['payment_request']

    # We try and get a quote for 1 sat.
    # This should not succeed.
    assert_err(
        lambda x : httpx.post(
            SERVER_ENDPOINT+"/v1/melt/quote/bolt11",
            json={
                "unit": "sat",
                "request": invoice,
                "options": {
                    "amountless": "1000",
                },
            },
        ),
        "Amount in request does not equal invoice"
    )

@pytest.mark.asyncio
@pytest.mark.skipif(
    is_cln or is_lnd or is_fake,
    reason="only run for backends where amountless is not supported"
)
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_unsupported_amountless_bolt11_invoice(wallet: Wallet):
    amountless_invoice = invoice_no_amount if is_fake else get_real_invoice(0)['payment_request']
    assert_err(wallet.melt_quote(amountless_invoice, 100*1000), "Mint does not support amountless invoices, cannot pay this invoice.")

