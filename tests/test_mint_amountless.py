import pytest

from cashu.core.models import (
    PostMeltQuoteRequest,
    PostMeltRequestOptionAmountless,
    PostMeltRequestOptions,
)

from .helpers import assert_err, get_real_invoice, is_fake, is_cln

invoice_no_amount = "lnbcrt1pnusdsqpp5fcxhgur2eewvsfy52q8xwanrjdglnf7htacp0ldeeakz6j62rj8sdqqcqzzsxqyz5vqsp5qk6l5dwhldy3gqjnr4806mtg22e25ekud4vdlf3p0hk89ud93lxs9qxpqysgq72fmgd460q04mvr5jetw7wys0vnt6ydl58gcg4jdy5jwx5d7epx8tr04et7a5yskwg4le54wrn6u6k0jjfehkc8n5spxkwxum239zxcqpuzakn"
normal_invoice = "lnbcrt10u1pnuakkapp5sgc2whvdcsl53cpmyvpvslrlgc3h9al42xpayw86ykl8nhp2j69sdqqcqzzsxqyz5vqsp52w4vs63hx264tqu3pq2dtkwg6c8eummmjsel8r46adp3ascthgvs9qxpqysgqdjjexqh6acf77gpvkf3usjs0t30w0ru8e2v6pv42j7tcdy5tjxtrkqak8wp6mnrslnrkxqfv4pxjapylnn37m367zsqx4uvzsa79dkqpzdg2ex"

@pytest.mark.asyncio
@pytest.mark.skipif(
    not (is_cln or is_lnd or is_fake),
    reason="Only run when amountless is supported",
)
async def test_get_quote_for_amountless_invoice(wallet, ledger):
    # Get an amountless invoice
    invoice = invoice_no_amount if is_fake else get_real_invoice(0)['payment_request']

    request = PostMeltQuoteRequest(
        unit='sat',
        request=invoice,
        options=PostMeltRequestOptions(
            amountless=PostMeltRequestOptionAmountless(
                amount_msat=1000,
            )
        ),
    )

    response = await ledger.melt_quote(request)
    assert response.unit == 'sat'
    assert response.amount == 1

@pytest.mark.asyncio
@pytest.mark.skipif(
    not (is_cln or is_lnd or is_fake),
    reason="Only run when amountless is supported",
)
async def test_get_amountless_quote_for_non_amountless_invoice(wallet, ledger):
    # Get normal invoice
    invoice = normal_invoice if is_fake else get_real_invoice(1000)['payment_request']

    request = PostMeltQuoteRequest(
        unit='sat',
        request=invoice,
        options=PostMeltRequestOptions(
            amountless=PostMeltRequestOptionAmountless(
                amount_msat=1000,
            )
        ),
    )

    assert_err(ledger.melt_quote(request), "Amount in request does not equal invoice")
    