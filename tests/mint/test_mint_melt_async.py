import asyncio

import pytest
import pytest_asyncio

from cashu.core.base import MeltQuoteState, Unit
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.helpers import (
    get_real_invoice,
    is_deprecated_api_only,
    is_fake,
    pay_if_regtest,
)

SERVER_ENDPOINT = "http://localhost:3337"
invoice_62_sat = "lnbcrt620n1pn0r3vepp5zljn7g09fsyeahl4rnhuy0xax2puhua5r3gspt7ttlfrley6valqdqqcqzzsxqyz5vqsp577h763sel3q06tfnfe75kvwn5pxn344sd5vnays65f9wfgx4fpzq9qxpqysgqg3re9afz9rwwalytec04pdhf9mvh3e2k4r877tw7dr4g0fvzf9sny5nlfggdy6nduy2dytn06w50ls34qfldgsj37x0ymxam0a687mspp0ytr8"


@pytest_asyncio.fixture(scope="function")
async def wallet1(ledger: Ledger):
    wallet1 = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet_1",
        name="wallet_1",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest.mark.asyncio
@pytest.mark.skipif(
    is_deprecated_api_only,
    reason=("Deprecated API"),
)
async def test_melt_internal_async(ledger: Ledger, wallet1: Wallet):
    quote = await wallet1.request_mint(64)
    await pay_if_regtest(quote.request)
    proofs = await wallet1.mint(64, quote.quote)
    assert wallet1.available_balance == 64

    # create a melt quote for an internal payment
    invoice_internal = await wallet1.mint_quote(10, Unit.sat)

    # melt the proofs
    quote = await wallet1.melt_quote(invoice_internal.request)
    melt_resp = await wallet1.melt(
        proofs,
        invoice_internal.request,
        quote.fee_reserve,
        quote.quote,
        prefer_async=True,
    )

    # internal melts are settled immediately
    assert melt_resp.state == MeltQuoteState.paid.value


@pytest.mark.asyncio
@pytest.mark.skipif(
    is_deprecated_api_only,
    reason=("Deprecated API"),
)
async def test_melt_external_async(ledger: Ledger, wallet1: Wallet):
    # mint a proof in keyset_a
    quote = await wallet1.request_mint(64)
    await pay_if_regtest(quote.request)
    proofs = await wallet1.mint(64, quote.quote)
    assert wallet1.available_balance == 64

    # create a melt quote for an external payment
    external_invoice = (
        invoice_62_sat if is_fake else get_real_invoice(62)["payment_request"]
    )
    quote = await wallet1.melt_quote(external_invoice)

    # melt the proofs
    melt_resp = await wallet1.melt(
        proofs, external_invoice, quote.fee_reserve, quote.quote, prefer_async=True
    )

    # the response should be pending
    assert melt_resp.state == "PENDING"

    delay = settings.fakewallet_delay_outgoing_payment or 0
    await asyncio.sleep(delay + 1)

    settled = await wallet1.get_melt_quote(quote.quote)
    assert settled is not None
    assert settled.state == MeltQuoteState.paid


@pytest.mark.asyncio
@pytest.mark.skipif(
    is_deprecated_api_only or is_fake,
    reason=("Deprecated API"),
)
async def test_melt_external_async_get_quote_race(ledger: Ledger, wallet1: Wallet):
    # we call get_melt_quote right after executing a melt
    # mint a proof in keyset_a
    quote = await wallet1.request_mint(64)
    await pay_if_regtest(quote.request)
    proofs = await wallet1.mint(64, quote.quote)
    assert wallet1.available_balance == 64

    # create a melt quote for an external payment
    external_invoice = (
        invoice_62_sat if is_fake else get_real_invoice(62)["payment_request"]
    )
    quote = await wallet1.melt_quote(external_invoice)

    # melt the proofs
    melt_resp = await wallet1.melt(
        proofs, external_invoice, quote.fee_reserve, quote.quote, prefer_async=True
    )

    # the response should be pending
    assert melt_resp.state == "PENDING"

    pending_quote = await wallet1.get_melt_quote(quote.quote)
    assert pending_quote
    assert pending_quote.state == MeltQuoteState.pending

    delay = settings.fakewallet_delay_outgoing_payment or 0
    await asyncio.sleep(delay + 1)

    settled = await wallet1.get_melt_quote(quote.quote)
    assert settled is not None
    assert settled.state == MeltQuoteState.paid
