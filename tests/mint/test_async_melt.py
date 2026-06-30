import asyncio

import httpx
import pytest

from cashu.core.base import Amount, MeltQuoteState, Method, Unit
from cashu.core.models import PostMeltQuoteRequest
from cashu.core.settings import settings
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import is_fake, pay_if_regtest

BASE_URL = "http://localhost:3337"


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="only on fakewallet")
async def test_async_melt(ledger):
    # This test uses direct API calls because the wallet fixture issue
    # for async melt is complex in this setup.
    from cashu.wallet.wallet import Wallet

    wallet = await Wallet.with_db(
        url=SERVER_ENDPOINT, db="test_data/wallet_async_melt", name="wallet_async_melt"
    )
    await wallet.load_mint()

    # Setup: get some funds
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    # Create invoice to melt to
    mint_quote = await wallet.request_mint(64)
    invoice_payment_request = mint_quote.request

    # Get quote
    quote = await wallet.melt_quote(invoice_payment_request)
    inputs_payload = [p.to_dict() for p in wallet.proofs]

    # Melt with prefer_async=True
    response = httpx.post(
        f"{BASE_URL}/v1/melt/bolt11",
        json={
            "quote": quote.quote,
            "inputs": inputs_payload,
            "prefer_async": True,
        },
        timeout=None,
    )
    assert response.status_code == 200
    result = response.json()
    assert result["state"] == MeltQuoteState.pending.value

    # Wait a bit for the background task to complete
    await asyncio.sleep(2)

    # Verify it became paid
    response = httpx.get(f"{BASE_URL}/v1/melt/quote/bolt11/{quote.quote}")
    assert response.status_code == 200
    result = response.json()
    assert result["state"] == MeltQuoteState.paid.value


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="only on fakewallet")
async def test_async_melt_commits_pending_before_returning(ledger):
    """Regression: async_melt must durably persist PENDING *before* it returns
    PENDING. If the commit is deferred into the detached task (the old behavior),
    a NUT-17 subscriber or a poller reading right after the response sees the
    stale UNPAID, which NUT-05 clients treat as a terminal payment failure."""
    from cashu.wallet.wallet import Wallet

    wallet = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet_async_melt_race",
        name="wallet_async_melt_race",
    )
    await wallet.load_mint()
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)

    # External invoice: payable by the backend but with no matching mint quote,
    # so the melt takes the Lightning path (where the race window exists) instead
    # of settling internally and synchronously.
    invoice = await ledger.backends[Method.bolt11][Unit.sat].create_invoice(
        Amount(Unit.sat, 32)
    )
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=invoice.payment_request, unit="sat")
    )
    _, send_proofs = await wallet.swap_to_send(
        wallet.proofs, melt_quote.amount + melt_quote.fee_reserve
    )

    # Hold the background Lightning payment in-flight so the committed PENDING
    # state is observable instead of racing straight to PAID.
    original_delay = settings.fakewallet_delay_outgoing_payment
    settings.fakewallet_delay_outgoing_payment = 1.0
    try:
        resp = await ledger.async_melt(proofs=send_proofs, quote=melt_quote.quote)
        assert resp.state == MeltQuoteState.pending.value

        # Read the RAW committed state (as the NUT-17 snapshot does); the public
        # ledger.get_melt_quote() would itself poll the backend and settle it.
        persisted = await ledger.crud.get_melt_quote(
            quote_id=melt_quote.quote, db=ledger.db
        )
        assert persisted is not None
        assert persisted.state == MeltQuoteState.pending

        # Wait for the background payment to complete
        await asyncio.sleep(settings.fakewallet_delay_outgoing_payment + 1)
    finally:
        settings.fakewallet_delay_outgoing_payment = original_delay

    persisted = await ledger.crud.get_melt_quote(
        quote_id=melt_quote.quote, db=ledger.db
    )
    assert persisted is not None
    assert persisted.state == MeltQuoteState.paid


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="only on fakewallet")
async def test_async_melt_nonexistent_quote(ledger):
    # Melt with prefer_async=True and a fake quote
    response = httpx.post(
        f"{BASE_URL}/v1/melt/bolt11",
        json={
            "quote": "nonexistent_quote_id",
            "inputs": [],
            "prefer_async": True,
        },
        timeout=None,
    )
    # Expect failure (404 or 400 is fine)
    assert response.status_code != 200
