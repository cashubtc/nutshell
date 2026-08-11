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
        url=SERVER_ENDPOINT,
        db="test_data/wallet_async_melt",
        name="wallet_async_melt",
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
    """async_melt must persist PENDING before returning PENDING.

    Deferred commit into the detached task lets a poller see stale UNPAID, which
    NUT-05 clients treat as a terminal payment failure.
    """
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

    # External invoice (no matching mint quote) so melt takes the Lightning path.
    invoice = await ledger.backends[Method.bolt11][Unit.sat].create_invoice(
        Amount(Unit.sat, 32)
    )
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=invoice.payment_request, unit="sat")
    )
    _, send_proofs = await wallet.swap_to_send(
        wallet.proofs, melt_quote.amount + melt_quote.fee_reserve
    )
    # Blank outputs for fee return — must be stored during prepare, before return.
    n_change_outputs = 4
    secrets, rs, _ = await wallet.generate_n_secrets(n_change_outputs, skip_bump=True)
    change_outputs, _ = wallet._construct_outputs(n_change_outputs * [1], secrets, rs)

    original_delay = settings.fakewallet_delay_outgoing_payment
    settings.fakewallet_delay_outgoing_payment = 1.0
    try:
        resp = await ledger.async_melt(
            proofs=send_proofs, quote=melt_quote.quote, outputs=change_outputs
        )
        assert resp.state == MeltQuoteState.pending.value

        # Raw DB state as NUT-17 snapshot sees it (not public get_melt_quote,
        # which re-polls the backend and may settle the quote).
        persisted = await ledger.crud.get_melt_quote(
            quote_id=melt_quote.quote, db=ledger.db
        )
        assert persisted is not None
        assert persisted.state == MeltQuoteState.pending

        states = await ledger.db_read.get_proofs_states([p.Y for p in send_proofs])
        assert all(s.pending for s in states)

        stored_outputs = await ledger.crud.get_blinded_messages_melt_id(
            melt_id=melt_quote.quote, db=ledger.db
        )
        assert len(stored_outputs) == n_change_outputs

        for _ in range(30):
            persisted = await ledger.crud.get_melt_quote(
                quote_id=melt_quote.quote, db=ledger.db
            )
            assert persisted is not None
            if persisted.state == MeltQuoteState.paid:
                break
            await asyncio.sleep(0.1)
        else:
            pytest.fail("background async melt did not settle before test exit")
    finally:
        settings.fakewallet_delay_outgoing_payment = original_delay


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
