
import pytest
import httpx
from cashu.core.base import MeltQuoteState
from cashu.core.models import PostMeltQuoteResponse
from tests.helpers import pay_if_regtest, is_fake

BASE_URL = "http://localhost:3337"

@pytest.mark.asyncio
@pytest.mark.skipif(
    is_fake,
    reason="only works on regtest",
)
async def test_async_melt(ledger, wallet):
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
    import asyncio
    await asyncio.sleep(2)
    
    # Verify it became paid
    response = httpx.get(f"{BASE_URL}/v1/melt/quote/bolt11/{quote.quote}")
    assert response.status_code == 200
    result = response.json()
    assert result["state"] == MeltQuoteState.paid.value
