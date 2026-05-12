import pytest
import asyncio
import httpx
from cashu.core.base import MeltQuoteState
from cashu.core.settings import settings
from cashu.wallet.wallet import Wallet
from tests.helpers import pay_if_regtest, is_fake
from tests.conftest import SERVER_ENDPOINT
import pytest_asyncio

BASE_URL = "http://localhost:3337"

@pytest_asyncio.fixture(scope="function")
async def wallet(ledger):
    wallet1 = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet_async_melt",
        name="wallet_async_melt",
    )
    await wallet1.load_mint()
    yield wallet1

@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="only on fakewallet")
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
    await asyncio.sleep(2)
    
    # Verify it became paid
    response = httpx.get(f"{BASE_URL}/v1/melt/quote/bolt11/{quote.quote}")
    assert response.status_code == 200
    result = response.json()
    assert result["state"] == MeltQuoteState.paid.value

@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="only on fakewallet")
async def test_async_melt_functional(ledger, wallet):
    # Make sure FakeWallet takes time to pay to observe PENDING state
    settings.fakewallet_delay_outgoing_payment = 2
    
    # Setup: get some funds
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    # Create invoice to melt to
    melt_quote_mint = await wallet.request_mint(10)
    invoice_payment_request = melt_quote_mint.request

    # Get melt quote
    melt_quote_response = await wallet.melt_quote(invoice_payment_request)
    
    # Melt with prefer_async=True
    inputs_payload = [p.to_dict() for p in wallet.proofs]
    response = httpx.post(
        f"{BASE_URL}/v1/melt/bolt11",
        json={
            "quote": melt_quote_response.quote,
            "inputs": inputs_payload,
            "prefer_async": True,
        },
        timeout=None,
    )
    assert response.status_code == 200
    result = response.json()
    assert result["state"] == MeltQuoteState.pending.value
    
    # Wait for the background task to complete (should be ~2s)
    await asyncio.sleep(3)
    
    # Verify it became paid
    response = httpx.get(f"{BASE_URL}/v1/melt/quote/bolt11/{melt_quote_response.quote}")
    assert response.status_code == 200
    result = response.json()
    assert result["state"] == MeltQuoteState.paid.value
    
    # Reset setting
    settings.fakewallet_delay_outgoing_payment = 0

@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="only on fakewallet")
async def test_async_melt_nonexistent_quote(ledger, wallet):
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
