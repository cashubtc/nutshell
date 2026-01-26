import pytest
import time
from cashu.core.base import BlindedMessage, Unit, Method
from cashu.core.crypto.b_dhke import step1_alice
from cashu.core.models import (
    PostMintQuoteRequest,
    PostMintBatchRequest,
    PostMintQuoteCheckRequest,
)
from cashu.mint.ledger import Ledger
from cashu.core.settings import settings
from tests.helpers import assert_err, pay_if_regtest, is_fake

@pytest.mark.skipif(not is_fake, reason="only for FakeWallet")
@pytest.mark.asyncio
async def test_mint_batch_success(ledger: Ledger):
    # Ensure BRR is on
    settings.fakewallet_brr = True
    
    # Create two quotes
    quote1 = await ledger.mint_quote(PostMintQuoteRequest(amount=8, unit="sat"))
    quote2 = await ledger.mint_quote(PostMintQuoteRequest(amount=4, unit="sat"))
    
    await pay_if_regtest(quote1.request)
    await pay_if_regtest(quote2.request)
    
    # Check if they are paid (optional, but good for verification)
    quotes_status = await ledger.check_mint_quotes([quote1.quote, quote2.quote])
    assert all(q.state.value == "PAID" for q in quotes_status)
    
    # Prepare blinded messages
    b1, _ = step1_alice("secret1")
    b2, _ = step1_alice("secret2")
    
    outputs = [
        BlindedMessage(
            amount=8,
            B_=b1.format().hex(),
            id=ledger.keyset.id,
        ),
        BlindedMessage(
            amount=4,
            B_=b2.format().hex(),
            id=ledger.keyset.id,
        )
    ]
    
    promises = await ledger.mint_batch(
        outputs=outputs,
        quotes=[quote1.quote, quote2.quote]
    )
    
    assert len(promises) == 2
    assert promises[0].amount == 8
    assert promises[1].amount == 4
    
    # Verify quotes are now ISSUED
    q1_db = await ledger.get_mint_quote(quote1.quote)
    q2_db = await ledger.get_mint_quote(quote2.quote)
    assert q1_db.issued
    assert q2_db.issued

@pytest.mark.skipif(not is_fake, reason="only for FakeWallet")
@pytest.mark.asyncio
async def test_check_mint_quotes(ledger: Ledger):
    try:
        # Disable auto-payment for this test to verify UNPAID state
        settings.fakewallet_brr = False
        
        quote1 = await ledger.mint_quote(PostMintQuoteRequest(amount=8, unit="sat"))
        quote2 = await ledger.mint_quote(PostMintQuoteRequest(amount=4, unit="sat"))
        
        # Initially unpaid
        quotes_status = await ledger.check_mint_quotes([quote1.quote, quote2.quote])
        assert all(q.state.value == "UNPAID" for q in quotes_status)
        
        # Manually pay one via FakeWallet backend
        backend = ledger.backends[Method.bolt11][Unit.sat]
        invoice = next(i for i in backend.created_invoices if i.payment_hash == quote1.checking_id)
        
        # Temporarily enable BRR to allow marking as paid (FakeWallet check)
        settings.fakewallet_brr = True
        await backend.mark_invoice_paid(invoice, delay=False)
        settings.fakewallet_brr = False
        
        # Check again
        quotes_status = await ledger.check_mint_quotes([quote1.quote, quote2.quote])
        q1_status = next(q for q in quotes_status if q.quote == quote1.quote)
        q2_status = next(q for q in quotes_status if q.quote == quote2.quote)
        
        assert q1_status.state.value == "PAID"
        assert q2_status.state.value == "UNPAID"
    finally:
        # Restore setting
        settings.fakewallet_brr = True

@pytest.mark.skipif(not is_fake, reason="only for FakeWallet")
@pytest.mark.asyncio
async def test_mint_batch_failure_unpaid(ledger: Ledger):
    try:
        settings.fakewallet_brr = False
        quote1 = await ledger.mint_quote(PostMintQuoteRequest(amount=8, unit="sat"))
        quote2 = await ledger.mint_quote(PostMintQuoteRequest(amount=4, unit="sat"))
        
        # Pay only one
        backend = ledger.backends[Method.bolt11][Unit.sat]
        invoice = next(i for i in backend.created_invoices if i.payment_hash == quote1.checking_id)
        
        settings.fakewallet_brr = True
        await backend.mark_invoice_paid(invoice, delay=False)
        settings.fakewallet_brr = False
        
        b1, _ = step1_alice("secret1")
        b2, _ = step1_alice("secret2")
        
        outputs = [
            BlindedMessage(
                amount=8,
                B_=b1.format().hex(),
                id=ledger.keyset.id,
            ),
            BlindedMessage(
                amount=4,
                B_=b2.format().hex(),
                id=ledger.keyset.id,
            )
        ]
        
        # Should fail because quote2 is unpaid
        await assert_err(
            ledger.mint_batch(
                outputs=outputs,
                quotes=[quote1.quote, quote2.quote]
            ),
            "quote not paid"
        )
        
        # Verify quote1 is still PAID (not ISSUED)
        q1_db = await ledger.get_mint_quote(quote1.quote)
        assert q1_db.state.value == "PAID"
        assert not q1_db.issued
    finally:
        settings.fakewallet_brr = True

@pytest.mark.skipif(not is_fake, reason="only for FakeWallet")
@pytest.mark.asyncio
async def test_mint_batch_failure_amount_mismatch(ledger: Ledger):
    settings.fakewallet_brr = True
    quote1 = await ledger.mint_quote(PostMintQuoteRequest(amount=8, unit="sat"))
    quote2 = await ledger.mint_quote(PostMintQuoteRequest(amount=4, unit="sat"))
    
    await pay_if_regtest(quote1.request)
    await pay_if_regtest(quote2.request)
    
    # outputs sum to 8+8=16, quotes sum to 8+4=12
    b1, _ = step1_alice("secret1")
    b2, _ = step1_alice("secret2")
    outputs = [
        BlindedMessage(
            amount=8,
            B_=b1.format().hex(),
            id=ledger.keyset.id,
        ),
        BlindedMessage(
            amount=8,
            B_=b2.format().hex(),
            id=ledger.keyset.id,
        )
    ]
    
    await assert_err(
        ledger.mint_batch(
            outputs=outputs,
            quotes=[quote1.quote, quote2.quote]
        ),
        "output amount 16 exceeds quote amount 12"
    )

@pytest.mark.skipif(not is_fake, reason="only for FakeWallet")
@pytest.mark.asyncio
async def test_mint_batch_failure_already_spent(ledger: Ledger):
    settings.fakewallet_brr = True
    quote1 = await ledger.mint_quote(PostMintQuoteRequest(amount=8, unit="sat"))
    await pay_if_regtest(quote1.request)
    
    # Ensure it is paid
    q1_db = await ledger.get_mint_quote(quote1.quote)
    assert q1_db.state.value == "PAID"
    
    b1, _ = step1_alice("secret1")
    outputs1 = [
        BlindedMessage(
            amount=8,
            B_=b1.format().hex(),
            id=ledger.keyset.id,
        )
    ]
    
    # First mint succeeds
    await ledger.mint_batch(
        outputs=outputs1,
        quotes=[quote1.quote]
    )
    
    # Verify state is ISSUED
    q1_db = await ledger.get_mint_quote(quote1.quote)
    assert q1_db.issued
    
    # Use different outputs for second attempt to isolate quote reuse error
    b2, _ = step1_alice("secret2")
    outputs2 = [
        BlindedMessage(
            amount=8,
            B_=b2.format().hex(),
            id=ledger.keyset.id,
        )
    ]
    
    # Second mint fails
    await assert_err(
        ledger.mint_batch(
            outputs=outputs2,
            quotes=[quote1.quote]
        ),
        "quote already issued"
    )
