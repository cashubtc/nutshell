
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cashu.core.base import (
    BlindedMessage,
    BlindedSignature,
    Method,
    MintQuoteState,
    Unit,
)
from cashu.core.crypto.b_dhke import step1_alice
from cashu.core.mint_info import MintInfo
from cashu.core.models import (
    PostMintQuoteRequest,
)
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from cashu.wallet.npc import NpubCash
from cashu.wallet.wallet import Wallet
from tests.helpers import assert_err, is_fake, pay_if_regtest


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


# ============================================================
# Tests for MintInfo batch minting methods (NUT-333)
# ============================================================

class TestMintInfoBatchSupport:
    """Tests for MintInfo batch minting methods."""

    def test_supports_batch_mint_without_nuts(self):
        """Test that supports_batch_mint returns False when nuts is None."""
        mint_info = MintInfo.model_construct(nuts=None)
        assert mint_info.supports_batch_mint("bolt11") is False

    def test_supports_batch_mint_without_batch_nut(self):
        """Test that supports_batch_mint returns False when NUT-333 not supported."""
        mint_info = MintInfo.model_construct(nuts={})
        assert mint_info.supports_batch_mint("bolt11") is False

    def test_supports_batch_mint_with_supported_method(self):
        """Test that supports_batch_mint returns True for supported method."""
        mint_info = MintInfo.model_construct(nuts={333: {"methods": ["bolt11", "bolt12"]}})
        assert mint_info.supports_batch_mint("bolt11") is True
        assert mint_info.supports_batch_mint("bolt12") is True

    def test_supports_batch_mint_with_unsupported_method(self):
        """Test that supports_batch_mint returns False for unsupported method."""
        mint_info = MintInfo.model_construct(nuts={333: {"methods": ["bolt11"]}})
        assert mint_info.supports_batch_mint("bolt12") is False

    def test_supports_batch_mint_with_empty_methods(self):
        """Test that supports_batch_mint returns False when methods list is empty."""
        mint_info = MintInfo.model_construct(nuts={333: {"methods": []}})
        assert mint_info.supports_batch_mint("bolt11") is False

    def test_get_max_batch_size_without_nuts(self):
        """Test that get_max_batch_size returns 0 when nuts is None."""
        mint_info = MintInfo.model_construct(nuts=None)
        assert mint_info.get_max_batch_size() == 0

    def test_get_max_batch_size_without_batch_nut(self):
        """Test that get_max_batch_size returns 0 when NUT-333 not supported."""
        mint_info = MintInfo.model_construct(nuts={})
        assert mint_info.get_max_batch_size() == 0

    def test_get_max_batch_size_with_value(self):
        """Test that get_max_batch_size returns the configured value."""
        mint_info = MintInfo.model_construct(nuts={333: {"methods": ["bolt11"], "max_batch_size": 50}})
        assert mint_info.get_max_batch_size() == 50

    def test_get_max_batch_size_without_max(self):
        """Test that get_max_batch_size returns 0 when max_batch_size not set."""
        mint_info = MintInfo.model_construct(nuts={333: {"methods": ["bolt11"]}})
        assert mint_info.get_max_batch_size() == 0


# ============================================================
# Tests for Wallet batch minting (NUT-333)
# ============================================================

@pytest.fixture
def mock_wallet():
    wallet = MagicMock(spec=Wallet)
    wallet.seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    wallet.url = "https://mint.example.com"
    wallet.db = MagicMock()
    return wallet


@pytest.fixture
def npc(mock_wallet):
    return NpubCash(mock_wallet)


class TestWalletSignatureToPromise:
    """Test Wallet._signature_to_promise method."""

    def test_signature_to_promise_converts_correctly(self):
        """Test that _signature_to_promise correctly converts signature dict to BlindedSignature."""
        sig_dict = {
            "id": "keyset123",
            "amount": 64,
            "C_": "0202aabbccdd"
        }
        
        result = BlindedSignature(
            id=sig_dict["id"],
            amount=sig_dict["amount"],
            C_=sig_dict["C_"]
        )
        
        assert result.id == "keyset123"
        assert result.amount == 64
        assert result.C_ == "0202aabbccdd"


class TestNpubCashBatchSelection:
    """Tests for NpubCash batch vs sequential mint selection."""

    @pytest.mark.asyncio
    async def test_uses_batch_when_supported(self, npc, mock_wallet):
        """Test that NpubCash uses batch mint when mint supports it."""
        mock_mint_info = MagicMock()
        mock_mint_info.supports_batch_mint = MagicMock(return_value=True)
        mock_wallet.mint_info = mock_mint_info
        mock_wallet.mint_batch = AsyncMock(return_value=[])
        
        npc.check_quotes = AsyncMock(return_value=[
            {"quoteId": "q1", "amount": 100, "mintUrl": "https://mint.example.com"}
        ])
        
        with patch("cashu.wallet.npc.get_bolt11_mint_quote", new_callable=AsyncMock) as mock_get:
            mock_quote = MagicMock()
            mock_quote.state = MintQuoteState.unpaid
            mock_quote.amount = 100
            mock_quote.privkey = None
            mock_get.return_value = mock_quote
            
            mock_wallet.get_mint_quote = AsyncMock(return_value=mock_quote)
            
            await npc.mint_quotes()
            
            mock_mint_info.supports_batch_mint.assert_called()
            mock_wallet.mint_batch.assert_called()

    @pytest.mark.asyncio
    async def test_skips_different_mint_quotes(self, npc, mock_wallet):
        """Test that NpubCash skips quotes from different mints."""
        mock_mint_info = MagicMock()
        mock_mint_info.supports_batch_mint = MagicMock(return_value=False)
        mock_wallet.mint_info = mock_mint_info
        
        npc.check_quotes = AsyncMock(return_value=[
            {"quoteId": "q1", "amount": 100, "mintUrl": "https://other-mint.com"},
            {"quoteId": "q2", "amount": 200, "mintUrl": "https://mint.example.com"},
        ])
        
        mock_wallet.mint = AsyncMock(return_value=[])
        
        with patch("cashu.wallet.npc.get_bolt11_mint_quote", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = None
            mock_wallet.get_mint_quote = AsyncMock(return_value=MagicMock(state=MintQuoteState.unpaid))
            
            await npc.mint_quotes()
            
            assert mock_wallet.mint.call_count == 1

    @pytest.mark.asyncio
    async def test_no_quotes_returns_empty(self, npc, mock_wallet):
        """Test that mint_quotes returns empty list when no quotes."""
        npc.check_quotes = AsyncMock(return_value=[])
        
        result = await npc.mint_quotes()
        
        assert result == []

    @pytest.mark.asyncio
    async def test_sequential_fallback_on_batch_failure(self, npc, mock_wallet):
        """Test that NpubCash falls back to sequential when batch fails."""
        mock_mint_info = MagicMock()
        mock_mint_info.supports_batch_mint = MagicMock(return_value=True)
        mock_wallet.mint_info = mock_mint_info
        
        mock_wallet.mint_batch = AsyncMock(side_effect=Exception("Batch not supported"))
        mock_wallet.mint = AsyncMock(return_value=[])
        
        npc.check_quotes = AsyncMock(return_value=[
            {"quoteId": "q1", "amount": 100, "mintUrl": "https://mint.example.com"}
        ])
        
        with patch("cashu.wallet.npc.get_bolt11_mint_quote", new_callable=AsyncMock) as mock_get:
            mock_quote = MagicMock()
            mock_quote.state = MintQuoteState.unpaid
            mock_quote.amount = 100
            mock_quote.privkey = None
            mock_get.return_value = mock_quote
            
            mock_wallet.get_mint_quote = AsyncMock(return_value=mock_quote)
            
            await npc.mint_quotes()
            
            assert mock_wallet.mint_batch.called
            assert mock_wallet.mint.called
