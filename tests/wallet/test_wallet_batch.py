"""Tests for wallet batch minting (NUT-333)."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cashu.core.base import BlindedSignature, MintQuoteState
from cashu.wallet.npc import NpubCash
from cashu.wallet.wallet import Wallet


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
