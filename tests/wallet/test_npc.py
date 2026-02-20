from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cashu.core.base import Proof
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

@pytest.mark.asyncio
async def test_get_lnurl(npc):
    lnurl = await npc.get_lnurl()
    assert lnurl.startswith("npub1")
    assert lnurl.endswith("@npubx.cash")

@pytest.mark.asyncio
async def test_create_lnurl_success(npc):
    with patch("cashu.wallet.npc.httpx.AsyncClient") as mock_client:
        mock_instance = mock_client.return_value.__aenter__.return_value
        
        # Mock GET /user/info (return user without mintUrl)
        mock_info_resp = MagicMock()
        mock_info_resp.status_code = 200
        mock_info_resp.json.return_value = {"error": False, "data": {"user": {"mintUrl": None}}}
        
        # Mock PATCH /user/mint
        mock_patch_resp = MagicMock()
        mock_patch_resp.status_code = 200
        mock_patch_resp.json.return_value = {"error": False, "data": {"user": {"mintUrl": "https://mint.example.com"}}}
        
        mock_instance.get.return_value = mock_info_resp
        mock_instance.patch.return_value = mock_patch_resp

        lnurl = await npc.create_lnurl()
        assert lnurl.startswith("npub1")
        assert mock_instance.patch.called
        # Check call arguments to ensure correct body
        args, kwargs = mock_instance.patch.call_args
        assert kwargs['json'] == {'mint_url': 'https://mint.example.com'}

@pytest.mark.asyncio
async def test_create_lnurl_already_exists(npc):
    with patch("cashu.wallet.npc.httpx.AsyncClient") as mock_client:
        mock_instance = mock_client.return_value.__aenter__.return_value
        
        # Mock GET /user/info (return user WITH mintUrl)
        mock_info_resp = MagicMock()
        mock_info_resp.status_code = 200
        mock_info_resp.json.return_value = {"error": False, "data": {"user": {"mintUrl": "https://existing.mint"}}}
        
        mock_instance.get.return_value = mock_info_resp

        with pytest.raises(Exception, match="LNURL already created"):
            await npc.create_lnurl()

@pytest.mark.asyncio
async def test_check_quotes(npc):
    with patch("cashu.wallet.npc.httpx.AsyncClient") as mock_client:
        mock_instance = mock_client.return_value.__aenter__.return_value
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "error": False,
            "data": {
                "quotes": [
                    {"quoteId": "1", "amount": 100, "state": "PAID"},
                    {"quoteId": "2", "amount": 200, "state": "UNPAID"},
                    {"quoteId": "3", "amount": 300, "state": "PAID"}
                ]
            }
        }
        mock_instance.get.return_value = mock_resp

        quotes = await npc.check_quotes()
        assert len(quotes) == 2
        assert quotes[0]["quoteId"] == "1"
        assert quotes[1]["quoteId"] == "3"

@pytest.mark.asyncio
async def test_mint_quotes(npc, mock_wallet):
    with patch("cashu.wallet.npc.httpx.AsyncClient") as mock_client, \
         patch("cashu.wallet.npc.get_bolt11_mint_quote", new_callable=AsyncMock) as mock_get_quote:
        
        mock_instance = mock_client.return_value.__aenter__.return_value
        
        # Mock quotes response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "error": False,
            "data": {
                "quotes": [
                    {"quoteId": "q1", "amount": 100, "state": "PAID", "mintUrl": "https://mint.example.com"},
                    {"quoteId": "q2", "amount": 200, "state": "PAID", "mintUrl": "https://other.mint.com"} # Different mint
                ]
            }
        }
        mock_instance.get.return_value = mock_resp
        
        # Mock local DB quote (not found)
        mock_get_quote.return_value = None

        # Mock wallet.get_mint_quote (return quote with state != issued)
        mock_mint_quote = MagicMock()
        mock_mint_quote.state = "PAID"  # Not MintQuoteState.issued
        mock_wallet.get_mint_quote = AsyncMock(return_value=mock_mint_quote)
        
        # Mock wallet mint
        mock_wallet.mint = AsyncMock(return_value=[Proof(id="1", amount=100, C="C", secret="s")])

        proofs = await npc.mint_quotes()
        
        assert len(proofs) == 1
        mock_wallet.mint.assert_called_once_with(100, quote_id="q1")
