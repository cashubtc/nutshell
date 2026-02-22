from unittest.mock import MagicMock, patch

import pytest

from cashu.wallet.lnurl import decode_lnurl, handle_lnurl, resolve_lightning_address


def test_decode_lnurl():
    # Test valid LNURL (lnurl1dp68gurn8ghj7etcv9khqmr99e3k7mf0d3h82unvq257ls decodes to https://example.com/lnurl)
    lnurl = "lnurl1dp68gurn8ghj7etcv9khqmr99e3k7mf0d3h82unvq257ls"
    decoded = decode_lnurl(lnurl)
    assert decoded == "https://example.com/lnurl"

    # Test invalid LNURL
    assert decode_lnurl("invalid") is None

def test_resolve_lightning_address():
    address = "user@domain.com"
    url = resolve_lightning_address(address)
    assert url == "https://domain.com/.well-known/lnurlp/user"

    assert resolve_lightning_address("invalid") is None

@pytest.mark.asyncio
async def test_handle_lnurl_success_with_amount():
    lnurl = "user@domain.com"
    amount = 1000
    callback_url = "https://domain.com/lnurl/callback"

    with patch("cashu.wallet.lnurl.httpx.AsyncClient") as mock_client:
        mock_instance = mock_client.return_value.__aenter__.return_value
        
        # Mock initial LNURL request
        mock_response_1 = MagicMock()
        mock_response_1.json.return_value = {
            "tag": "payRequest",
            "callback": callback_url,
            "minSendable": 1000,
            "maxSendable": 10000000,
            "metadata": "[[\"text/plain\", \"Description\"]]"
        }
        mock_response_1.status_code = 200

        # Mock callback request
        mock_response_2 = MagicMock()
        mock_response_2.json.return_value = {
            "pr": "lnbc1...",
            "status": "OK"
        }
        mock_response_2.status_code = 200

        mock_instance.get.side_effect = [mock_response_1, mock_response_2]

        invoice = await handle_lnurl(lnurl, amount)
        assert invoice == "lnbc1..."

@pytest.mark.asyncio
async def test_handle_lnurl_interactive_amount():
    lnurl = "user@domain.com"
    callback_url = "https://domain.com/lnurl/callback"

    with patch("cashu.wallet.lnurl.httpx.AsyncClient") as mock_client:
        mock_instance = mock_client.return_value.__aenter__.return_value
        
        mock_response_1 = MagicMock()
        mock_response_1.json.return_value = {
            "tag": "payRequest",
            "callback": callback_url,
            "minSendable": 1000, # 1 sat
            "maxSendable": 10000000,
            "metadata": "[[\"text/plain\", \"Description\"]]"
        }
        mock_response_1.status_code = 200

        mock_response_2 = MagicMock()
        mock_response_2.json.return_value = {
            "pr": "lnbc1...",
            "status": "OK"
        }
        mock_response_2.status_code = 200

        mock_instance.get.side_effect = [mock_response_1, mock_response_2]

        # Mock user input for 1 sat
        with patch("builtins.input", return_value="1"):
            invoice = await handle_lnurl(lnurl, None)
            assert invoice == "lnbc1..."

@pytest.mark.asyncio
async def test_handle_lnurl_amount_out_of_range():
    lnurl = "user@domain.com"
    amount = 1 # 1 sat = 1000 msat

    with patch("cashu.wallet.lnurl.httpx.AsyncClient") as mock_client:
        mock_instance = mock_client.return_value.__aenter__.return_value
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "tag": "payRequest",
            "callback": "https://callback",
            "minSendable": 2000, # Min 2 sats
            "maxSendable": 10000000,
            "metadata": "[]"
        }
        mock_response.status_code = 200
        mock_instance.get.return_value = mock_response

        invoice = await handle_lnurl(lnurl, amount)
        assert invoice is None

@pytest.mark.asyncio
async def test_handle_lnurl_network_error():
    lnurl = "user@domain.com"
    amount = 1000

    with patch("cashu.wallet.lnurl.httpx.AsyncClient") as mock_client:
        mock_instance = mock_client.return_value.__aenter__.return_value
        mock_instance.get.side_effect = Exception("Network Error")

        invoice = await handle_lnurl(lnurl, amount)
        assert invoice is None