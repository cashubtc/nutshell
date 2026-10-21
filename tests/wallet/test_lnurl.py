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

    with patch("cashu.wallet.lnurl.httpx.AsyncClient") as mock_client, \
         patch("cashu.wallet.lnurl.bolt11.decode") as mock_decode:
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

        mock_invoice = MagicMock()
        mock_invoice.amount_msat = amount * 1000
        mock_invoice.description_hash = None
        mock_decode.return_value = mock_invoice

        invoice = await handle_lnurl(lnurl, amount)
        assert invoice == "lnbc1..."

@pytest.mark.asyncio
async def test_handle_lnurl_interactive_amount():
    lnurl = "user@domain.com"
    callback_url = "https://domain.com/lnurl/callback"

    with patch("cashu.wallet.lnurl.httpx.AsyncClient") as mock_client, \
         patch("cashu.wallet.lnurl.bolt11.decode") as mock_decode:
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

        mock_invoice = MagicMock()
        mock_invoice.amount_msat = 1000  # 1 sat = 1000 msat
        mock_invoice.description_hash = None
        mock_decode.return_value = mock_invoice

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


@pytest.mark.asyncio
async def test_handle_lnurl_rejects_amount_mismatch():
    """
    Regression test for missing LUD-06 step 7 verification:
    'LN WALLET Verifies that amount in provided invoice equals the amount
    previously specified by user.'

    A malicious (or compromised) LNURL service can return a bolt11 invoice
    whose amount differs from what the user requested. ``handle_lnurl``
    must decode the returned invoice and reject any amount mismatch instead
    of blindly forwarding the invoice to the caller -- otherwise users who
    have suppressed the CLI confirmation (e.g. via ``--yes``), or any
    programmatic caller, will pay an attacker-chosen amount.
    """
    # Real bolt11 invoice for 10u BTC = 1000 sats = 1_000_000 msat
    invoice_for_1000_sats = (
        "lnbc10u1pjap7phpp50s9lzr3477j0tvacpfy2ucrs4q0q6cvn232ex7nt2zqxxxj"
        "8gxrsdpv2phhwetjv4jzqcneypqyc6t8dp6xu6twva2xjuzzda6qcqzzsxqrrsss"
        "p575z0n39w2j7zgnpqtdlrgz9rycner4eptjm3lz363dzylnrm3h4s9qyyssqfz8"
        "jglcshnlcf0zkw4qu8fyr564lg59x5al724kms3h6gpuhx9xrfv27tgx3l3u3cyf"
        "63r52u0xmac6max8mdupghfzh84t4hfsvrfsqwnuszf"
    )

    # User requests 100 sats (100_000 msat); the LNURL service returns an
    # invoice for 1000 sats (10x). Must be rejected.
    user_requested_sats = 100

    with patch("cashu.wallet.lnurl.httpx.AsyncClient") as mock_client:
        mock_instance = mock_client.return_value.__aenter__.return_value

        info_resp = MagicMock()
        info_resp.json.return_value = {
            "tag": "payRequest",
            "callback": "https://domain.com/lnurl/callback",
            "minSendable": 1000,
            "maxSendable": 100000000,
            "metadata": "[[\"text/plain\", \"Description\"]]",
        }
        info_resp.status_code = 200

        invoice_resp = MagicMock()
        invoice_resp.json.return_value = {"pr": invoice_for_1000_sats, "status": "OK"}
        invoice_resp.status_code = 200

        mock_instance.get.side_effect = [info_resp, invoice_resp]

        invoice = await handle_lnurl("user@domain.com", user_requested_sats)

    assert invoice is None, (
        "LUD-06 step 7 violation: wallet returned a bolt11 invoice whose "
        f"amount (1000 sats) differs from the user-requested {user_requested_sats} sats"
    )


@pytest.mark.asyncio
async def test_handle_lnurl_rejects_description_hash_mismatch():
    """
    Verifies that handle_lnurl rejects an invoice if its description_hash is present
    but does not match the metadata hash from the LNURL service.
    """
    # Real bolt11 invoice for 10u BTC = 1000 sats = 1_000_000 msat, but with a description_hash
    # We can use a mock for bolt11.decode instead of a real invoice
    user_requested_sats = 1000
    callback_url = "https://domain.com/lnurl/callback"
    metadata_str = "[[\"text/plain\", \"Description\"]]"

    with patch("cashu.wallet.lnurl.httpx.AsyncClient") as mock_client, \
         patch("cashu.wallet.lnurl.bolt11.decode") as mock_decode:
        mock_instance = mock_client.return_value.__aenter__.return_value

        info_resp = MagicMock()
        info_resp.json.return_value = {
            "tag": "payRequest",
            "callback": callback_url,
            "minSendable": 1000,
            "maxSendable": 100000000,
            "metadata": metadata_str,
        }
        info_resp.status_code = 200

        invoice_resp = MagicMock()
        invoice_resp.json.return_value = {"pr": "lnbc1...", "status": "OK"}
        invoice_resp.status_code = 200

        mock_instance.get.side_effect = [info_resp, invoice_resp]

        # Mock the decoded invoice with a wrong description_hash
        mock_invoice = MagicMock()
        mock_invoice.amount_msat = user_requested_sats * 1000
        mock_invoice.description_hash = "wrong_hash"
        mock_decode.return_value = mock_invoice

        invoice = await handle_lnurl("user@domain.com", user_requested_sats)

    assert invoice is None, "Wallet should reject invoice with mismatched description_hash"