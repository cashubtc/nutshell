import time
from unittest.mock import AsyncMock

import pytest

import cashu.mint.management_rpc.protos.management_pb2 as management_pb2
from cashu.core.base import MeltQuote, MeltQuoteState, MintQuote, MintQuoteState
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from cashu.mint.management_rpc.management_rpc import MintManagementRPC


@pytest.fixture
def rpc_servicer(ledger: Ledger):
    return MintManagementRPC(ledger=ledger)

def test_get_info(rpc_servicer):
    request = management_pb2.GetInfoRequest()
    response = rpc_servicer.GetInfo(request, None)
    
    assert response.name == settings.mint_info_name
    assert response.pubkey == rpc_servicer.ledger.mint_info.pubkey

@pytest.mark.asyncio
async def test_update_motd(rpc_servicer):
    request = management_pb2.UpdateMotdRequest(motd="New Test MOTD")
    response = await rpc_servicer.UpdateMotd(request, None)
    
    assert settings.mint_info_motd == "New Test MOTD"
    assert isinstance(response, management_pb2.UpdateResponse)

@pytest.mark.asyncio
async def test_update_short_description(rpc_servicer):
    request = management_pb2.UpdateDescriptionRequest(description="New Short Desc")
    response = await rpc_servicer.UpdateShortDescription(request, None)
    
    assert settings.mint_info_description == "New Short Desc"
    assert isinstance(response, management_pb2.UpdateResponse)

@pytest.mark.asyncio
async def test_update_long_description(rpc_servicer):
    request = management_pb2.UpdateDescriptionRequest(description="New Long Desc")
    response = await rpc_servicer.UpdateLongDescription(request, None)
    
    assert settings.mint_info_description_long == "New Long Desc"
    assert isinstance(response, management_pb2.UpdateResponse)

@pytest.mark.asyncio
async def test_update_icon_url(rpc_servicer):
    request = management_pb2.UpdateIconUrlRequest(icon_url="http://test.com/icon.png")
    response = await rpc_servicer.UpdateIconUrl(request, None)
    
    assert settings.mint_info_icon_url == "http://test.com/icon.png"
    assert isinstance(response, management_pb2.UpdateResponse)

@pytest.mark.asyncio
async def test_update_name(rpc_servicer):
    request = management_pb2.UpdateNameRequest(name="New Name")
    response = await rpc_servicer.UpdateName(request, None)
    
    assert settings.mint_info_name == "New Name"
    assert isinstance(response, management_pb2.UpdateResponse)

@pytest.mark.asyncio
async def test_add_remove_url(rpc_servicer):
    # Add URL
    request_add = management_pb2.UpdateUrlRequest(url="http://new-url.com")
    await rpc_servicer.AddUrl(request_add, None)
    assert "http://new-url.com" in settings.mint_info_urls

    # Add duplicate URL should raise exception
    with pytest.raises(Exception, match="URL already in mint_info_urls"):
        await rpc_servicer.AddUrl(request_add, None)

    # Remove URL
    request_remove = management_pb2.UpdateUrlRequest(url="http://new-url.com")
    await rpc_servicer.RemoveUrl(request_remove, None)
    assert "http://new-url.com" not in settings.mint_info_urls

    # Remove non-existent URL should raise exception
    with pytest.raises(Exception, match="No such URL in mint_info_urls"):
        await rpc_servicer.RemoveUrl(request_remove, None)

@pytest.mark.asyncio
async def test_add_remove_contact(rpc_servicer):
    settings.mint_info_contact = []
    
    # Add contact
    request_add = management_pb2.UpdateContactRequest(method="email", info="test@example.com")
    await rpc_servicer.AddContact(request_add, None)
    assert ["email", "test@example.com"] in settings.mint_info_contact

    # Add duplicate contact method should raise exception
    with pytest.raises(Exception, match="Contact method already set"):
        await rpc_servicer.AddContact(request_add, None)

    # Remove contact
    request_remove = management_pb2.UpdateContactRequest(method="email")
    await rpc_servicer.RemoveContact(request_remove, None)
    assert ["email", "test@example.com"] not in settings.mint_info_contact

    # Remove non-existent contact should raise exception
    with pytest.raises(Exception, match="Contact method not found"):
        await rpc_servicer.RemoveContact(request_remove, None)

@pytest.mark.asyncio
async def test_update_quote_ttl(rpc_servicer):
    # Test updating mint ttl
    request = management_pb2.UpdateQuoteTtlRequest(mint_ttl=12345)
    await rpc_servicer.UpdateQuoteTtl(request, None)
    assert settings.mint_redis_cache_ttl == 12345

    # Test updating melt ttl
    request = management_pb2.UpdateQuoteTtlRequest(melt_ttl=54321)
    await rpc_servicer.UpdateQuoteTtl(request, None)
    assert settings.mint_redis_cache_ttl == 54321

    # Test no ttl specified
    request_empty = management_pb2.UpdateQuoteTtlRequest()
    with pytest.raises(Exception, match="No quote ttl was specified"):
        await rpc_servicer.UpdateQuoteTtl(request_empty, None)

@pytest.mark.asyncio
async def test_update_lightning_fee(rpc_servicer):
    request = management_pb2.UpdateLightningFeeRequest(fee_percent=1.5)
    await rpc_servicer.UpdateLightningFee(request, None)
    assert settings.lightning_fee_percent == 1.5

    request = management_pb2.UpdateLightningFeeRequest(fee_min_reserve=10)
    await rpc_servicer.UpdateLightningFee(request, None)
    assert settings.lightning_reserve_fee_min == 10

    # Test no fee specified
    request_empty = management_pb2.UpdateLightningFeeRequest()
    with pytest.raises(Exception, match="No fee specified"):
        await rpc_servicer.UpdateLightningFee(request_empty, None)

@pytest.mark.asyncio
async def test_update_auth_limits(rpc_servicer):
    request = management_pb2.UpdateAuthLimitsRequest(auth_rate_limit_per_minute=20)
    await rpc_servicer.UpdateAuthLimits(request, None)
    assert settings.mint_auth_rate_limit_per_minute == 20

    request = management_pb2.UpdateAuthLimitsRequest(auth_max_blind_tokens=50)
    await rpc_servicer.UpdateAuthLimits(request, None)
    assert settings.mint_auth_max_blind_tokens == 50

    request_empty = management_pb2.UpdateAuthLimitsRequest()
    with pytest.raises(Exception, match="No auth limit was specified"):
        await rpc_servicer.UpdateAuthLimits(request_empty, None)

@pytest.mark.asyncio
async def test_rotate_next_keyset(rpc_servicer):
    request = management_pb2.RotateNextKeysetRequest(
        unit="sat",
        input_fee_ppk=2,
        final_expiry=86400,
        max_order=12
    )
    response = await rpc_servicer.RotateNextKeyset(request, None)
    
    assert response.unit == "sat"
    assert response.input_fee_ppk == 2
    assert response.final_expiry == 86400
    assert response.max_order > 0

@pytest.mark.asyncio
async def test_nut04_quote(rpc_servicer):
    quote_id = "test-mint-quote-123"
    
    # Mock get_mint_quote
    mock_quote = MintQuote(
        quote=quote_id,
        method="bolt11",
        request="lnbc...",
        checking_id="chk123",
        unit="sat",
        amount=100,
        state=MintQuoteState.unpaid,
        created_time=int(time.time()),
        expiry=int(time.time()) + 3600,
        mint=None,
        privkey=None
    )
    
    rpc_servicer.ledger.get_mint_quote = AsyncMock(return_value=mock_quote)
    
    # Test GetNut04Quote
    request_get = management_pb2.GetNut04QuoteRequest(quote_id=quote_id)
    response_get = await rpc_servicer.GetNut04Quote(request_get, None)
    
    assert response_get.quote.quote == quote_id
    assert response_get.quote.state == str(MintQuoteState.unpaid)
    assert response_get.quote.amount == 100
    
    # Mock UpdateNut04Quote state update
    rpc_servicer.ledger.db_write._update_mint_quote_state = AsyncMock()
    
    # Test UpdateNut04Quote
    request_update = management_pb2.UpdateQuoteRequest(
        quote_id=quote_id,
        state=MintQuoteState.paid.value
    )
    response_update = await rpc_servicer.UpdateNut04Quote(request_update, None)
    
    assert isinstance(response_update, management_pb2.UpdateResponse)
    rpc_servicer.ledger.db_write._update_mint_quote_state.assert_called_once_with(
        quote_id, MintQuoteState.paid
    )

@pytest.mark.asyncio
async def test_nut05_quote(rpc_servicer):
    quote_id = "test-melt-quote-123"
    
    # Mock get_melt_quote
    mock_quote = MeltQuote(
        quote=quote_id,
        method="bolt11",
        request="lnbc...",
        checking_id="chk123",
        unit="sat",
        amount=100,
        fee_reserve=5,
        state=MeltQuoteState.unpaid,
        created_time=int(time.time()),
        expiry=int(time.time()) + 3600,
        payment_preimage=None,
        error=None,
        mint=None
    )
    
    rpc_servicer.ledger.get_melt_quote = AsyncMock(return_value=mock_quote)
    
    # Test GetNut05Quote
    request_get = management_pb2.GetNut05QuoteRequest(quote_id=quote_id)
    response_get = await rpc_servicer.GetNut05Quote(request_get, None)
    
    assert response_get.quote.quote == quote_id
    assert response_get.quote.state == str(MeltQuoteState.unpaid)
    assert response_get.quote.amount == 100
    assert response_get.quote.fee_reserve == 5
    
    # Mock UpdateNut05Quote state update
    rpc_servicer.ledger.db_write._update_melt_quote_state = AsyncMock()
    
    # Test UpdateNut05Quote
    request_update = management_pb2.UpdateQuoteRequest(
        quote_id=quote_id,
        state=MeltQuoteState.paid.value
    )
    response_update = await rpc_servicer.UpdateNut05Quote(request_update, None)
    
    assert isinstance(response_update, management_pb2.UpdateResponse)
    rpc_servicer.ledger.db_write._update_melt_quote_state.assert_called_once_with(
        quote_id, MeltQuoteState.paid
    )

