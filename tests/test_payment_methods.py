import pytest

from cashu.core.base import MeltQuote, MeltQuoteState, MintQuote, MintQuoteState
from cashu.core.models import PostMeltQuoteResponse, PostMintQuoteResponse
from cashu.payment import payment_method_registry
from cashu.payment.registry import PaymentMethodRegistry


def test_builtin_bolt11_payment_method_is_registered():
    assert payment_method_registry.get("bolt11").method == "bolt11"


@pytest.mark.parametrize("method", ["", "BOLT11", "has space", "../bolt11"])
def test_payment_method_names_are_safe_route_segments(method: str):
    with pytest.raises(ValueError):
        PaymentMethodRegistry.validate_method(method)


def test_mint_quote_response_only_exposes_method_data():
    quote = MintQuote(
        quote="quote-id",
        method="testpay",
        request="case-sensitive-request",
        checking_id="secret-checking-id",
        unit="sat",
        amount=10,
        state=MintQuoteState.paid,
        created_time=123,
        method_data={"payment_url": "https://example.test/pay"},
    )

    response = PostMintQuoteResponse.from_mint_quote(quote).model_dump()

    assert response["payment_url"] == "https://example.test/pay"
    assert "checking_id" not in response
    assert "created_time" not in response
    assert "state_val" not in response


def test_melt_quote_response_only_exposes_method_data():
    quote = MeltQuote(
        quote="quote-id",
        method="testpay",
        request="case-sensitive-request",
        checking_id="secret-checking-id",
        unit="sat",
        amount=10,
        fee_reserve=1,
        state=MeltQuoteState.unpaid,
        created_time=123,
        method_data={"destination": "merchant-123"},
    )

    response = PostMeltQuoteResponse.from_melt_quote(quote).model_dump()

    assert response["destination"] == "merchant-123"
    assert "checking_id" not in response
    assert "created_time" not in response
