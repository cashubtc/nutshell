from unittest.mock import AsyncMock, Mock, patch

import pytest
from bolt11 import Bolt11

from cashu.core.base import MeltQuote, MeltQuoteState, Unit
from cashu.lightning.base import PaymentResult
from cashu.lightning.clnrest import CLNRestWallet


def create_melt_quote(
    amount: int, unit: str = "msat", request: str = "lnbc10u1p0example"
) -> MeltQuote:
    return MeltQuote(
        quote="quote_test_123",
        method="bolt11",
        request=request,
        checking_id="checking_id_test",
        unit=unit,
        amount=amount,
        fee_reserve=1000,
        state=MeltQuoteState.unpaid,
        created_time=None,
        paid_time=None,
    )


@pytest.fixture
def wallet(monkeypatch: pytest.MonkeyPatch) -> CLNRestWallet:
    monkeypatch.setattr(
        "cashu.lightning.clnrest.settings.mint_clnrest_url", "https://localhost:3010"
    )
    monkeypatch.setattr(
        "cashu.lightning.clnrest.settings.mint_clnrest_rune", "test_rune"
    )
    monkeypatch.setattr("cashu.lightning.clnrest.settings.mint_clnrest_cert", False)
    monkeypatch.setattr(
        "cashu.lightning.clnrest.settings.mint_clnrest_enable_mpp", True
    )
    monkeypatch.setattr(
        "cashu.lightning.clnrest.settings.mint_retry_exponential_backoff_base_delay", 1
    )
    monkeypatch.setattr(
        "cashu.lightning.clnrest.settings.mint_retry_exponential_backoff_max_delay", 10
    )

    mock_client = Mock()
    mock_client.post = AsyncMock()
    monkeypatch.setattr(
        "cashu.lightning.clnrest.httpx.AsyncClient", Mock(return_value=mock_client)
    )

    wallet = CLNRestWallet(unit=Unit.sat)
    wallet.supports_mpp = True
    return wallet


@pytest.mark.asyncio
async def test_mpp_detection_routes_to_partial(wallet: CLNRestWallet):
    with patch("cashu.lightning.clnrest.decode") as mock_decode:
        mock_invoice = Mock(spec=Bolt11)
        mock_invoice.payment_hash = "hash789"
        mock_invoice.amount_msat = 1000000
        mock_decode.return_value = mock_invoice

        wallet.client.post = AsyncMock(
            return_value=Mock(
                is_error=False,
                json=lambda: {
                    "payment_hash": "hash789",
                    "payment_preimage": "preimage_mpp",
                    "amount_sent_msat": 600100,
                    "amount_msat": 600000,
                    "status": "complete",
                },
            )
        )

        quote = create_melt_quote(amount=600000, unit="msat")
        fee_limit_msat = 1000

        result = await wallet.pay_invoice(quote, fee_limit_msat)

        assert result.result == PaymentResult.SETTLED
        assert result.preimage == "preimage_mpp"
        call_data = wallet.client.post.call_args.kwargs["data"]
        assert "partial_msat" in call_data, "partial_msat must be sent to CLN for MPP"
        assert call_data["partial_msat"] == 600000


@pytest.mark.asyncio
async def test_mpp_disabled_returns_error(wallet: CLNRestWallet):
    wallet.supports_mpp = False

    with patch("cashu.lightning.clnrest.decode") as mock_decode:
        mock_invoice = Mock(spec=Bolt11)
        mock_invoice.payment_hash = "hash123"
        mock_invoice.amount_msat = 1000000
        mock_decode.return_value = mock_invoice

        quote = create_melt_quote(amount=600000, unit="msat")

        result = await wallet.pay_invoice(quote, 1000)

        assert result.result == PaymentResult.FAILED
        assert result.error_message is not None
        assert "does not support MPP" in result.error_message


@pytest.mark.asyncio
async def test_full_payment_no_mpp(wallet: CLNRestWallet):
    with patch("cashu.lightning.clnrest.decode") as mock_decode:
        mock_invoice = Mock(spec=Bolt11)
        mock_invoice.payment_hash = "full_payment_hash"
        mock_invoice.amount_msat = 1000000
        mock_decode.return_value = mock_invoice

        quote = create_melt_quote(amount=1000000, unit="msat")

        wallet.client.post = AsyncMock(
            return_value=Mock(
                is_error=False,
                json=lambda: {
                    "payment_hash": "full_payment_hash",
                    "payment_preimage": "preimage123",
                    "amount_sent_msat": 1000100,
                    "amount_msat": 1000000,
                    "status": "complete",
                },
            )
        )

        result = await wallet.pay_invoice(quote, 1000)

        assert result.result == PaymentResult.SETTLED
        assert result.preimage == "preimage123"
        call_data = wallet.client.post.call_args.kwargs["data"]
        assert "partial_msat" not in call_data, "partial_msat must not be sent for full payments"

