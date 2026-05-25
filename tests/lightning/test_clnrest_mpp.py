from unittest.mock import AsyncMock, Mock, patch

import pytest
from bolt11 import Bolt11

from cashu.core.base import Amount, MeltQuote, MeltQuoteState, Unit
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
async def test_pay_partial_invoice_success(wallet: CLNRestWallet):
    with patch("cashu.lightning.clnrest.decode") as mock_decode:
        mock_invoice = Mock(spec=Bolt11)
        mock_invoice.payment_hash = "abc123def456"
        mock_invoice.amount_msat = 1000000
        mock_decode.return_value = mock_invoice

        wallet.client.post = AsyncMock(
            return_value=Mock(
                is_error=False,
                json=lambda: {
                    "payment_hash": "abc123def456",
                    "payment_preimage": "preimage_partial",
                    "amount_sent_msat": 600100,
                    "amount_msat": 600000,
                    "status": "complete",
                },
            )
        )

        quote = create_melt_quote(amount=600000, unit="msat")
        amount = Amount(Unit.msat, 600000)
        fee_limit = 1000

        result = await wallet.pay_partial_invoice(quote, amount, fee_limit)

        assert result.result == PaymentResult.SETTLED
        assert result.checking_id == "abc123def456"
        assert result.preimage == "preimage_partial"
        assert result.fee is not None
        wallet.client.post.assert_called_once()  # type: ignore[attr-defined]


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


@pytest.mark.asyncio
async def test_invalid_invoice_decode_error(wallet: CLNRestWallet):
    with patch("cashu.lightning.clnrest.decode") as mock_decode:
        from bolt11 import Bolt11Exception

        mock_decode.side_effect = Bolt11Exception("Invalid invoice")

        quote = create_melt_quote(amount=600000, unit="msat")
        amount = Amount(Unit.msat, 600000)

        result = await wallet.pay_partial_invoice(quote, amount, 1000)

        assert result.result == PaymentResult.FAILED
        assert result.error_message is not None
        assert "Invalid invoice" in result.error_message


@pytest.mark.asyncio
async def test_fee_limit_calculation(wallet: CLNRestWallet):
    with patch("cashu.lightning.clnrest.decode") as mock_decode:
        mock_invoice = Mock(spec=Bolt11)
        mock_invoice.payment_hash = "fee_test_hash"
        mock_invoice.amount_msat = 1000000
        mock_decode.return_value = mock_invoice

        quote = create_melt_quote(amount=600000, unit="msat")
        amount = Amount(Unit.msat, 600000)
        fee_limit_msat = 600

        async def mock_post_side_effect(*args, **kwargs):
            post_data = kwargs.get("data", {})
            maxfeepercent = float(post_data.get("maxfeepercent", "0"))
            expected_fee_percent = (fee_limit_msat / 600000) * 100
            assert abs(maxfeepercent - expected_fee_percent) < 0.001

            return Mock(
                is_error=False,
                json=lambda: {
                    "payment_hash": "fee_test_hash",
                    "payment_preimage": "preimage_fee",
                    "amount_sent_msat": 600100,
                    "amount_msat": 600000,
                    "status": "complete",
                },
            )

        wallet.client.post = AsyncMock(side_effect=mock_post_side_effect)

        await wallet.pay_partial_invoice(quote, amount, fee_limit_msat)

        wallet.client.post.assert_called_once()


@pytest.mark.asyncio
async def test_partial_msat_parameter_sent_to_cln(wallet: CLNRestWallet):
    with patch("cashu.lightning.clnrest.decode") as mock_decode:
        mock_invoice = Mock(spec=Bolt11)
        mock_invoice.payment_hash = "cln_param_test"
        mock_invoice.amount_msat = 1000000
        mock_decode.return_value = mock_invoice

        quote = create_melt_quote(amount=600000, unit="msat")
        amount = Amount(Unit.msat, 600000)

        async def verify_partial_msat(*args, **kwargs):
            post_data = kwargs.get("data", {})
            assert "partial_msat" in post_data
            assert post_data["partial_msat"] == 600000
            assert "bolt11" in post_data

            return Mock(
                is_error=False,
                json=lambda: {
                    "payment_hash": "cln_param_test",
                    "payment_preimage": "preimage_param",
                    "amount_sent_msat": 600100,
                    "amount_msat": 600000,
                    "status": "complete",
                },
            )

        wallet.client.post = AsyncMock(side_effect=verify_partial_msat)

        await wallet.pay_partial_invoice(quote, amount, 1000)

        wallet.client.post.assert_called_once()


@pytest.mark.asyncio
async def test_amount_unit_conversion(wallet: CLNRestWallet):
    with patch("cashu.lightning.clnrest.decode") as mock_decode:
        mock_invoice = Mock(spec=Bolt11)
        mock_invoice.payment_hash = "unit_test"
        mock_invoice.amount_msat = 1000000
        mock_decode.return_value = mock_invoice

        wallet.client.post = AsyncMock(
            return_value=Mock(
                is_error=False,
                json=lambda: {
                    "payment_hash": "unit_test",
                    "payment_preimage": "preimage_unit",
                    "amount_sent_msat": 600100,
                    "amount_msat": 600000,
                    "status": "complete",
                },
            )
        )

        amount_sat = Amount(Unit.sat, 600)
        amount_msat = amount_sat.to(Unit.msat).amount

        assert amount_msat == 600000

        quote = create_melt_quote(amount=600, unit="sat")

        result = await wallet.pay_partial_invoice(quote, amount_sat, 1000)

        assert result.result == PaymentResult.SETTLED
