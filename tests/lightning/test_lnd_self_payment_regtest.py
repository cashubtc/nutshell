import importlib

import pytest

from cashu.core.base import Amount, MeltQuote, MeltQuoteState, Unit
from cashu.core.settings import settings
from cashu.lightning.base import LightningBackend, PaymentResult

LND_BACKENDS = {"LndRPCWallet", "LndRestWallet"}


@pytest.mark.asyncio
async def test_lnd_can_pay_its_own_invoice_when_enabled(monkeypatch):
    backend_name = settings.mint_backend_bolt11_sat
    if backend_name not in LND_BACKENDS:
        pytest.skip("requires an LND regtest backend")

    monkeypatch.setattr(settings, "mint_lnd_allow_self_payment", True)
    wallets_module = importlib.import_module("cashu.lightning")
    backend: LightningBackend = getattr(wallets_module, backend_name)(unit=Unit.sat)

    try:
        invoice = await backend.create_invoice(
            Amount(unit=Unit.sat, amount=10), memo="self-payment integration test"
        )
        assert invoice.ok
        assert invoice.payment_request
        assert invoice.checking_id

        quote = MeltQuote(
            quote="self-payment-integration-test",
            method="bolt11",
            request=invoice.payment_request,
            checking_id=invoice.checking_id,
            unit=Unit.sat.name,
            amount=10,
            fee_reserve=10,
            state=MeltQuoteState.unpaid,
        )
        payment = await backend.pay_invoice(quote, fee_limit_msat=10_000)

        assert payment.result == PaymentResult.SETTLED, payment.error_message
        assert payment.checking_id == invoice.checking_id
        assert payment.preimage

        invoice_status = await backend.get_invoice_status(invoice.checking_id)
        assert invoice_status.result == PaymentResult.SETTLED
    finally:
        client = getattr(backend, "client", None)
        if client is not None:
            await client.aclose()
