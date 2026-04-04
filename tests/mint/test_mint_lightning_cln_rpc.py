import importlib

import pytest

from cashu.core.base import Amount, MeltQuote, MeltQuoteState, Unit
from cashu.core.models import PostMeltQuoteRequest
from cashu.core.settings import settings
from cashu.lightning.base import PaymentResult, Unsupported
from cashu.lightning.cln_rpc import CLNRPCWallet

settings.mint_cln_rpc_socket = (
    settings.mint_cln_rpc_socket or "~/.lightning/bitcoin/lightning-rpc"
)

wallet = CLNRPCWallet(unit=Unit.sat)
payment_request = (
    "lnbc10u1pjap7phpp50s9lzr3477j0tvacpfy2ucrs4q0q6cvn232ex7nt2zqxxxj8gxrsdpv2phhwetjv4jzqcneypqyc6t8dp6xu6twva2xjuzzda6qcqzzsxqrrsss"
    "p575z0n39w2j7zgnpqtdlrgz9rycner4eptjm3lz363dzylnrm3h4s9qyyssqfz8jglcshnlcf0zkw4qu8fyr564lg59x5al724kms3h6gpuhx9xrfv27tgx3l3u3cyf6"
    "3r52u0xmac6max8mdupghfzh84t4hfsvrfsqwnuszf"
)  # 1000 sat


@pytest.mark.asyncio
async def test_cln_rpc_status(monkeypatch):
    async def fake_rpc_call(method, params=None):
        assert method == "listfunds"
        return {
            "channels": [
                {"our_amount_msat": 1000},
                {"our_amount_msat": "2000msat"},
                {"our_amount_msat": {"msat": "3000msat"}},
            ]
        }

    monkeypatch.setattr(wallet, "_rpc_call", fake_rpc_call)
    status = await wallet.status()
    assert status.error_message is None
    assert status.balance == Amount(Unit.sat, 6)


@pytest.mark.asyncio
async def test_cln_rpc_status_error(monkeypatch):
    async def fake_rpc_call(method, params=None):
        raise Exception("rpc down")

    monkeypatch.setattr(wallet, "_rpc_call", fake_rpc_call)
    status = await wallet.status()
    assert status.balance == Amount(Unit.sat, 0)
    assert status.error_message
    assert "rpc down" in status.error_message


@pytest.mark.asyncio
async def test_cln_rpc_create_invoice(monkeypatch):
    async def fake_rpc_call(method, params=None):
        assert method == "invoice"
        assert params and params["amount_msat"] == 1000 * 1000
        return {"payment_hash": "hash123", "bolt11": payment_request}

    monkeypatch.setattr(wallet, "_rpc_call", fake_rpc_call)
    invoice = await wallet.create_invoice(Amount(Unit.sat, 1000), "memo")
    assert invoice.ok
    assert invoice.checking_id == "hash123"
    assert invoice.payment_request == payment_request


@pytest.mark.asyncio
async def test_cln_rpc_create_invoice_description_hash_unsupported():
    with pytest.raises(Unsupported):
        await wallet.create_invoice(Amount(Unit.sat, 1000), description_hash=b"hash")


@pytest.mark.asyncio
async def test_cln_rpc_get_invoice_status_maps_paid(monkeypatch):
    async def fake_rpc_call(method, params=None):
        assert method == "listinvoices"
        return {"invoices": [{"status": "paid"}]}

    monkeypatch.setattr(wallet, "_rpc_call", fake_rpc_call)
    status = await wallet.get_invoice_status("hash123")
    assert status.result == PaymentResult.SETTLED


@pytest.mark.asyncio
async def test_cln_rpc_get_payment_status_maps_complete(monkeypatch):
    async def fake_rpc_call(method, params=None):
        assert method == "listpays"
        return {
            "pays": [
                {
                    "status": "complete",
                    "amount_msat": "1000000msat",
                    "amount_sent_msat": "1002000msat",
                    "preimage": "pre123",
                }
            ]
        }

    monkeypatch.setattr(wallet, "_rpc_call", fake_rpc_call)
    status = await wallet.get_payment_status("hash123")
    assert status.result == PaymentResult.SETTLED
    assert status.fee == Amount(Unit.msat, 2000)
    assert status.preimage == "pre123"


@pytest.mark.asyncio
async def test_cln_rpc_get_payment_quote():
    melt_quote_request = PostMeltQuoteRequest(
        unit=Unit.sat.name,
        request=payment_request,
    )
    quote = await wallet.get_payment_quote(melt_quote_request)
    assert quote.amount == Amount(Unit.sat, 1000)
    assert quote.checking_id
    assert quote.fee == Amount(Unit.sat, 20)


@pytest.mark.asyncio
async def test_cln_rpc_paid_invoices_stream_is_empty():
    seen = []
    async for item in wallet.paid_invoices_stream():
        seen.append(item)
    assert seen == []


@pytest.mark.asyncio
async def test_cln_rpc_pay_invoice_failure_on_decode_error():
    quote = MeltQuote(
        request="not-a-bolt11",
        quote="q1",
        method="bolt11",
        checking_id="check1",
        unit="sat",
        amount=1000,
        fee_reserve=20,
        state=MeltQuoteState.unpaid,
    )
    payment = await wallet.pay_invoice(quote, 1000)
    assert payment.result == PaymentResult.FAILED
    assert payment.error_message


def test_cln_rpc_backend_instantiation_from_settings(monkeypatch, tmp_path):
    socket_path = tmp_path / "lightning-rpc"
    monkeypatch.setattr(settings, "mint_backend_bolt11_sat", "CLNRPCWallet")
    monkeypatch.setattr(settings, "mint_cln_rpc_socket", str(socket_path))

    wallets_module = importlib.import_module("cashu.lightning")
    wallet_class = getattr(wallets_module, settings.mint_backend_bolt11_sat)
    backend = wallet_class(unit=Unit.sat)

    assert backend.__class__.__name__ == "CLNRPCWallet"
    assert backend.socket_path == str(socket_path)
