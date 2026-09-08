"""Real Spark payments against ``cashu-regtest/start.sh --spark``.

Run with CASHU_SPARK_REGTEST=true; see CONTRIBUTING.md for setup.
Only SDK connection configuration is replaced. Payments, storage, polling,
and event delivery use the installed Breez SDK and the local network.
"""

import asyncio
import copy
import os
from contextlib import suppress
from uuid import uuid4

import bolt11
import breez_sdk_spark as breez
import pytest
import pytest_asyncio
from mnemonic import Mnemonic

from cashu.core.base import Amount, MeltQuote, MeltQuoteState, Unit
from cashu.core.models import PostMeltQuoteRequest
from cashu.core.settings import settings
from cashu.lightning.base import PaymentResult
from cashu.lightning.sparkl2 import SparkL2Wallet
from tests.spark import (
    TIMEOUT,
    assert_preimage,
    connect_spark,
    lightning,
    local_spark_config,
    wait_balance,
    wait_invoice,
    wait_payment,
)

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        os.getenv("CASHU_SPARK_REGTEST", "").lower() != "true",
        reason="requires CASHU_SPARK_REGTEST=true and cashu-regtest/start.sh --spark",
    ),
]


@pytest.fixture(scope="session", autouse=True)
def mint():
    """These backend tests do not need the parent conftest's HTTP mint server."""


@pytest_asyncio.fixture
async def spark_wallet_factory(monkeypatch, tmp_path):
    config = await local_spark_config()

    def local_config(network):
        assert network == breez.Network.REGTEST
        return copy.deepcopy(config)

    monkeypatch.setattr(breez, "default_config", local_config)
    monkeypatch.setattr(breez, "connect", connect_spark)
    monkeypatch.setattr(settings, "mint_spark_network", "REGTEST")
    monkeypatch.setattr(settings, "mint_spark_api_key", None)
    monkeypatch.setattr(settings, "mint_spark_mnemonic", Mnemonic("english").generate())
    monkeypatch.setattr(settings, "cashu_dir", str(tmp_path))
    wallets = []

    async def create(unit):
        wallet = SparkL2Wallet(unit=unit)
        wallets.append(wallet)
        status = await asyncio.wait_for(wallet.status(), TIMEOUT)
        assert not status.error_message, status.error_message
        assert wallet.sdk is not None
        return wallet

    yield create

    for wallet in wallets:
        if wallet.sdk is not None:
            await asyncio.wait_for(wallet.sdk.disconnect(), TIMEOUT)
            wallet.sdk = None


@pytest.mark.parametrize("unit", [Unit.sat, Unit.msat], ids=lambda unit: unit.name)
@pytest.mark.parametrize("peer", ["lnd", "cln"])
async def test_spark_lightning_round_trip(spark_wallet_factory, unit, peer):
    wallet = await spark_wallet_factory(unit)
    await wait_balance(wallet, 0)
    missing = await wallet.get_payment_status(str(uuid4()))
    assert missing.result == PaymentResult.UNKNOWN

    # Receive through Nutshell, including msat -> sat rounding and the listener.
    # This also funds the isolated wallet for the outgoing half of the test.
    receive_sats = 20_001
    requested = Amount(unit, receive_sats if unit == Unit.sat else 20_000_001)
    memo = f"nutshell-spark-{uuid4()}"
    invoice = await wallet.create_invoice(requested, memo=memo)
    assert invoice.ok, invoice.error_message
    assert invoice.payment_request
    assert invoice.checking_id
    decoded = bolt11.decode(invoice.payment_request)
    assert decoded.currency == "bcrt"
    assert decoded.amount_msat == receive_sats * 1000
    assert decoded.description == memo
    assert decoded.payment_hash == invoice.checking_id
    unpaid = await wallet.get_invoice_status(invoice.checking_id)
    assert unpaid.result in (PaymentResult.UNKNOWN, PaymentResult.PENDING)

    stream = wallet.paid_invoices_stream()
    event = asyncio.create_task(stream.__anext__())
    try:
        if peer == "lnd":
            received = await lightning(
                peer,
                "payinvoice",
                "--force",
                "--json",
                "--fee_limit=100",
                invoice.payment_request,
            )
            assert received["status"] == "SUCCEEDED", received
        else:
            received = await lightning(peer, "pay", invoice.payment_request)
            assert received["status"] == "complete", received
        assert received["payment_hash"] == invoice.checking_id
        assert_preimage(received["payment_preimage"], invoice.checking_id)
        assert await asyncio.wait_for(event, TIMEOUT) == invoice.checking_id
    finally:
        event.cancel()
        with suppress(asyncio.CancelledError):
            await event
        await stream.aclose()
    await wait_invoice(wallet, invoice.checking_id)
    await wait_balance(wallet, receive_sats)

    # Send to the same Lightning peer, verifying quote units and actual fees.
    send_sats = 3000
    if peer == "lnd":
        outgoing = await lightning(peer, "addinvoice", str(send_sats))
        request = outgoing["payment_request"]
    else:
        outgoing = await lightning(peer, "invoice", str(send_sats * 1000), memo, memo)
        request = outgoing["bolt11"]
    payment_hash = bolt11.decode(request).payment_hash
    payment_quote = await wallet.get_payment_quote(
        PostMeltQuoteRequest(request=request, unit=unit.name)
    )
    assert payment_quote.checking_id == payment_hash
    assert payment_quote.amount == Amount(Unit.sat, send_sats).to(unit)
    assert payment_quote.fee.unit == unit
    assert payment_quote.fee.amount >= 0
    quote = MeltQuote(
        quote=str(uuid4()),
        method="bolt11",
        unit=unit.name,
        state=MeltQuoteState.unpaid,
        request=request,
        checking_id=payment_quote.checking_id,
        amount=payment_quote.amount.amount,
        fee_reserve=payment_quote.fee.amount,
    )
    fee_limit_msat = payment_quote.fee.to(Unit.msat).amount
    payment = await asyncio.wait_for(wallet.pay_invoice(quote, fee_limit_msat), TIMEOUT)
    assert payment.result in (PaymentResult.SETTLED, PaymentResult.PENDING), payment
    assert payment.checking_id
    settled = await wait_payment(wallet, payment.checking_id)
    assert_preimage(settled.preimage, payment_hash)
    assert settled.fee is not None
    assert settled.fee.unit == unit
    assert 0 <= settled.fee.to(Unit.msat).amount <= fee_limit_msat
    if payment.settled:
        if payment.preimage is not None:
            assert payment.preimage == settled.preimage
        assert payment.fee == settled.fee

    if peer == "lnd":
        peer_invoice = await lightning(peer, "lookupinvoice", payment_hash)
        assert peer_invoice["state"] == "SETTLED"
        assert int(peer_invoice["amt_paid_sat"]) == send_sats
        assert peer_invoice["r_preimage"] == settled.preimage
    else:
        peer_invoice = (await lightning(peer, "listinvoices", memo))["invoices"][0]
        assert peer_invoice["status"] == "paid"
        assert peer_invoice["amount_received_msat"] == send_sats * 1000
        assert peer_invoice["payment_preimage"] == settled.preimage

    remaining_sats = receive_sats - send_sats - settled.fee.to(Unit.sat).amount
    await wait_balance(wallet, remaining_sats)

    # Reopen the same seed/storage to verify persisted backend status and fees.
    assert wallet.sdk is not None
    await wallet.sdk.disconnect()
    wallet.sdk = None
    reopened = await spark_wallet_factory(unit)
    await wait_balance(reopened, remaining_sats)
    await wait_invoice(reopened, invoice.checking_id)
    restored = await wait_payment(reopened, payment.checking_id)
    assert restored.preimage == settled.preimage
    assert restored.fee == settled.fee
    restored_by_hash = await wait_payment(reopened, payment_quote.checking_id)
    assert restored_by_hash == restored
