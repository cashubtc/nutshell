from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock

import bolt11
import grpc
import pytest

from cashu.core.base import (
    Amount,
    BlindedMessage,
    MeltQuote,
    MeltQuoteState,
    MintQuote,
    MintQuoteState,
    Unit,
)
from cashu.core.crypto.b_dhke import step1_alice
from cashu.core.models import PostMeltQuoteRequest, PostMintQuoteRequest
from cashu.lightning.base import PaymentResult
from cashu.mint.ledger import Ledger
from cashu.payment import payment_method_registry
from cashu.payment.grpc import payment_processor_pb2 as pb
from cashu.payment.grpc import payment_processor_pb2_grpc as pb_grpc
from cashu.payment.grpc_processor import (
    CDK_PAYMENT_PROCESSOR_PROTOCOL_VERSION,
    CDK_VERSION_HEADER,
    GrpcPaymentProcessor,
)


class FakeCdkProcessor(pb_grpc.CdkPaymentProcessorServicer):
    def __init__(self) -> None:
        self.requests = []

    @staticmethod
    def _check_version(context) -> None:
        metadata = dict(context.invocation_metadata())
        assert metadata[CDK_VERSION_HEADER] == CDK_PAYMENT_PROCESSOR_PROTOCOL_VERSION

    async def GetSettings(self, request, context):
        self._check_version(context)
        return pb.SettingsResponse(
            unit="sat", custom={"testpay": json.dumps({"reusable": True})}
        )

    async def CreatePayment(self, request, context):
        self._check_version(context)
        self.requests.append(request)
        assert request.options.custom.quote_id == "mint-quote"
        assert json.loads(request.options.custom.extra_json) == {"account": "alice"}
        return pb.CreatePaymentResponse(
            request_identifier=pb.PaymentIdentifier(
                type=pb.PAYMENT_IDENTIFIER_TYPE_CUSTOM_ID, id="incoming-1"
            ),
            request="external-request",
            expiry=1234,
            extra_json=json.dumps({"payment_url": "https://processor.test/pay"}),
        )

    async def CheckIncomingPayment(self, request, context):
        self._check_version(context)
        assert request.request_identifier.id == "incoming-1"
        return pb.CheckIncomingPaymentResponse(
            payments=[
                pb.WaitIncomingPaymentResponse(
                    payment_identifier=pb.PaymentIdentifier(
                        type=pb.PAYMENT_IDENTIFIER_TYPE_PAYMENT_ID, id="payment-1"
                    ),
                    payment_amount=pb.AmountMessage(value=21, unit="sat"),
                    payment_id="payment-1",
                )
            ]
        )

    async def GetPaymentQuote(self, request, context):
        self._check_version(context)
        assert request.quote_id == "melt-quote"
        assert request.request_type == pb.OUTGOING_PAYMENT_REQUEST_TYPE_CUSTOM
        assert json.loads(request.extra_json) == {
            "account": "alice",
            "options": {
                "custom_confirmation": 3,
                "routing": {"hints": ["fast", "cheap"]},
            },
        }
        return pb.PaymentQuoteResponse(
            request_identifier=pb.PaymentIdentifier(
                type=pb.PAYMENT_IDENTIFIER_TYPE_CUSTOM_ID, id="outgoing-1"
            ),
            amount=pb.AmountMessage(value=20, unit="sat"),
            fee=pb.AmountMessage(value=2, unit="sat"),
            state=pb.QUOTE_STATE_UNPAID,
            extra_json=json.dumps({"destination": "merchant-1"}),
        )

    async def MakePayment(self, request, context):
        self._check_version(context)
        assert request.payment_options.custom.quote_id == "melt-quote"
        return pb.MakePaymentResponse(
            payment_identifier=pb.PaymentIdentifier(
                type=pb.PAYMENT_IDENTIFIER_TYPE_PAYMENT_ID, id="payment-2"
            ),
            payment_proof="proof",
            status=pb.QUOTE_STATE_PAID,
            total_spent=pb.AmountMessage(value=21, unit="sat"),
        )

    async def CheckOutgoingPayment(self, request, context):
        self._check_version(context)
        assert request.request_identifier.id == "outgoing-1"
        return pb.MakePaymentResponse(
            payment_identifier=request.request_identifier,
            payment_proof="proof",
            status=pb.QUOTE_STATE_PAID,
            total_spent=pb.AmountMessage(value=21, unit="sat"),
        )


@pytest.mark.asyncio
async def test_grpc_payment_processor_is_cdk_compatible():
    service = FakeCdkProcessor()
    server = grpc.aio.server()
    pb_grpc.add_CdkPaymentProcessorServicer_to_server(service, server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()

    processor = GrpcPaymentProcessor(
        "testpay",
        Unit.sat,
        {
            "endpoint": f"127.0.0.1:{port}",
            "allow_insecure": True,
        },
    )
    try:
        await processor.start(processor)
        assert processor.settings_for(processor, Unit.sat).options == {"reusable": True}

        incoming = await processor.create_incoming_payment(
            processor,
            PostMintQuoteRequest(amount=20, unit="sat", account="alice"),
            "mint-quote",
        )
        assert incoming.payment_request == "external-request"
        assert incoming.model_extra == {
            "payment_url": "https://processor.test/pay",
            "expiry": 1234,
        }

        incoming_status = await processor.get_incoming_payment_status(
            processor,
            MintQuote(
                quote="mint-quote",
                method="testpay",
                request="external-request",
                checking_id=incoming.checking_id,
                unit="sat",
                amount=20,
                state=MintQuoteState.unpaid,
            ),
        )
        assert incoming_status.result == PaymentResult.SETTLED
        assert incoming_status.amount_paid == Amount(Unit.sat, 21)

        partial_status = await processor.get_incoming_payment_status(
            processor,
            MintQuote(
                quote="larger-mint-quote",
                method="testpay",
                request="external-request",
                checking_id=incoming.checking_id,
                unit="sat",
                amount=22,
                state=MintQuoteState.unpaid,
            ),
        )
        assert partial_status.result == PaymentResult.PENDING
        assert partial_status.amount_paid == Amount(Unit.sat, 21)

        outgoing = await processor.quote_outgoing_payment(
            processor,
            PostMeltQuoteRequest.model_validate(
                {
                    "unit": "sat",
                    "request": "merchant-request",
                    "account": "alice",
                    "options": {
                        "custom_confirmation": 3,
                        "routing": {"hints": ["fast", "cheap"]},
                    },
                }
            ),
            "melt-quote",
        )
        assert outgoing.amount == Amount(Unit.sat, 20)
        assert outgoing.model_extra == {"destination": "merchant-1"}

        melt_quote = MeltQuote(
            quote="melt-quote",
            method="testpay",
            request="merchant-request",
            checking_id=outgoing.checking_id,
            unit="sat",
            amount=20,
            fee_reserve=2,
            state=MeltQuoteState.unpaid,
        )
        payment = await processor.execute_outgoing_payment(
            processor, melt_quote, Amount(Unit.sat, 2)
        )
        assert payment.result == PaymentResult.SETTLED
        assert payment.fee == Amount(Unit.sat, 1)

        status = await processor.get_outgoing_payment_status(processor, melt_quote)
        assert status.result == PaymentResult.SETTLED
        assert status.preimage == "proof"
    finally:
        await processor.stop(processor)
        await server.stop(None)


@pytest.mark.asyncio
async def test_grpc_payment_processor_requires_explicit_transport_security():
    processor = GrpcPaymentProcessor(
        "testpay", Unit.sat, {"endpoint": "127.0.0.1:8090"}
    )
    with pytest.raises(ValueError, match="requires mTLS"):
        await processor.start(processor)


def _invoice(amount_msat: int) -> str:
    tags = bolt11.Tags()
    tags.add(bolt11.TagChar.payment_hash, "22" * 32)
    tags.add(bolt11.TagChar.payment_secret, "11" * 32)
    tags.add(bolt11.TagChar.description, "gRPC payment regression")
    return bolt11.encode(
        bolt11.Bolt11(
            currency="bc",
            date=int(time.time()),
            amount_msat=bolt11.MilliSatoshi(amount_msat),
            tags=tags,
        ),
        private_key="01" * 32,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("unit", [Unit.sat, Unit.msat])
@pytest.mark.parametrize("partial", [False, True])
async def test_grpc_bolt11_execution_respects_persisted_quote_amount(
    ledger: Ledger, unit: Unit, partial: bool
):
    invoice_msat = 3501
    requested_msat = 2000 if partial else invoice_msat
    quote_amount = Amount(Unit.msat, requested_msat).to(unit, round="up")
    processor = GrpcPaymentProcessor("bolt11", unit, {})
    stub = AsyncMock()
    processor._stub = stub
    stub.GetPaymentQuote.return_value = pb.PaymentQuoteResponse(
        request_identifier=pb.PaymentIdentifier(
            type=pb.PAYMENT_IDENTIFIER_TYPE_PAYMENT_HASH, hash="22" * 32
        ),
        amount=pb.AmountMessage(value=quote_amount.amount, unit=unit.name),
        fee=pb.AmountMessage(value=1, unit=unit.name),
    )
    request = PostMeltQuoteRequest.model_validate(
        {
            "unit": unit.name,
            "request": _invoice(invoice_msat),
            **({"options": {"mpp": {"amount": requested_msat}}} if partial else {}),
        }
    )
    priced = await processor.quote_outgoing_payment(processor, request, "mpp-quote")
    sent_quote = stub.GetPaymentQuote.call_args.args[0]
    if partial:
        assert sent_quote.options.mpp.amount == requested_msat
        assert (sent_quote.amount.value, sent_quote.amount.unit) == (
            requested_msat,
            "msat",
        )
    quote = MeltQuote(
        quote="mpp-quote",
        method="bolt11",
        request=request.request,
        checking_id=priced.checking_id,
        unit=unit.name,
        amount=priced.amount.amount,
        fee_reserve=priced.fee.amount,
        state=MeltQuoteState.unpaid,
    )
    await ledger.crud.store_melt_quote(quote=quote, db=ledger.db)
    stored = await ledger.crud.get_melt_quote(quote_id=quote.quote, db=ledger.db)
    assert stored is not None

    spent_msat = 0

    async def make_payment(request, **kwargs):
        nonlocal spent_msat
        options = request.payment_options.bolt11
        spent_msat = (
            options.melt_options.mpp.amount
            if options.HasField("melt_options")
            else int(bolt11.decode(options.bolt11).amount_msat)
        )
        spent = Amount(Unit.msat, spent_msat).to(unit, round="up")
        return pb.MakePaymentResponse(
            status=pb.QUOTE_STATE_PAID,
            total_spent=pb.AmountMessage(value=spent.amount, unit=unit.name),
        )

    # A fresh adapter has no in-memory copy of the original MPP request.
    restarted = GrpcPaymentProcessor("bolt11", unit, {})
    restarted._stub = stub
    stub.MakePayment.side_effect = make_payment
    response = await restarted.execute_outgoing_payment(restarted, stored, priced.fee)
    assert response.settled
    assert spent_msat == requested_msat
    assert response.fee == Amount(unit, 0)


@pytest.mark.asyncio
async def test_grpc_onchain_quote_sends_required_options():
    processor = GrpcPaymentProcessor("onchain", Unit.sat, {})
    stub = AsyncMock()
    processor._stub = stub

    async def get_payment_quote(request, **kwargs):
        # CDK rejects onchain quote requests without this nested message.
        assert request.HasField("onchain_options")
        options = request.onchain_options
        assert options.quote_id == request.quote_id == "onchain-quote"
        assert options.address == "address"
        assert (options.amount.value, options.amount.unit) == (8, "sat")
        return pb.PaymentQuoteResponse(
            request_identifier=pb.PaymentIdentifier(
                type=pb.PAYMENT_IDENTIFIER_TYPE_QUOTE_ID, id=request.quote_id
            ),
            amount=options.amount,
            fee=pb.AmountMessage(value=1, unit="sat"),
        )

    stub.GetPaymentQuote.side_effect = get_payment_quote
    response = await processor.quote_outgoing_payment(
        processor,
        PostMeltQuoteRequest(unit="sat", request="address", amount=8),
        "onchain-quote",
    )
    assert response.amount == Amount(Unit.sat, 8)
    assert response.fee == Amount(Unit.sat, 1)

    stub.GetPaymentQuote.reset_mock()
    with pytest.raises(ValueError, match="require an amount"):
        await processor.quote_outgoing_payment(
            processor,
            PostMeltQuoteRequest(unit="sat", request="address"),
            "amountless-melt",
        )
    stub.GetPaymentQuote.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["onchain", "bolt12", "testpay"])
async def test_grpc_amountless_mint_issues_cumulative_payments(
    ledger: Ledger, monkeypatch, method
):
    processor = GrpcPaymentProcessor(
        method,
        Unit.sat,
        {
            "allows_amountless_mint": True,
            "allows_partial_mint": True,
            "allows_repeated_payments": True,
        },
    )
    stub = AsyncMock()
    processor._stub = stub
    monkeypatch.setitem(payment_method_registry._plugins, method, processor)
    monkeypatch.setattr(
        ledger, "backends", {**ledger.backends, method: {Unit.sat: processor}}
    )
    stub.CreatePayment.return_value = pb.CreatePaymentResponse(
        request_identifier=pb.PaymentIdentifier(
            type=pb.PAYMENT_IDENTIFIER_TYPE_QUOTE_ID, id="incoming"
        ),
        request="payment-request",
    )
    paid_amount = 8

    async def incoming_status(*args, **kwargs):
        return pb.CheckIncomingPaymentResponse(
            payments=[
                pb.WaitIncomingPaymentResponse(
                    payment_amount=pb.AmountMessage(value=paid_amount, unit="sat"),
                    payment_id="incoming-payment",
                )
            ]
        )

    stub.CheckIncomingPayment.side_effect = incoming_status
    quote = await ledger.mint_quote(PostMintQuoteRequest(unit="sat"), method)
    assert quote.amount == 0
    for i, (amount, expected_paid, expected_issued) in enumerate(
        [(4, 8, 4), (4, 8, 8), (1, 9, 9)]
    ):
        paid_amount = expected_paid
        await ledger.get_mint_quote(quote.quote, force_backend_check=True)
        output = BlindedMessage(
            amount=amount,
            B_=step1_alice(f"{method}-{i}")[0].format().hex(),
            id=ledger.keyset.id,
        )
        promises = await ledger.mint(
            outputs=[output], quote_id=quote.quote, method_str=method
        )
        assert sum(p.amount for p in promises) == amount
        stored = await ledger.crud.get_mint_quote(quote_id=quote.quote, db=ledger.db)
        assert stored is not None
        assert (stored.amount_paid, stored.amount_issued) == (
            expected_paid,
            expected_issued,
        )
        assert stored.state == (
            MintQuoteState.issued
            if expected_paid == expected_issued
            else MintQuoteState.paid
        )


def test_grpc_bolt11_retains_single_issuance():
    assert not GrpcPaymentProcessor("bolt11", Unit.sat, {}).allows_partial_mint


@pytest.mark.asyncio
@pytest.mark.parametrize("unit", [Unit.sat, Unit.msat])
@pytest.mark.parametrize("use_options", [False, True])
async def test_bolt12_amountless_payment_survives_reload(
    ledger, monkeypatch, unit, use_options
):
    monkeypatch.setattr(ledger.keyset, "unit", unit)
    processor = GrpcPaymentProcessor("bolt12", unit, {})
    processor._stub = stub = AsyncMock()
    monkeypatch.setitem(payment_method_registry._plugins, "bolt12", processor)
    monkeypatch.setattr(
        ledger, "backends", {**ledger.backends, "bolt12": {unit: processor}}
    )
    requested_msat = 3501 if use_options else 8000
    priced_amount = Amount(Unit.msat, requested_msat).to(unit, round="up")
    stub.GetPaymentQuote.return_value = pb.PaymentQuoteResponse(
        request_identifier=pb.PaymentIdentifier(
            type=pb.PAYMENT_IDENTIFIER_TYPE_QUOTE_ID, id="outgoing"
        ),
        amount=pb.AmountMessage(value=priced_amount.amount, unit=unit.name),
        fee=pb.AmountMessage(value=0, unit=unit.name),
    )
    payload = {"unit": unit.name, "request": "lno1amountless"}
    if use_options:
        payload["options"] = {"amountless": {"amount_msat": requested_msat}}
    else:
        payload["amount"] = Amount(Unit.msat, requested_msat).to(unit).amount
    response = await ledger.melt_quote(
        PostMeltQuoteRequest.model_validate(payload), "bolt12"
    )
    sent = stub.GetPaymentQuote.call_args.args[0]
    assert sent.options.WhichOneof("options") == "amountless"
    assert sent.options.amountless.amount_msat == requested_msat
    quote = await ledger.crud.get_melt_quote(quote_id=response.quote, db=ledger.db)
    assert quote is not None
    assert quote.amountless_msat == requested_msat
    assert "amountless_msat" not in response.model_dump()
    restarted = GrpcPaymentProcessor("bolt12", unit, {})
    restarted._stub = stub
    stub.MakePayment.return_value = pb.MakePaymentResponse(
        status=pb.QUOTE_STATE_PAID,
        total_spent=pb.AmountMessage(value=priced_amount.amount, unit=unit.name),
    )
    await restarted.execute_outgoing_payment(restarted, quote, Amount(unit, 0))
    options = stub.MakePayment.call_args.args[0].payment_options.bolt12
    assert options.melt_options.amountless.amount_msat == requested_msat


@pytest.mark.parametrize(
    "options",
    [
        {"amountless": {"amount_msat": 0}},
        {"amountless": {"amount_msat": -1}},
        {"amountless": {"amount_msat": 1000}, "mpp": {"amount": 1000}},
    ],
)
def test_invalid_amountless_options_rejected(options):
    with pytest.raises(ValueError):
        PostMeltQuoteRequest(unit="sat", request="offer", options=options)


@pytest.mark.asyncio
async def test_conflicting_bolt12_amounts_rejected_before_rpc():
    processor = GrpcPaymentProcessor("bolt12", Unit.sat, {})
    processor._stub = stub = AsyncMock()
    request = PostMeltQuoteRequest.model_validate(
        {
            "unit": "sat",
            "request": "offer",
            "amount": 8,
            "options": {"amountless": {"amount_msat": 9000}},
        }
    )
    with pytest.raises(ValueError, match="conflicting"):
        await processor.quote_outgoing_payment(processor, request, "quote")
    stub.GetPaymentQuote.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("mint_amount", [0, 32])
async def test_onchain_self_payment_uses_processor_amount_and_status(
    ledger, monkeypatch, mint_amount
):
    processor = GrpcPaymentProcessor("onchain", Unit.sat, {})
    processor._stub = stub = AsyncMock()
    monkeypatch.setitem(payment_method_registry._plugins, "onchain", processor)
    monkeypatch.setattr(
        ledger, "backends", {**ledger.backends, "onchain": {Unit.sat: processor}}
    )
    mint_quote = MintQuote(
        quote="receive",
        method="onchain",
        request="address",
        checking_id="incoming",
        unit="sat",
        amount=mint_amount,
        state=MintQuoteState.unpaid,
    )
    await ledger.crud.store_mint_quote(quote=mint_quote, db=ledger.db)
    stub.GetPaymentQuote.return_value = pb.PaymentQuoteResponse(
        request_identifier=pb.PaymentIdentifier(
            type=pb.PAYMENT_IDENTIFIER_TYPE_QUOTE_ID, id="outgoing"
        ),
        amount=pb.AmountMessage(value=8, unit="sat"),
        fee=pb.AmountMessage(value=1, unit="sat"),
    )
    response = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request="address", amount=8), "onchain"
    )
    assert response.amount == 8
    assert stub.GetPaymentQuote.call_args.args[0].onchain_options.amount.value == 8
    quote = await ledger.crud.get_melt_quote(quote_id=response.quote, db=ledger.db)
    assert quote is not None
    assert (
        await ledger.melt_mint_settle_internally(quote, [])
    ).state == MeltQuoteState.unpaid
    quote.state = MeltQuoteState.pending
    await ledger.crud.update_melt_quote(quote=quote, db=ledger.db)
    stub.CheckOutgoingPayment.return_value = pb.MakePaymentResponse(
        status=pb.QUOTE_STATE_PAID, total_spent=pb.AmountMessage(value=9, unit="sat")
    )
    assert (await ledger.get_melt_quote(quote.quote)).state == MeltQuoteState.paid
    stub.CheckOutgoingPayment.assert_awaited_once()
    stored = await ledger.crud.get_mint_quote(quote_id=mint_quote.quote, db=ledger.db)
    assert stored.amount_paid == 0


@pytest.mark.parametrize("method", ["bolt11", "bolt12", "onchain", "unknownpay"])
def test_grpc_capabilities_require_explicit_booleans(method):
    processor = GrpcPaymentProcessor(method, Unit.sat, {})
    assert not processor.supports_partial_mint(processor)
    assert not processor.supports_repeated_payments(processor)
    assert not processor.supports_amountless_mint(processor)
    for capability in [
        "allows_partial_mint",
        "allows_repeated_payments",
        "allows_amountless_mint",
    ]:
        with pytest.raises(ValueError, match="must be a boolean"):
            GrpcPaymentProcessor(method, Unit.sat, {capability: "false"})
    # The registry can use one method plugin for multiple units. The capability
    # must come from the backend for the unit actually being used.
    other = GrpcPaymentProcessor(method, Unit.msat, {"allows_partial_mint": True})
    assert processor.supports_partial_mint(other)
    assert not processor.supports_repeated_payments(other)
    assert not processor.supports_amountless_mint(other)


@pytest.mark.asyncio
@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("amountless", [False, True])
async def test_reusable_method_can_disallow_partial_issuance(
    ledger, monkeypatch, batch, amountless
):
    from cashu.core.errors import TransactionError
    from cashu.core.models import PostMintBatchRequest

    processor = GrpcPaymentProcessor(
        "fixedpay",
        Unit.sat,
        {
            "allows_repeated_payments": True,
            "allows_amountless_mint": amountless,
        },
    )
    processor._stub = stub = AsyncMock()
    monkeypatch.setitem(payment_method_registry._plugins, "fixedpay", processor)
    monkeypatch.setattr(
        ledger, "backends", {**ledger.backends, "fixedpay": {Unit.sat: processor}}
    )
    stub.CreatePayment.return_value = pb.CreatePaymentResponse(
        request_identifier=pb.PaymentIdentifier(
            type=pb.PAYMENT_IDENTIFIER_TYPE_QUOTE_ID, id="incoming"
        ),
        request="request",
    )
    if not amountless:
        with pytest.raises(Exception, match="does not support amountless"):
            await ledger.mint_quote(PostMintQuoteRequest(unit="sat"), "fixedpay")
        stub.CreatePayment.assert_not_awaited()
    quote = await ledger.mint_quote(
        PostMintQuoteRequest(unit="sat", amount=None if amountless else 8), "fixedpay"
    )

    def receipt(paid):
        return pb.CheckIncomingPaymentResponse(
            payments=[
                pb.WaitIncomingPaymentResponse(
                    payment_amount=pb.AmountMessage(value=paid, unit="sat"),
                    payment_id="receipt",
                )
            ]
        )

    stub.CheckIncomingPayment.return_value = receipt(8)

    async def mint(amount, secret):
        output = BlindedMessage(
            amount=amount, id=ledger.keyset.id, B_=step1_alice(secret)[0].format().hex()
        )
        if batch:
            return await ledger.mint_batch(
                PostMintBatchRequest(
                    quotes=[quote.quote], quote_amounts=[amount], outputs=[output]
                )
            )
        return await ledger.mint(outputs=[output], quote_id=quote.quote)

    await ledger.get_mint_quote(quote.quote, force_backend_check=True)
    with pytest.raises(TransactionError, match="does not match"):
        await mint(4, "partial")
    await mint(8, "full")
    stub.CheckIncomingPayment.return_value = receipt(24)
    await ledger.get_mint_quote(quote.quote, force_backend_check=True)
    await mint(16, "next-full")
    stored = await ledger.crud.get_mint_quote(quote_id=quote.quote, db=ledger.db)
    assert (stored.amount_paid, stored.amount_issued, stored.state) == (
        24,
        24,
        MintQuoteState.issued,
    )
