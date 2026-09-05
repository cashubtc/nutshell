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
            PostMeltQuoteRequest(unit="sat", request="merchant-request"),
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
    processor = GrpcPaymentProcessor(method, Unit.sat, {})
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
