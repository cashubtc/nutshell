from __future__ import annotations

import json

import grpc
import pytest

from cashu.core.base import (
    Amount,
    MeltQuote,
    MeltQuoteState,
    MintQuote,
    MintQuoteState,
    Unit,
)
from cashu.core.models import PostMeltQuoteRequest, PostMintQuoteRequest
from cashu.lightning.base import PaymentResult
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
