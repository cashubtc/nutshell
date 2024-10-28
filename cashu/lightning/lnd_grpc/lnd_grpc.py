import asyncio
import codecs
import hashlib
import os
from typing import AsyncGenerator, Optional

import bolt11
import grpc
from bolt11 import (
    TagChar,
)
from grpc.aio import AioRpcError
from loguru import logger

import cashu.lightning.lnd_grpc.protos.lightning_pb2 as lnrpc
import cashu.lightning.lnd_grpc.protos.lightning_pb2_grpc as lightningstub
import cashu.lightning.lnd_grpc.protos.router_pb2 as routerrpc
import cashu.lightning.lnd_grpc.protos.router_pb2_grpc as routerstub
from cashu.core.base import Amount, MeltQuote, Unit
from cashu.core.helpers import fee_reserve
from cashu.core.settings import settings
from cashu.lightning.base import (
    InvoiceResponse,
    LightningBackend,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
    PostMeltQuoteRequest,
    StatusResponse,
)

# maps statuses to None, False, True:
# https://api.lightning.community/?python=#paymentpaymentstatus
PAYMENT_RESULT_MAP = {
    lnrpc.Payment.PaymentStatus.UNKNOWN: PaymentResult.UNKNOWN,
    lnrpc.Payment.PaymentStatus.IN_FLIGHT: PaymentResult.PENDING,
    lnrpc.Payment.PaymentStatus.INITIATED: PaymentResult.PENDING,
    lnrpc.Payment.PaymentStatus.SUCCEEDED: PaymentResult.SETTLED,
    lnrpc.Payment.PaymentStatus.FAILED: PaymentResult.FAILED,
}
INVOICE_RESULT_MAP = {
    lnrpc.Invoice.InvoiceState.OPEN: PaymentResult.PENDING,
    lnrpc.Invoice.InvoiceState.SETTLED: PaymentResult.SETTLED,
    lnrpc.Invoice.InvoiceState.CANCELED: PaymentResult.FAILED,
    lnrpc.Invoice.InvoiceState.ACCEPTED: PaymentResult.PENDING,
}


class LndRPCWallet(LightningBackend):
    supports_mpp = settings.mint_lnd_enable_mpp
    supports_incoming_payment_stream = True
    supported_units = {Unit.sat, Unit.msat}
    supports_description: bool = True

    unit = Unit.sat

    def __init__(self, unit: Unit = Unit.sat, **kwargs):
        self.assert_unit_supported(unit)
        self.unit = unit
        cert_path = settings.mint_lnd_rpc_cert

        macaroon_path = settings.mint_lnd_rpc_macaroon

        if not settings.mint_lnd_rpc_endpoint:
            raise Exception("cannot initialize LndRPCWallet: no endpoint")

        self.endpoint = settings.mint_lnd_rpc_endpoint

        if not macaroon_path:
            raise Exception("cannot initialize LndRPCWallet: no macaroon")

        if not cert_path:
            raise Exception("no certificate for LndRPCWallet provided")

        self.macaroon = codecs.encode(open(macaroon_path, "rb").read(), "hex")

        def metadata_callback(context, callback):
            callback([("macaroon", self.macaroon)], None)

        auth_creds = grpc.metadata_call_credentials(metadata_callback)

        # create SSL credentials
        os.environ["GRPC_SSL_CIPHER_SUITES"] = "HIGH+ECDSA"
        cert = open(cert_path, "rb").read()
        ssl_creds = grpc.ssl_channel_credentials(cert)

        # combine macaroon and SSL credentials
        self.combined_creds = grpc.composite_channel_credentials(ssl_creds, auth_creds)

        if self.supports_mpp:
            logger.info("LndRPCWallet enabling MPP feature")

    async def status(self) -> StatusResponse:
        r = None
        try:
            async with grpc.aio.secure_channel(
                self.endpoint, self.combined_creds
            ) as channel:
                lnstub = lightningstub.LightningStub(channel)
                r = await lnstub.ChannelBalance(lnrpc.ChannelBalanceRequest())
        except AioRpcError as e:
            return StatusResponse(
                error_message=f"Error calling Lnd gRPC: {e}", balance=0
            )
        # NOTE: `balance` field is deprecated. Change this.
        return StatusResponse(error_message=None, balance=r.balance * 1000)

    async def create_invoice(
        self,
        amount: Amount,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        unhashed_description: Optional[bytes] = None,
        **kwargs,
    ) -> InvoiceResponse:
        self.assert_unit_supported(amount.unit)
        data = lnrpc.Invoice(
            value=amount.to(Unit.sat).amount,
            private=True,
            memo=memo or "",
        )
        if kwargs.get("expiry"):
            data.expiry = kwargs["expiry"]
        if description_hash:
            data.description_hash = description_hash
        elif unhashed_description:
            data.description_hash = hashlib.sha256(unhashed_description).digest()

        r = None
        try:
            async with grpc.aio.secure_channel(
                self.endpoint, self.combined_creds
            ) as channel:
                lnstub = lightningstub.LightningStub(channel)
                r = await lnstub.AddInvoice(data)
        except AioRpcError as e:
            logger.error(f"AddInvoice failed: {e}")
            return InvoiceResponse(
                ok=False,
                error_message=f"AddInvoice failed: {e}",
            )

        payment_request = r.payment_request
        payment_hash = r.r_hash.hex()
        checking_id = payment_hash

        return InvoiceResponse(
            ok=True,
            checking_id=checking_id,
            payment_request=payment_request,
            error_message=None,
        )

    async def pay_invoice(
        self, quote: MeltQuote, fee_limit_msat: int
    ) -> PaymentResponse:
        # if the amount of the melt quote is different from the request
        # call pay_partial_invoice instead
        invoice = bolt11.decode(quote.request)
        if invoice.amount_msat:
            amount_msat = int(invoice.amount_msat)
            if amount_msat != quote.amount * 1000 and self.supports_mpp:
                return await self.pay_partial_invoice(
                    quote, Amount(Unit.sat, quote.amount), fee_limit_msat
                )

        # set the fee limit for the payment
        feelimit = lnrpc.FeeLimit(fixed_msat=fee_limit_msat)
        r = None
        try:
            async with grpc.aio.secure_channel(
                self.endpoint, self.combined_creds
            ) as channel:
                lnstub = lightningstub.LightningStub(channel)
                r = await lnstub.SendPaymentSync(
                    lnrpc.SendRequest(
                        payment_request=quote.request,
                        fee_limit=feelimit,
                    )
                )
        except AioRpcError as e:
            error_message = f"SendPaymentSync failed: {e}"
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message=error_message,
            )

        if r.payment_error:
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message=r.payment_error,
            )

        checking_id = r.payment_hash.hex()
        fee_msat = r.payment_route.total_fees_msat
        preimage = r.payment_preimage.hex()
        return PaymentResponse(
            result=PaymentResult.SETTLED,
            checking_id=checking_id,
            fee=Amount(unit=Unit.msat, amount=fee_msat) if fee_msat else None,
            preimage=preimage,
            error_message=None,
        )

    async def pay_partial_invoice(
        self, quote: MeltQuote, amount: Amount, fee_limit_msat: int
    ) -> PaymentResponse:
        # set the fee limit for the payment
        feelimit = lnrpc.FeeLimit(fixed_msat=fee_limit_msat)
        invoice = bolt11.decode(quote.request)

        invoice_amount = invoice.amount_msat
        assert invoice_amount, "invoice has no amount."
        total_amount_msat = int(invoice_amount)

        payee = invoice.tags.get(TagChar.payee)
        assert payee
        pubkey = str(payee.data)

        payer_addr_tag = invoice.tags.get(bolt11.TagChar("s"))
        assert payer_addr_tag
        payer_addr = str(payer_addr_tag.data)

        # get the route
        r = None
        try:
            async with grpc.aio.secure_channel(
                self.endpoint, self.combined_creds
            ) as channel:
                lnstub = lightningstub.LightningStub(channel)
                router_stub = routerstub.RouterStub(channel)
                r = await lnstub.QueryRoutes(
                    lnrpc.QueryRoutesRequest(
                        pub_key=pubkey,
                        amt=amount.to(Unit.sat).amount,
                        fee_limit=feelimit,
                    )
                )
                """
                # We need to set the mpp_record for a partial payment
                mpp_record = lnrpc.MPPRecord(
                    payment_addr=bytes.fromhex(payer_addr),
                    total_amt_msat=total_amount_msat,
                )
                """
                # modify the mpp_record in the last hop
                route_nr = 0
                r.routes[route_nr].hops[-1].mpp_record.payment_addr = bytes.fromhex(  # type: ignore
                    payer_addr
                )
                r.routes[route_nr].hops[  # type: ignore
                    -1
                ].mpp_record.total_amt_msat = total_amount_msat

                # Send to route request
                r = await router_stub.SendToRouteV2(
                    routerrpc.SendToRouteRequest(
                        payment_hash=bytes.fromhex(invoice.payment_hash),
                        route=r.routes[route_nr],  # type: ignore
                    )
                )
        except AioRpcError as e:
            logger.error(f"QueryRoute or SendToRouteV2 failed: {e}")
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message=str(e),
            )

        if r.status == lnrpc.HTLCAttempt.HTLCStatus.FAILED:
            error_message = f"Sending to route failed with code {r.failure.code}"
            logger.error(error_message)
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message=error_message,
            )

        result = PaymentResult.UNKNOWN
        if r.status == lnrpc.HTLCAttempt.HTLCStatus.SUCCEEDED:
            result = PaymentResult.SETTLED
        elif r.status == lnrpc.HTLCAttempt.HTLCStatus.IN_FLIGHT:
            result = PaymentResult.PENDING
        else:
            result = PaymentResult.FAILED

        checking_id = invoice.payment_hash
        fee_msat = r.route.total_fees_msat
        preimage = r.preimage.hex()
        return PaymentResponse(
            result=result,
            checking_id=checking_id,
            fee=Amount(unit=Unit.msat, amount=fee_msat) if fee_msat else None,
            preimage=preimage,
            error_message=None,
        )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        r = None
        try:
            async with grpc.aio.secure_channel(
                self.endpoint, self.combined_creds
            ) as channel:
                lnstub = lightningstub.LightningStub(channel)
                r = await lnstub.LookupInvoice(
                    lnrpc.PaymentHash(r_hash=bytes.fromhex(checking_id))
                )
        except AioRpcError as e:
            error_message = f"LookupInvoice failed: {e}"
            logger.error(error_message)
            return PaymentStatus(result=PaymentResult.UNKNOWN)

        return PaymentStatus(
            result=INVOICE_RESULT_MAP[r.state],
        )

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        """
        This routine checks the payment status using routerpc.TrackPaymentV2.
        """
        # convert checking_id from hex to bytes and some LND magic
        checking_id_bytes = bytes.fromhex(checking_id)
        request = routerrpc.TrackPaymentRequest(payment_hash=checking_id_bytes)

        async with grpc.aio.secure_channel(
            self.endpoint, self.combined_creds
        ) as channel:
            router_stub = routerstub.RouterStub(channel)
            try:
                async for payment in router_stub.TrackPaymentV2(request):
                    if payment is not None and payment.status:
                        preimage = (
                            payment.payment_preimage
                            if payment.payment_preimage != "0" * 64
                            else None
                        )
                        return PaymentStatus(
                            result=PAYMENT_RESULT_MAP[payment.status],
                            fee=(
                                Amount(unit=Unit.msat, amount=payment.fee_msat)
                                if payment.fee_msat
                                else None
                            ),
                            preimage=preimage,
                        )
            except AioRpcError as e:
                # status = StatusCode.NOT_FOUND
                if e.code() == grpc.StatusCode.NOT_FOUND:
                    return PaymentStatus(result=PaymentResult.UNKNOWN)

        return PaymentStatus(result=PaymentResult.UNKNOWN)

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        while True:
            try:
                async with grpc.aio.secure_channel(
                    self.endpoint, self.combined_creds
                ) as channel:
                    lnstub = lightningstub.LightningStub(channel)
                    async for invoice in lnstub.SubscribeInvoices(
                        lnrpc.InvoiceSubscription()
                    ):
                        if invoice.state != lnrpc.Invoice.InvoiceState.SETTLED:
                            continue
                        payment_hash = invoice.r_hash.hex()
                        yield payment_hash
            except AioRpcError as exc:
                logger.error(f"SubscribeInvoices failed: {exc}. Retrying in 1 sec...")
                await asyncio.sleep(1)

    async def get_payment_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        # get amount from melt_quote or from bolt11
        amount = (
            Amount(Unit[melt_quote.unit], melt_quote.mpp_amount)
            if melt_quote.is_mpp
            else None
        )

        invoice_obj = bolt11.decode(melt_quote.request)
        assert invoice_obj.amount_msat, "invoice has no amount."

        if amount:
            amount_msat = amount.to(Unit.msat).amount
        else:
            amount_msat = int(invoice_obj.amount_msat)

        fees_msat = fee_reserve(amount_msat)
        fees = Amount(unit=Unit.msat, amount=fees_msat)

        amount = Amount(unit=Unit.msat, amount=amount_msat)

        return PaymentQuoteResponse(
            checking_id=invoice_obj.payment_hash,
            fee=fees.to(self.unit, round="up"),
            amount=amount.to(self.unit, round="up"),
        )
