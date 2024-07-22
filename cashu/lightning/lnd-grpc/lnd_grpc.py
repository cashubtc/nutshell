import asyncio
import base64
import hashlib
import json
from typing import AsyncGenerator, Dict, Optional

import bolt11
import codecs, grpc, os
import lightning_pb2 as lnrpc, lightning_pb2_grpc as lightningstub
from bolt11 import (
    TagChar,
    decode,
)
from loguru import logger

from cashu.core.base import Amount, MeltQuote, Unit
from cashu.core.helpers import fee_reserve
from cashu.core.models import PostMeltQuoteRequest
from cashu.core.settings import settings
from cashu.lightning.base import (
    InvoiceResponse,
    LightningBackend,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentStatus,
    StatusResponse,
)
from cashu.lightning.macaroon import load_macaroon

class LndRPCWallet(LightningBackend):

    supports_mpp = settings.mint_lnd_enable_mpp
    supports_incoming_payment_stream = True
    supported_units = set([Unit.sat, Unit.msat])
    unit = Unit.sat

    def __init__(self, unit: Unit = Unit.sat, **kwargs):
        self.assert_unit_supported(unit)
        self.unit = unit
        self.endpoint = settings.mint_lnd_rpc_endpoint
        cert_path = settings.mint_lnd_tls_cert

        macaroon_path = (
            settings.mint_lnd_rpc_macaroon
            or settings.mint_lnd_rpc_admin_macaroon
            or settings.mint_lnd_rpc_invoice_macaroon
        )

        if not self.endpoint:
            raise Exception("cannot initialize LndRPCWallet: no endpoint")

        if not macaroon_path:
            raise Exception("cannot initialize LndRPCWallet: no macaroon")

        if not cert_path:
            raise Exception("no certificate for LndRPCWallet provided")

        self.macaroon = codecs.encode(open(macaroon_path, 'rb').read(), 'hex')

        def metadata_callback(context, callback):
            callback([('macaroon', self.macaroon)], None)
        auth_creds = grpc.metadata_call_credentials(metadata_callback)

        # create SSL credentials
        os.environ['GRPC_SSL_CIPHER_SUITES'] = 'HIGH+ECDSA'
        cert = open(cert_path, 'rb').read()
        ssl_creds = grpc.ssl_channel_credentials(cert)

        # combine macaroon and SSL credentials
        combined_creds = grpc.composite_channel_credentials(ssl_creds, auth_creds)
        
        # connect and create stub
        # (channel and stub should be thread-safe and should be able to work in async)
        try:
            self.channel = grpc.aio.secure_channel(self.endpoint, combined_creds)
        except (grpc.GrpcError, OSError) as e:
            logger.error(f"Failed to create secure channel: {e}")
            raise Exception(f"Failed to create secure channel: {e}")
        
        self.stub = lightningstub.LightningStub(self.channel)
        
        if self.supports_mpp:
            logger.info("LndRPCWallet enabling MPP feature")

    async def status(self) -> StatusResponse:
        try:
            r = await self.stub.ChannelBalance(lnrpc.ChannelBalanceRequest())
        except grpc.GrpcError as e:
            return StatusResponse(
                error_message=f"Error calling Lnd gRPC: {e}", balance=0
            )
        # NOTE: `balance` field is deprecated. Change this.
        return StatusResponse(error_message=None, balance=r.balance*1000)

    
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

        try:
            r = await self.stub.AddInvoice(data)
        except grpc.GrpcError as e:
            logger.error(f"failed to create invoice: {e}")
            return InvoiceResponse(
                ok=False,
                error_message=f"failed to create invoice: {e}",
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
    '''
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
        lnrpcFeeLimit = dict()
        lnrpcFeeLimit["fixed_msat"] = f"{fee_limit_msat}"

        r = await self.client.post(
            url="/v1/channels/transactions",
            json={"payment_request": quote.request, "fee_limit": lnrpcFeeLimit},
            timeout=None,
        )

        if r.is_error or r.json().get("payment_error"):
            error_message = r.json().get("payment_error") or r.text
            return PaymentResponse(
                ok=False,
                checking_id=None,
                fee=None,
                preimage=None,
                error_message=error_message,
            )

        data = r.json()
        checking_id = base64.b64decode(data["payment_hash"]).hex()
        fee_msat = int(data["payment_route"]["total_fees_msat"])
        preimage = base64.b64decode(data["payment_preimage"]).hex()
        return PaymentResponse(
            ok=True,
            checking_id=checking_id,
            fee=Amount(unit=Unit.msat, amount=fee_msat) if fee_msat else None,
            preimage=preimage,
            error_message=None,
        )

    async def pay_partial_invoice(
        self, quote: MeltQuote, amount: Amount, fee_limit_msat: int
    ) -> PaymentResponse:
        # set the fee limit for the payment
        lnrpcFeeLimit = dict()
        lnrpcFeeLimit["fixed_msat"] = f"{fee_limit_msat}"
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
        r = await self.client.post(
            url=f"/v1/graph/routes/{pubkey}/{amount.to(Unit.sat).amount}",
            json={"fee_limit": lnrpcFeeLimit},
            timeout=None,
        )

        data = r.json()
        if r.is_error or data.get("message"):
            error_message = data.get("message") or r.text
            return PaymentResponse(
                ok=False,
                checking_id=None,
                fee=None,
                preimage=None,
                error_message=error_message,
            )

        # We need to set the mpp_record for a partial payment
        mpp_record = {
            "mpp_record": {
                "payment_addr": base64.b64encode(bytes.fromhex(payer_addr)).decode(),
                "total_amt_msat": total_amount_msat,
            }
        }

        # add the mpp_record to the last hop
        rout_nr = 0
        data["routes"][rout_nr]["hops"][-1].update(mpp_record)

        # send to route
        r = await self.client.post(
            url="/v2/router/route/send",
            json={
                "payment_hash": base64.b64encode(
                    bytes.fromhex(invoice.payment_hash)
                ).decode(),
                "route": data["routes"][rout_nr],
            },
            timeout=None,
        )

        data = r.json()
        if r.is_error or data.get("message"):
            error_message = data.get("message") or r.text
            return PaymentResponse(
                ok=False,
                checking_id=None,
                fee=None,
                preimage=None,
                error_message=error_message,
            )

        ok = data.get("status") == "SUCCEEDED"
        checking_id = invoice.payment_hash
        fee_msat = int(data["route"]["total_fees_msat"])
        preimage = base64.b64decode(data["preimage"]).hex()
        return PaymentResponse(
            ok=ok,
            checking_id=checking_id,
            fee=Amount(unit=Unit.msat, amount=fee_msat) if fee_msat else None,
            preimage=preimage,
            error_message=None,
        )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        r = await self.client.get(url=f"/v1/invoice/{checking_id}")

        if r.is_error or not r.json().get("settled"):
            # this must also work when checking_id is not a hex recognizable by lnd
            # it will return an error and no "settled" attribute on the object
            return PaymentStatus(paid=None)

        return PaymentStatus(paid=True)

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        """
        This routine checks the payment status using routerpc.TrackPaymentV2.
        """
        # convert checking_id from hex to base64 and some LND magic
        try:
            checking_id = base64.urlsafe_b64encode(bytes.fromhex(checking_id)).decode(
                "ascii"
            )
        except ValueError:
            return PaymentStatus(paid=None)

        url = f"/v2/router/track/{checking_id}"

        # check payment.status:
        # https://api.lightning.community/?python=#paymentpaymentstatus
        statuses = {
            "UNKNOWN": None,
            "IN_FLIGHT": None,
            "SUCCEEDED": True,
            "FAILED": False,
        }

        async with self.client.stream("GET", url, timeout=None) as r:
            async for json_line in r.aiter_lines():
                try:
                    line = json.loads(json_line)

                    # check for errors
                    if line.get("error"):
                        message = (
                            line["error"]["message"]
                            if "message" in line["error"]
                            else line["error"]
                        )
                        logger.error(f"LND get_payment_status error: {message}")
                        return PaymentStatus(paid=None)

                    payment = line.get("result")

                    # payment exists
                    if payment is not None and payment.get("status"):
                        return PaymentStatus(
                            paid=statuses[payment["status"]],
                            fee=(
                                Amount(unit=Unit.msat, amount=payment.get("fee_msat"))
                                if payment.get("fee_msat")
                                else None
                            ),
                            preimage=payment.get("payment_preimage"),
                        )
                    else:
                        return PaymentStatus(paid=None)
                except Exception:
                    continue

        return PaymentStatus(paid=None)

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        while True:
            try:
                url = "/v1/invoices/subscribe"
                async with self.client.stream("GET", url, timeout=None) as r:
                    async for line in r.aiter_lines():
                        try:
                            inv = json.loads(line)["result"]
                            if not inv["settled"]:
                                continue
                        except Exception:
                            continue

                        payment_hash = base64.b64decode(inv["r_hash"]).hex()
                        yield payment_hash
            except Exception as exc:
                logger.error(
                    f"lost connection to lnd invoices stream: '{exc}', retrying in 5"
                    " seconds"
                )
                await asyncio.sleep(5)

    async def get_payment_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        # get amount from melt_quote or from bolt11
        amount = (
            Amount(Unit[melt_quote.unit], melt_quote.mpp_amount)
            if melt_quote.is_mpp
            else None
        )

        invoice_obj = decode(melt_quote.request)
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
    '''