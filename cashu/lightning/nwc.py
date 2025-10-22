from typing import AsyncGenerator, Optional

from bolt11 import decode
from loguru import logger

from ..core.base import Amount, MeltQuote, Unit
from ..core.helpers import fee_reserve
from ..core.models import PostMeltQuoteRequest
from ..core.settings import settings
from ..nostr.nwc import (
    Nip47Error,
    Nip47LookupInvoiceRequest,
    Nip47MakeInvoiceRequest,
    Nip47PayInvoiceRequest,
    NWCClient,
)
from .base import (
    InvoiceResponse,
    LightningBackend,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
    StatusResponse,
)

required_nip47_methods = [
    "get_info",
    "get_balance",
    "make_invoice",
    "pay_invoice",
    "lookup_invoice",
]


class NWCWallet(LightningBackend):

    supported_units = {Unit.sat, Unit.msat}

    def __init__(self, unit: Unit, **kwargs):
        logger.debug(f"Initializing NWCWallet with unit: {unit}")
        logger.debug(f"Unit type: {type(unit)}")
        logger.debug(f"Supported units: {self.supported_units}")
        logger.debug(f"Supported units types: {[type(u) for u in self.supported_units]}")
        logger.debug(f"Unit in supported_units: {unit in self.supported_units}")
        logger.debug(f"Unit.msat: {Unit.msat}, Unit.sat: {Unit.sat}")
        self.assert_unit_supported(unit)
        self.unit = unit
        self.client = NWCClient(nostrWalletConnectUrl=settings.mint_nwc_url)

    async def status(self) -> StatusResponse:
        try:
            info = await self.client.get_info()
            if not all([method in info.methods for method in required_nip47_methods]):
                return StatusResponse(
                    error_message=f"NWC does not support all required methods. Supports: {info.methods}",
                    balance=Amount(unit=self.unit, amount=0),
                )
            res = await self.client.get_balance()
            balance_msat = res.balance
            # NWC returns balance in msats, convert to configured unit
            balance_amount = Amount(unit=Unit.msat, amount=balance_msat)
            return StatusResponse(balance=balance_amount.to(self.unit), error_message=None)
        except Nip47Error as exc:
            return StatusResponse(
                error_message=str(exc),
                balance=Amount(unit=self.unit, amount=0),
            )
        except Exception as exc:
            return StatusResponse(
                error_message=f"Failed to connect to lightning wallet via NWC due to: {exc}",
                balance=Amount(unit=self.unit, amount=0),
            )

    async def create_invoice(
        self,
        amount: Amount,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        unhashed_description: Optional[str] = None,
    ) -> InvoiceResponse:
        try:
            # NWC expects amount in msats, convert from configured unit
            amount_msat = amount.to(Unit.msat).amount
            res = await self.client.create_invoice(
                request=Nip47MakeInvoiceRequest(amount=amount_msat)
            )
            return InvoiceResponse(
                checking_id=res.payment_hash,
                payment_request=res.invoice,
                ok=True,
                error_message=None,
            )
        except Nip47Error as exc:
            return InvoiceResponse(
                error_message=str(exc),
                ok=False,
            )
        except Exception as exc:
            return InvoiceResponse(
                error_message=f"Failed to create invoice due to: {exc}",
                ok=False,
            )

    async def pay_invoice(
        self, quote: MeltQuote, fee_limit_msat: int
    ) -> PaymentResponse:
        try:
            pay_invoice_res = await self.client.pay_invoice(
                Nip47PayInvoiceRequest(invoice=quote.request)
            )
            invoice = await self.client.lookup_invoice(
                Nip47LookupInvoiceRequest(payment_hash=quote.checking_id)
            )
            # NWC returns fees in msats, convert to configured unit
            fees_msat = invoice.fees_paid
            fees_amount = Amount(unit=Unit.msat, amount=fees_msat)

            return PaymentResponse(
                result=PaymentResult.SETTLED,
                checking_id=None,
                fee=fees_amount.to(self.unit),
                preimage=pay_invoice_res.preimage,
            )
        except Nip47Error as exc:
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message=str(exc),
            )
        except Exception as exc:
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message=f"Failed to pay invoice due to: {exc}",
            )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        try:
            res = await self.client.lookup_invoice(
                Nip47LookupInvoiceRequest(payment_hash=checking_id)
            )
            paid = res.preimage is not None and res.preimage != ""
            return PaymentStatus(paid=paid)
        except Exception as exc:
            logger.error(f"Failed to get invoice status due to: {exc}")
            return PaymentStatus(paid=False)

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        try:
            res = await self.client.lookup_invoice(
                Nip47LookupInvoiceRequest(payment_hash=checking_id)
            )
            paid = res.preimage is not None and res.preimage != ""
            return PaymentStatus(paid=paid)
        except Exception as exc:
            logger.error(f"Failed to get invoice status due to: {exc}")
            return PaymentStatus(paid=False)

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

    def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        raise NotImplementedError("paid_invoices_stream not implemented")
