import asyncio
import json
import random
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, Optional

from bolt11 import (
    Bolt11Exception,
    decode,
)
from loguru import logger

from ..core.base import Amount, MeltQuote, Unit
from ..core.helpers import fee_reserve
from ..core.models import PostMeltQuoteRequest
from ..core.settings import settings
from .base import (
    InvoiceResponse,
    LightningBackend,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
    StatusResponse,
    Unsupported,
)

# https://docs.corelightning.org/reference/lightning-pay
PAYMENT_RESULT_MAP = {
    "complete": PaymentResult.SETTLED,
    "pending": PaymentResult.PENDING,
    "failed": PaymentResult.FAILED,
}

# https://docs.corelightning.org/reference/lightning-listinvoices
INVOICE_RESULT_MAP = {
    "paid": PaymentResult.SETTLED,
    "unpaid": PaymentResult.PENDING,
    "expired": PaymentResult.FAILED,
}


def _parse_msat(value: Any) -> int:
    """Parses CLN msat fields returned as int/str/dict formats."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value.removesuffix("msat"))
    if isinstance(value, dict):
        if "msat" in value:
            return _parse_msat(value["msat"])
        if "millisatoshis" in value:
            return _parse_msat(value["millisatoshis"])
    raise ValueError(f"Unsupported msat value format: {value}")


class CLNRPCWallet(LightningBackend):
    supported_units = {Unit.sat, Unit.msat}
    unit = Unit.sat
    supports_mpp = settings.mint_cln_rpc_enable_mpp
    supports_incoming_payment_stream: bool = False
    supports_description: bool = True

    def __init__(self, unit: Unit = Unit.sat, **kwargs):
        self.assert_unit_supported(unit)
        self.unit = unit
        socket_path = settings.mint_cln_rpc_socket
        if not socket_path:
            raise Exception("missing socket path for cln rpc")
        self.socket_path = str(Path(socket_path).expanduser())
        self._id_counter = 0

    async def _rpc_call(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        self._id_counter += 1
        request_data = {
            "jsonrpc": "2.0",
            "id": self._id_counter,
            "method": method,
            "params": params or {},
        }
        request_raw = (json.dumps(request_data) + "\n\n").encode("utf-8")

        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        try:
            writer.write(request_raw)
            await writer.drain()

            response_raw = await reader.readuntil(b"\n\n")
            response = json.loads(response_raw.decode("utf-8").strip())
        finally:
            writer.close()
            await writer.wait_closed()

        if "error" in response:
            error = response["error"]
            message = (
                error.get("message", str(error))
                if isinstance(error, dict)
                else str(error)
            )
            raise Exception(message)

        result = response.get("result")
        if result is None:
            raise Exception(f"missing result for method '{method}'")
        return result

    async def status(self) -> StatusResponse:
        try:
            data = await self._rpc_call("listfunds")
            balance_msat = sum(
                _parse_msat(c.get("our_amount_msat", 0))
                for c in data.get("channels", [])
            )
            return StatusResponse(balance=Amount(self.unit, balance_msat // 1000))
        except Exception as exc:
            return StatusResponse(
                error_message=f"Failed to connect to cln rpc at '{self.socket_path}': {exc}",
                balance=Amount(self.unit, 0),
            )

    async def create_invoice(
        self,
        amount: Amount,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        unhashed_description: Optional[bytes] = None,
        **kwargs,
    ) -> InvoiceResponse:
        self.assert_unit_supported(amount.unit)
        label = f"lbl{random.random()}"
        description = memo or ""
        params: Dict[str, Any] = {
            "amount_msat": amount.to(Unit.msat, round="up").amount,
            "label": label,
            "description": description,
        }

        if description_hash and not unhashed_description:
            raise Unsupported(
                "'description_hash' unsupported by CLNRPCWallet, provide 'unhashed_description'"
            )
        if unhashed_description:
            params["description"] = unhashed_description.decode("utf-8")
            params["deschashonly"] = True

        if kwargs.get("expiry"):
            params["expiry"] = kwargs["expiry"]
        if kwargs.get("preimage"):
            params["preimage"] = kwargs["preimage"]

        try:
            data = await self._rpc_call("invoice", params)
            return InvoiceResponse(
                ok=True,
                checking_id=data["payment_hash"],
                payment_request=data["bolt11"],
            )
        except Exception as exc:
            return InvoiceResponse(ok=False, error_message=str(exc))

    async def pay_invoice(
        self, quote: MeltQuote, fee_limit_msat: int
    ) -> PaymentResponse:
        try:
            invoice = decode(quote.request)
        except Bolt11Exception as exc:
            return PaymentResponse(result=PaymentResult.FAILED, error_message=str(exc))

        if not invoice.amount_msat or invoice.amount_msat <= 0:
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message="0 amount invoices are not allowed",
            )

        quote_amount_msat = Amount(Unit[quote.unit], quote.amount).to(Unit.msat).amount
        fee_limit_percent = fee_limit_msat / quote_amount_msat * 100
        params: Dict[str, Any] = {
            "bolt11": quote.request,
            "maxfeepercent": f"{fee_limit_percent:.11}",
            "exemptfee": 0,
        }

        logger.trace(f"{quote_amount_msat = }, {invoice.amount_msat = }")
        if quote_amount_msat != invoice.amount_msat:
            logger.trace("Detected Multi-Nut payment")
            if self.supports_mpp:
                params["partial_msat"] = quote_amount_msat
            else:
                error_message = "mint does not support MPP"
                logger.error(error_message)
                return PaymentResponse(
                    result=PaymentResult.FAILED,
                    error_message=error_message,
                )

        try:
            data = await self._rpc_call("pay", params)
        except Exception as exc:
            return PaymentResponse(result=PaymentResult.FAILED, error_message=str(exc))

        status = PAYMENT_RESULT_MAP.get(data.get("status", ""), PaymentResult.UNKNOWN)
        fee_msat = None
        if "amount_sent_msat" in data and "amount_msat" in data:
            fee_msat = _parse_msat(data["amount_sent_msat"]) - _parse_msat(
                data["amount_msat"]
            )

        return PaymentResponse(
            result=status,
            checking_id=data.get("payment_hash"),
            fee=Amount(unit=Unit.msat, amount=fee_msat) if fee_msat else None,
            preimage=data.get("payment_preimage") or data.get("preimage"),
        )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        try:
            data = await self._rpc_call("listinvoices", {"payment_hash": checking_id})
            invoices = data.get("invoices") or []
            if not invoices:
                return PaymentStatus(
                    result=PaymentResult.UNKNOWN,
                    error_message="invoice not found",
                )
            status = invoices[0].get("status")
            return PaymentStatus(
                result=INVOICE_RESULT_MAP.get(status, PaymentResult.UNKNOWN),
            )
        except Exception as exc:
            logger.error(f"Error getting invoice status: {exc}")
            return PaymentStatus(result=PaymentResult.UNKNOWN, error_message=str(exc))

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        try:
            data = await self._rpc_call("listpays", {"payment_hash": checking_id})
            pays = data.get("pays") or []
            if not pays:
                return PaymentStatus(
                    result=PaymentResult.UNKNOWN,
                    error_message="payment not found",
                )

            pay = pays[0]
            result = PAYMENT_RESULT_MAP.get(pay.get("status"), PaymentResult.UNKNOWN)
            fee_msat, preimage = None, None
            if result == PaymentResult.SETTLED:
                if "amount_sent_msat" in pay and "amount_msat" in pay:
                    fee_msat = _parse_msat(pay["amount_sent_msat"]) - _parse_msat(
                        pay["amount_msat"]
                    )
                preimage = pay.get("preimage")

            return PaymentStatus(
                result=result,
                fee=Amount(unit=Unit.msat, amount=fee_msat) if fee_msat else None,
                preimage=preimage,
            )
        except Exception as exc:
            return PaymentStatus(result=PaymentResult.UNKNOWN, error_message=str(exc))

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        # Phase 1 is polling-only. This backend intentionally does not provide streams yet.
        if False:
            yield ""

    async def get_payment_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        invoice_obj = decode(melt_quote.request)
        assert invoice_obj.amount_msat, "invoice has no amount."
        assert invoice_obj.amount_msat > 0, "invoice has 0 amount."
        amount_msat = (
            melt_quote.mpp_amount if melt_quote.is_mpp else invoice_obj.amount_msat
        )
        fees_msat = fee_reserve(amount_msat)
        fees = Amount(unit=Unit.msat, amount=fees_msat)
        amount = Amount(unit=Unit.msat, amount=amount_msat)
        return PaymentQuoteResponse(
            checking_id=invoice_obj.payment_hash,
            fee=fees.to(self.unit, round="up"),
            amount=amount.to(self.unit, round="up"),
        )
