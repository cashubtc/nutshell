import json
import math
from typing import AsyncGenerator, Dict, Optional, Union

import bolt11
import httpx
from bolt11 import (
    decode,
)
from loguru import logger

from ..core.base import Amount, MeltQuote, Unit
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
)

# according to https://github.com/GaloyMoney/galoy/blob/7e79cc27304de9b9c2e7d7f4fdd3bac09df23aac/core/api/src/domain/bitcoin/index.ts#L59
BLINK_MAX_FEE_PERCENT = 0.5
# according to https://github.com/GaloyMoney/blink/blob/7e79cc27304de9b9c2e7d7f4fdd3bac09df23aac/core/api/src/domain/bitcoin/index.ts#L60C1-L60C41
MINIMUM_FEE_MSAT = 10_000

DIRECTION_SEND = "SEND"
DIRECTION_RECEIVE = "RECEIVE"
PROBE_FEE_TIMEOUT_SEC = 1


INVOICE_RESULT_MAP = {
    "PENDING": PaymentResult.PENDING,
    "PAID": PaymentResult.SETTLED,
    "EXPIRED": PaymentResult.FAILED,
}
PAYMENT_EXECUTION_RESULT_MAP = {
    "SUCCESS": PaymentResult.SETTLED,
    "ALREADY_PAID": PaymentResult.FAILED,
    "FAILURE": PaymentResult.FAILED,
}
PAYMENT_RESULT_MAP = {
    "SUCCESS": PaymentResult.SETTLED,
    "PENDING": PaymentResult.PENDING,
    "FAILURE": PaymentResult.FAILED,
}


class BlinkWallet(LightningBackend):
    """https://dev.blink.sv/
    Create API Key at: https://dashboard.blink.sv/
    """

    wallet_ids: Dict[Unit, str] = {}
    endpoint = "https://api.blink.sv/graphql"

    supported_units = {Unit.sat, Unit.msat, Unit.usd}
    supports_description: bool = True
    unit = Unit.sat

    def __init__(self, unit: Unit = Unit.sat, **kwargs):
        self.assert_unit_supported(unit)
        self.unit = unit
        assert settings.mint_blink_key, "MINT_BLINK_KEY not set"
        self.client = httpx.AsyncClient(
            verify=not settings.debug,
            headers={
                "X-Api-Key": settings.mint_blink_key,
                "Content-Type": "application/json",
            },
            base_url=self.endpoint,
            timeout=None,
        )

    async def status(self) -> StatusResponse:
        try:
            data = {
                "query": "query me { me { defaultAccount { wallets { id walletCurrency balance }}}}",
                "variables": {},
            }
            r = await self.client.post(
                url=self.endpoint,
                data=json.dumps(data),  # type: ignore
            )
            r.raise_for_status()
        except Exception as exc:
            logger.error(f"Blink API error: {exc}")
            return StatusResponse(
                error_message=f"Failed to connect to {self.endpoint} due to: {exc}",
                balance=Amount(self.unit, 0),
            )

        try:
            resp: dict = r.json()
        except Exception:
            return StatusResponse(
                error_message=(
                    f"Received invalid response from {self.endpoint}: {r.text}"
                ),
                balance=Amount(self.unit, 0),
            )

        balance = 0
        for wallet_dict in (
            resp.get("data", {}).get("me", {}).get("defaultAccount", {}).get("wallets")
        ):
            if wallet_dict.get("walletCurrency") == "USD":
                self.wallet_ids[Unit.usd] = wallet_dict["id"]  # type: ignore
                if self.unit == Unit.usd:
                    balance = wallet_dict["balance"]  # type: ignore
            elif wallet_dict.get("walletCurrency") == "BTC":
                self.wallet_ids[Unit.sat] = wallet_dict["id"]  # type: ignore
                if self.unit == Unit.sat or self.unit == Unit.msat:
                    balance = wallet_dict["balance"]  # type: ignore

        return StatusResponse(error_message=None, balance=Amount(self.unit, balance))

    async def create_invoice(
        self,
        amount: Amount,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        unhashed_description: Optional[bytes] = None,
    ) -> InvoiceResponse:
        self.assert_unit_supported(amount.unit)

        if self.unit == Unit.sat or self.unit == Unit.msat:
            variables = {
                "input": {
                    "amount": str(amount.to(Unit.sat).amount),
                    "recipientWalletId": self.wallet_ids[Unit.sat],
                }
            }
            if description_hash:
                variables["input"]["descriptionHash"] = description_hash.hex()
            if memo:
                variables["input"]["memo"] = memo

            data = {
                "query": """
                mutation LnInvoiceCreateOnBehalfOfRecipient($input: LnInvoiceCreateOnBehalfOfRecipientInput!) {
                    lnInvoiceCreateOnBehalfOfRecipient(input: $input) {
                        invoice {
                            paymentRequest
                            paymentHash
                            paymentSecret
                            satoshis
                        }
                        errors {
                            message path code
                        }
                    }
                }
                """,
                "variables": variables,
            }
            response_key = "lnInvoiceCreateOnBehalfOfRecipient"
        elif self.unit == Unit.usd:
            variables = {
                "input": {
                    "amount": str(amount.to(Unit.usd).amount),
                    "recipientWalletId": self.wallet_ids[Unit.usd],
                }
            }
            if description_hash:
                variables["input"]["descriptionHash"] = description_hash.hex()
            if memo:
                variables["input"]["memo"] = memo

            data = {
                "query": """
                mutation LnUsdInvoiceCreateOnBehalfOfRecipient($input: LnUsdInvoiceCreateOnBehalfOfRecipientInput!) {
                    lnUsdInvoiceCreateOnBehalfOfRecipient(input: $input) {
                        invoice {
                            paymentRequest
                            paymentHash
                            paymentSecret
                            satoshis
                        }
                        errors {
                            message path code
                        }
                    }
                }
                """,
                "variables": variables,
            }
            response_key = "lnUsdInvoiceCreateOnBehalfOfRecipient"
        else:
            raise Exception(f"Unsupported unit: {self.unit}")

        try:
            r = await self.client.post(
                url=self.endpoint,
                data=json.dumps(data),  # type: ignore
            )
            r.raise_for_status()
        except Exception as e:
            logger.error(f"Blink API error: {e}")
            return InvoiceResponse(ok=False, error_message=str(e))

        resp = r.json()
        assert resp, "invalid response"
        payment_request = (
            resp.get("data", {})
            .get(response_key, {})
            .get("invoice", {})
            .get("paymentRequest")
        )
        assert payment_request, "payment request not found"
        checking_id = payment_request

        return InvoiceResponse(
            ok=True,
            checking_id=checking_id,
            payment_request=payment_request,
        )

    async def pay_invoice(
        self, quote: MeltQuote, fee_limit_msat: int
    ) -> PaymentResponse:
        if self.unit == Unit.sat or self.unit == Unit.msat:
            wallet_id = self.wallet_ids[Unit.sat]
        elif self.unit == Unit.usd:
            wallet_id = self.wallet_ids[Unit.usd]
        else:
            raise Exception(f"Unsupported unit: {self.unit}")

        variables = {
            "input": {
                "paymentRequest": quote.request,
                "walletId": wallet_id,
            }
        }
        data = {
            "query": """
            mutation lnInvoicePaymentSend($input: LnInvoicePaymentInput!) {
                lnInvoicePaymentSend(input: $input) {
                    errors {
                        message path code
                    }
                    status
                    transaction {
                        settlementAmount settlementFee status
                    }
                }
            }
            """,
            "variables": variables,
        }

        try:
            r = await self.client.post(
                url=self.endpoint,
                data=json.dumps(data),  # type: ignore
                timeout=None,
            )
            r.raise_for_status()
        except Exception as e:
            logger.error(f"Blink API error: {e}")
            return PaymentResponse(
                result=PaymentResult.UNKNOWN,
                error_message=str(e),
            )

        resp: dict = r.json()

        error_message: Union[None, str] = None
        fee: Union[None, int] = None
        if resp.get("data", {}).get("lnInvoicePaymentSend", {}).get("errors"):
            error_message = (
                resp["data"]["lnInvoicePaymentSend"]["errors"][0].get("message")  # type: ignore
                or "Unknown error"
            )

        status_str = resp.get("data", {}).get("lnInvoicePaymentSend", {}).get("status")
        result = PAYMENT_EXECUTION_RESULT_MAP[status_str]

        if status_str == "ALREADY_PAID":
            error_message = "Invoice already paid"

        if result == PaymentResult.FAILED:
            return PaymentResponse(
                result=result,
                error_message=error_message,
                checking_id=quote.request,
            )

        if resp.get("data", {}).get("lnInvoicePaymentSend", {}).get("transaction", {}):
            fee = (
                resp.get("data", {})
                .get("lnInvoicePaymentSend", {})
                .get("transaction", {})
                .get("settlementFee")
            )

        checking_id = quote.request
        preimage: Union[None, str] = None
        payment_status = await self.get_payment_status(checking_id)
        if payment_status.settled:
            preimage = payment_status.preimage

        fee_amount: Union[None, Amount] = None
        if fee:
            if self.unit == Unit.sat or self.unit == Unit.msat:
                fee_amount = Amount(Unit.sat, fee)
            elif self.unit == Unit.usd:
                fee_cents = await self._sats_to_cents(fee)
                fee_amount = Amount(Unit.usd, fee_cents)
            else:
                raise Exception(f"Unsupported unit: {self.unit}")

        return PaymentResponse(
            result=result,
            checking_id=checking_id,
            fee=fee_amount,
            preimage=preimage,
            error_message=error_message,
        )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        variables = {"input": {"paymentRequest": checking_id}}
        data = {
            "query": """
        query lnInvoicePaymentStatus($input: LnInvoicePaymentStatusInput!) {
                lnInvoicePaymentStatus(input: $input) {
                    errors {
                        message path code
                    }
                    status
                }
            }
        """,
            "variables": variables,
        }
        try:
            r = await self.client.post(url=self.endpoint, data=json.dumps(data))  # type: ignore
            r.raise_for_status()
        except Exception as e:
            logger.error(f"Blink API error: {e}")
            return PaymentStatus(result=PaymentResult.UNKNOWN, error_message=str(e))
        resp: dict = r.json()
        error_message = (
            resp.get("data", {}).get("lnInvoicePaymentStatus", {}).get("errors")
        )
        if error_message:
            logger.error(
                "Blink Error",
                error_message,
            )
            return PaymentStatus(
                result=PaymentResult.UNKNOWN, error_message=error_message
            )
        result = INVOICE_RESULT_MAP[
            resp.get("data", {}).get("lnInvoicePaymentStatus", {}).get("status")
        ]
        return PaymentStatus(result=result)

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        payment_hash = bolt11.decode(checking_id).payment_hash
        if self.unit == Unit.sat or self.unit == Unit.msat:
            wallet_id = self.wallet_ids[Unit.sat]
        elif self.unit == Unit.usd:
            wallet_id = self.wallet_ids[Unit.usd]
        else:
            raise Exception(f"Unsupported unit: {self.unit}")

        variables = {
            "paymentHash": payment_hash,
            "walletId": wallet_id,
        }
        data = {
            "query": """
            query TransactionsByPaymentHash($paymentHash: PaymentHash!, $walletId: WalletId!) {
                me {
                    defaultAccount {
                        walletById(walletId: $walletId) {
                            transactionsByPaymentHash(paymentHash: $paymentHash) {
                                status
                                direction
                                settlementFee
                                settlementVia {
                                    ... on SettlementViaIntraLedger {
                                        preImage
                                    }
                                    ... on SettlementViaLn {
                                        preImage
                                    }
                                }
                            }
                        }
                    }
                }
            }
            """,
            "variables": variables,
        }
        r = await self.client.post(
            url=self.endpoint,
            data=json.dumps(data),  # type: ignore
        )
        r.raise_for_status()

        resp: dict = r.json()

        # no result found, this payment has not been attempted before
        if (
            not resp.get("data", {})
            .get("me", {})
            .get("defaultAccount", {})
            .get("walletById", {})
            .get("transactionsByPaymentHash")
        ):
            return PaymentStatus(
                result=PaymentResult.UNKNOWN, error_message="No payment found"
            )

        all_payments_with_this_hash = (
            resp.get("data", {})
            .get("me", {})
            .get("defaultAccount", {})
            .get("walletById", {})
            .get("transactionsByPaymentHash")
        )

        # Blink API edge case: for a previously failed payment attempt, it returns the two payments with the same hash
        # if there are two payments with the same hash with "direction" == "SEND" and "RECEIVE"
        # it means that the payment previously failed and we can ignore the attempt and return
        # PaymentStatus(status=FAILED)
        if len(all_payments_with_this_hash) == 2 and all(
            p["direction"] in [DIRECTION_SEND, DIRECTION_RECEIVE]  # type: ignore
            for p in all_payments_with_this_hash
        ):
            return PaymentStatus(
                result=PaymentResult.FAILED, error_message="Payment failed"
            )

        # if there is only one payment with the same hash, it means that the payment might have succeeded
        # we only care about the payment with "direction" == "SEND"
        payment = next(
            (
                p
                for p in all_payments_with_this_hash
                if p.get("direction") == DIRECTION_SEND
            ),
            None,
        )
        if not payment:
            return PaymentStatus(
                result=PaymentResult.UNKNOWN, error_message="No payment found"
            )

        result = PAYMENT_RESULT_MAP[payment["status"]]  # type: ignore
        fee = payment["settlementFee"]  # type: ignore
        preimage = payment["settlementVia"].get("preImage")  # type: ignore

        if self.unit == Unit.sat or self.unit == Unit.msat:
            fee_amount = Amount(Unit.sat, fee)
        elif self.unit == Unit.usd:
            fee_cents = await self._sats_to_cents(fee)
            fee_amount = Amount(Unit.usd, fee_cents)
        else:
            raise Exception(f"Unsupported unit: {self.unit}")

        return PaymentStatus(
            result=result,
            fee=fee_amount,
            preimage=preimage,
        )

    async def _get_sats_per_usd(self) -> int:
        data = {
            "query": """
            query currencyConversionEstimation($amount: Float!, $currency: DisplayCurrency!) {
                currencyConversionEstimation(amount: $amount, currency: $currency) {
                    btcSatAmount
                    usdCentAmount
                }
            }
            """,
            "variables": {
                "amount": 1,
                "currency": "USD"
            },
        }
        try:
            r = await self.client.post(
                url=self.endpoint,
                data=json.dumps(data),  # type: ignore
            )
            r.raise_for_status()
        except Exception as e:
            logger.error(f"Blink currency conversion API error: {e}")
            raise Exception(f"Failed to fetch conversion rate from Blink: {e}")

        resp: dict = r.json()
        conversion = resp.get("data", {}).get("currencyConversionEstimation")

        if not conversion:
            logger.error("Blink currencyConversionEstimation returned null")
            raise Exception("Currency conversion service unavailable")

        sats_per_usd = conversion.get("btcSatAmount")

        if not sats_per_usd or sats_per_usd == 0:
            logger.error(f"Invalid conversion data from Blink: btcSatAmount={sats_per_usd}")
            raise Exception("Invalid conversion data: btcSatAmount is missing or zero")

        return int(sats_per_usd)

    def _sats_to_cents_with_rate(self, sats: int, sats_per_usd: int) -> int:
        return math.ceil(sats * 100 / sats_per_usd)

    async def _sats_to_cents(self, sats: int) -> int:
        sats_per_usd = await self._get_sats_per_usd()
        return self._sats_to_cents_with_rate(sats, sats_per_usd)

    async def get_payment_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        bolt11 = melt_quote.request
        invoice_obj = decode(bolt11)
        assert invoice_obj.amount_msat, "invoice has no amount."
        amount_msat = int(invoice_obj.amount_msat)

        if self.unit == Unit.sat or self.unit == Unit.msat:
            variables = {
                "input": {
                    "paymentRequest": bolt11,
                    "walletId": self.wallet_ids[Unit.sat],
                }
            }
            data = {
                "query": """
                mutation lnInvoiceFeeProbe($input: LnInvoiceFeeProbeInput!) {
                    lnInvoiceFeeProbe(input: $input) {
                        amount
                        errors {
                            message path code
                        }
                    }
                }
                """,
                "variables": variables,
            }
            response_key = "lnInvoiceFeeProbe"
        elif self.unit == Unit.usd:
            variables = {
                "input": {
                    "paymentRequest": bolt11,
                    "walletId": self.wallet_ids[Unit.usd],
                }
            }
            data = {
                "query": """
                mutation lnUsdInvoiceFeeProbe($input: LnUsdInvoiceFeeProbeInput!) {
                    lnUsdInvoiceFeeProbe(input: $input) {
                        amount
                        errors {
                            message path code
                        }
                    }
                }
                """,
                "variables": variables,
            }
            response_key = "lnUsdInvoiceFeeProbe"
        else:
            raise Exception(f"Unsupported unit: {self.unit}")

        fees_response_msat = 0
        try:
            r = await self.client.post(
                url=self.endpoint,
                data=json.dumps(data),  # type: ignore
                timeout=PROBE_FEE_TIMEOUT_SEC,
            )
            r.raise_for_status()
            resp: dict = r.json()
            if resp.get("data", {}).get(response_key, {}).get("errors"):
                fees_response_msat = 0
                logger.debug(
                    f"Blink probe error: {resp['data'][response_key]['errors'][0].get('message')}"
                )
            else:
                fees_response_msat = (
                    int(resp.get("data", {}).get(response_key, {}).get("amount"))
                    * 1000
                )
        except httpx.ReadTimeout:
            pass
        except Exception as e:
            logger.error(f"Blink API error: {e}")
            raise e

        fees_amount_msat: int = (
            math.ceil(amount_msat / 100 * BLINK_MAX_FEE_PERCENT / 1000) * 1000
        )

        fees_msat: int = max(
            fees_response_msat,
            max(
                fees_amount_msat,
                MINIMUM_FEE_MSAT,
            ),
        )

        if self.unit == Unit.sat or self.unit == Unit.msat:
            fees = Amount(unit=Unit.msat, amount=fees_msat)
            amount = Amount(unit=Unit.msat, amount=amount_msat)
            return PaymentQuoteResponse(
                checking_id=bolt11,
                fee=fees.to(self.unit, round="up"),
                amount=amount.to(self.unit, round="up"),
            )
        elif self.unit == Unit.usd:
            sats_per_usd = await self._get_sats_per_usd()
            amount_sats = amount_msat // 1000
            fees_sats = fees_msat // 1000
            amount_cents = self._sats_to_cents_with_rate(amount_sats, sats_per_usd)
            fees_cents = self._sats_to_cents_with_rate(fees_sats, sats_per_usd)
            return PaymentQuoteResponse(
                checking_id=bolt11,
                fee=Amount(Unit.usd, fees_cents),
                amount=Amount(Unit.usd, amount_cents),
            )
        else:
            raise Exception(f"Unsupported unit: {self.unit}")

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:  # type: ignore
        raise NotImplementedError("paid_invoices_stream not implemented")
