# type: ignore
import asyncio
import json
import math
from typing import Dict, Optional, Union

import bolt11
import httpx
from bolt11 import (
    decode,
)
from loguru import logger

from ..core.base import Amount, MeltQuote, Unit
from ..core.settings import settings
from .base import (
    InvoiceResponse,
    LightningBackend,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentStatus,
    StatusResponse,
)

# according to https://github.com/GaloyMoney/galoy/blob/7e79cc27304de9b9c2e7d7f4fdd3bac09df23aac/core/api/src/domain/bitcoin/index.ts#L59
BLINK_MAX_FEE_PERCENT = 0.5

DIRECTION_SEND = "SEND"
DIRECTION_RECEIVE = "RECEIVE"
PROBE_FEE_TIMEOUT_SEC = 1
MINIMUM_FEE_MSAT = 2000


class BlinkWallet(LightningBackend):
    """https://dev.blink.sv/
    Create API Key at: https://dashboard.blink.sv/
    """

    units = set([Unit.sat, Unit.usd])
    wallet_ids: Dict[Unit, str] = {}
    endpoint = "https://api.blink.sv/graphql"
    invoice_statuses = {"PENDING": None, "PAID": True, "EXPIRED": False}
    payment_execution_statuses = {
        "SUCCESS": True,
        "ALREADY_PAID": None,
        "FAILURE": False,
    }
    payment_statuses = {"SUCCESS": True, "PENDING": None, "FAILURE": False}

    def __init__(self):
        assert settings.mint_blink_key, "MINT_BLINK_KEY not set"
        self.client = httpx.AsyncClient(
            verify=not settings.debug,
            headers={
                "X-Api-Key": settings.mint_blink_key,
                "Content-Type": "application/json",
            },
            base_url=self.endpoint,
            timeout=15,
        )

    async def status(self) -> StatusResponse:
        try:
            r = await self.client.post(
                url=self.endpoint,
                data=(
                    '{"query":"query me { me { defaultAccount { wallets { id'
                    ' walletCurrency balance }}}}", "variables":{}}'
                ),
            )
            r.raise_for_status()
        except Exception as exc:
            logger.error(f"Blink API error: {str(exc)}")
            return StatusResponse(
                error_message=f"Failed to connect to {self.endpoint} due to: {exc}",
                balance=0,
            )

        try:
            resp: dict = r.json()
        except Exception:
            return StatusResponse(
                error_message=(
                    f"Received invalid response from {self.endpoint}: {r.text}"
                ),
                balance=0,
            )

        balance = 0
        for wallet_dict in (
            resp.get("data", {}).get("me", {}).get("defaultAccount", {}).get("wallets")
        ):
            if wallet_dict.get("walletCurrency") == "USD":
                self.wallet_ids[Unit.usd] = wallet_dict["id"]
            elif wallet_dict.get("walletCurrency") == "BTC":
                self.wallet_ids[Unit.sat] = wallet_dict["id"]
                balance = wallet_dict["balance"]

        return StatusResponse(error_message=None, balance=balance)

    async def create_invoice(
        self,
        amount: Amount,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        unhashed_description: Optional[bytes] = None,
    ) -> InvoiceResponse:
        self.assert_unit_supported(amount.unit)

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
        try:
            r = await self.client.post(
                url=self.endpoint,
                data=json.dumps(data),
            )
            r.raise_for_status()
        except Exception as e:
            logger.error(f"Blink API error: {str(e)}")
            return InvoiceResponse(ok=False, error_message=str(e))

        resp = r.json()
        assert resp, "invalid response"
        payment_request = (
            resp.get("data", {})
            .get("lnInvoiceCreateOnBehalfOfRecipient", {})
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
        variables = {
            "input": {
                "paymentRequest": quote.request,
                "walletId": self.wallet_ids[Unit.sat],
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
                data=json.dumps(data),
                timeout=None,
            )
            r.raise_for_status()
        except Exception as e:
            logger.error(f"Blink API error: {str(e)}")
            return PaymentResponse(ok=False, error_message=str(e))

        resp: dict = r.json()

        error_message: Union[None, str] = None
        fee: Union[None, int] = None
        if resp.get("data", {}).get("lnInvoicePaymentSend", {}).get("errors"):
            error_message = (
                resp["data"]["lnInvoicePaymentSend"]["errors"][0].get("message")
                or "Unknown error"
            )

        paid = self.payment_execution_statuses[
            resp.get("data", {}).get("lnInvoicePaymentSend", {}).get("status")
        ]
        if paid is None:
            error_message = "Invoice already paid."

        if resp.get("data", {}).get("lnInvoicePaymentSend", {}).get("transaction", {}):
            fee = (
                resp.get("data", {})
                .get("lnInvoicePaymentSend", {})
                .get("transaction", {})
                .get("settlementFee")
            )

        checking_id = quote.request

        # we check the payment status to get the preimage
        preimage: Union[None, str] = None
        payment_status = await self.get_payment_status(checking_id)
        if payment_status.paid:
            preimage = payment_status.preimage

        return PaymentResponse(
            ok=paid,
            checking_id=checking_id,
            fee=Amount(Unit.sat, fee) if fee else None,
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
            r = await self.client.post(url=self.endpoint, data=json.dumps(data))
            r.raise_for_status()
        except Exception as e:
            logger.error(f"Blink API error: {str(e)}")
            return PaymentStatus(paid=None)
        resp: dict = r.json()
        if resp.get("data", {}).get("lnInvoicePaymentStatus", {}).get("errors"):
            logger.error(
                "Blink Error",
                resp.get("data", {}).get("lnInvoicePaymentStatus", {}).get("errors"),
            )
            return PaymentStatus(paid=None)
        paid = self.invoice_statuses[
            resp.get("data", {}).get("lnInvoicePaymentStatus", {}).get("status")
        ]
        return PaymentStatus(paid=paid)

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        # Checking ID is the payment request and blink wants the payment hash
        payment_hash = bolt11.decode(checking_id).payment_hash
        variables = {
            "paymentHash": payment_hash,
            "walletId": self.wallet_ids[Unit.sat],
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

        try:
            r = await self.client.post(
                url=self.endpoint,
                data=json.dumps(data),
            )
            r.raise_for_status()
        except Exception as e:
            logger.error(f"Blink API error: {str(e)}")
            return PaymentResponse(ok=False, error_message=str(e))

        resp: dict = r.json()

        # no result found, this payment has not been attempted before
        if (
            not resp.get("data", {})
            .get("me", {})
            .get("defaultAccount", {})
            .get("walletById", {})
            .get("transactionsByPaymentHash")
        ):
            return PaymentStatus(paid=None)

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
        # PaymentStatus(paid=None)
        if len(all_payments_with_this_hash) == 2 and all(
            p["direction"] in [DIRECTION_SEND, DIRECTION_RECEIVE]
            for p in all_payments_with_this_hash
        ):
            return PaymentStatus(paid=None)

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
            return PaymentStatus(paid=None)

        # we read the status of the payment
        paid = self.payment_statuses[payment["status"]]
        fee = payment["settlementFee"]
        preimage = payment["settlementVia"].get("preImage")

        return PaymentStatus(
            paid=paid,
            fee=Amount(Unit.sat, fee),
            preimage=preimage,
        )

    async def get_payment_quote(self, bolt11: str) -> PaymentQuoteResponse:
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

        fees_response_msat = 0
        try:
            r = await self.client.post(
                url=self.endpoint,
                data=json.dumps(data),
                timeout=PROBE_FEE_TIMEOUT_SEC,
            )
            r.raise_for_status()
            resp: dict = r.json()
            if resp.get("data", {}).get("lnInvoiceFeeProbe", {}).get("errors"):
                # if there was an error, we simply ignore the response and decide the fees ourselves
                fees_response_msat = 0
                logger.debug(
                    f"Blink probe error: {resp['data']['lnInvoiceFeeProbe']['errors'][0].get('message')}"
                )

            else:
                fees_response_msat = (
                    int(resp.get("data", {}).get("lnInvoiceFeeProbe", {}).get("amount"))
                    * 1000
                )
        except httpx.ReadTimeout:
            pass
        except Exception as e:
            logger.error(f"Blink API error: {str(e)}")
            raise e

        invoice_obj = decode(bolt11)
        assert invoice_obj.amount_msat, "invoice has no amount."

        amount_msat = int(invoice_obj.amount_msat)

        # we take the highest: fee_msat_response, or BLINK_MAX_FEE_PERCENT, or MINIMUM_FEE_MSAT msat
        # Note: fees with BLINK_MAX_FEE_PERCENT are rounded to the nearest 1000 msat
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

        fees = Amount(unit=Unit.msat, amount=fees_msat)
        amount = Amount(unit=Unit.msat, amount=amount_msat)
        return PaymentQuoteResponse(checking_id=bolt11, fee=fees, amount=amount)


async def main():
    pass


if __name__ == "__main__":
    asyncio.run(main())
