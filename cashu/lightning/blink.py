# type: ignore
import asyncio
import json
from typing import Dict, Optional

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


class BlinkWallet(LightningBackend):
    """https://dev.blink.sv/
    Create API Key at: https://dashboard.blink.sv/
    """

    units = set([Unit.sat, Unit.usd])
    wallet_ids: Dict[Unit, str] = {}
    endpoint = "https://api.blink.sv/graphql"
    invoice_statuses = {"PENDING": None, "PAID": True, "EXPIRED": False}
    payment_execution_statuses = {"SUCCESS": True, "ALREADY_PAID": None}
    payment_statuses = {"SUCCESS": True, "PENDING": None, "FAILURE": False}

    def __init__(self):
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
            data: dict = r.json()
        except Exception:
            return StatusResponse(
                error_message=(
                    f"Received invalid response from {self.endpoint}: {r.text}"
                ),
                balance=0,
            )

        balance = 0
        for wallet_dict in data["data"]["me"]["defaultAccount"]["wallets"]:
            if wallet_dict["walletCurrency"] == "USD":
                self.wallet_ids[Unit.usd] = wallet_dict["id"]
            elif wallet_dict["walletCurrency"] == "BTC":
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

        data = r.json()
        assert data, "invalid response"
        payment_request = data["data"]["lnInvoiceCreateOnBehalfOfRecipient"]["invoice"][
            "paymentRequest"
        ]
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
            )
            r.raise_for_status()
        except Exception as e:
            logger.error(f"Blink API error: {str(e)}")
            return PaymentResponse(ok=False, error_message=str(e))

        data: dict = r.json()
        paid = self.payment_execution_statuses[
            data["data"]["lnInvoicePaymentSend"]["status"]
        ]
        fee = data["data"]["lnInvoicePaymentSend"]["transaction"]["settlementFee"]
        checking_id = quote.request

        return PaymentResponse(
            ok=paid,
            checking_id=checking_id,
            fee=Amount(Unit.sat, fee),
            preimage=None,
            error_message="Invoice already paid." if paid is None else None,
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
        data: dict = r.json()
        if data["data"]["lnInvoicePaymentStatus"]["errors"]:
            logger.error(
                "Blink Error", data["data"]["lnInvoicePaymentStatus"]["errors"]
            )
            return PaymentStatus(paid=None)
        paid = self.invoice_statuses[data["data"]["lnInvoicePaymentStatus"]["status"]]
        return PaymentStatus(paid=paid)

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        return PaymentStatus(
            paid=False,
        )
        # THIS IS NOT SUITED FOR get_payment_status because it executes the payment if it's not paid
        # LOOK FOR A METHOD THAT JUST CHECKS THE TRANSACTION STATUS
        variables = {
            "input": {
                "paymentRequest": checking_id,
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
            )
            r.raise_for_status()
        except Exception as e:
            logger.error(f"Blink API error: {str(e)}")
            return PaymentResponse(ok=False, error_message=str(e))

        data: dict = r.json()
        assert not data["data"]["lnInvoicePaymentSend"]["errors"], data["data"][
            "lnInvoicePaymentSend"
        ]["errors"][0]["message"]
        paid = self.payment_statuses[
            data["data"]["lnInvoicePaymentSend"]["transaction"]["status"]
        ]
        fee = data["data"]["lnInvoicePaymentSend"]["transaction"]["settlementFee"]

        return PaymentStatus(
            paid=paid,
            fee=Amount(Unit.sat, fee),
            preimage=None,
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

        try:
            r = await self.client.post(
                url=self.endpoint,
                data=json.dumps(data),
            )
            r.raise_for_status()
        except Exception as e:
            logger.error(f"Blink API error: {str(e)}")
            return PaymentResponse(ok=False, error_message=str(e))
        data: dict = r.json()

        invoice_obj = decode(bolt11)
        assert invoice_obj.amount_msat, "invoice has no amount."
        amount_msat = int(invoice_obj.amount_msat)
        fees_msat = int(data["data"]["lnInvoiceFeeProbe"]["amount"]) * 1000
        fees = Amount(unit=Unit.msat, amount=fees_msat)
        amount = Amount(unit=Unit.msat, amount=amount_msat)
        return PaymentQuoteResponse(checking_id=bolt11, fee=fees, amount=amount)


async def main():
    pass


if __name__ == "__main__":
    asyncio.run(main())
