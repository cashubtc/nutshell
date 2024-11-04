from typing import Optional

import bolt11

from ...core.base import Amount, Unit
from ...core.helpers import sum_promises
from ...core.settings import settings
from ...lightning.base import (
    InvoiceResponse,
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
    StatusResponse,
)
from ...wallet.crud import (
    get_bolt11_melt_quote,
    get_bolt11_mint_quote,
    get_proofs,
)
from ..wallet import Wallet


class LightningWallet(Wallet):
    """
    Lightning wallet interface for Cashu
    """

    async def async_init(self, raise_connection_error: bool = True):
        """Async init for lightning wallet"""
        settings.tor = False
        await self.load_proofs()
        try:
            await self.load_mint()
        except Exception as e:
            if raise_connection_error:
                raise e

    def __init__(self, *args, **kwargs):
        if not args and not kwargs:
            pass
        super().__init__(*args, **kwargs)

    async def create_invoice(
        self, amount: int, memo: Optional[str] = None
    ) -> InvoiceResponse:
        """Create lightning invoice

        Args:
            amount (int): amount in satoshis
            memo (str, optional): invoice memo. Defaults to None.
        Returns:
            str: invoice
        """
        mint_quote = await self.request_mint(amount, memo)
        return InvoiceResponse(
            ok=True,
            payment_request=mint_quote.request,
        )

    async def pay_invoice(self, request: str) -> PaymentResponse:
        """Pay lightning invoice

        Args:
            request (str): bolt11 payment request

        Returns:
            PaymentResponse: containing details of the operation
        """
        quote = await self.melt_quote(request)
        total_amount = quote.amount + quote.fee_reserve
        assert total_amount > 0, "amount is not positive"
        if self.available_balance < total_amount:
            print("Error: Balance too low.")
            return PaymentResponse(result=PaymentResult.FAILED)
        _, send_proofs = await self.swap_to_send(self.proofs, total_amount)
        try:
            resp = await self.melt(send_proofs, request, quote.fee_reserve, quote.quote)
            if resp.change:
                fees_paid_sat = quote.fee_reserve - sum_promises(resp.change)
            else:
                fees_paid_sat = quote.fee_reserve

            invoice_obj = bolt11.decode(request)
            return PaymentResponse(
                result=PaymentResult.SETTLED,
                checking_id=invoice_obj.payment_hash,
                preimage=resp.payment_preimage,
                fee=Amount(Unit.msat, fees_paid_sat),
            )
        except Exception as e:
            print("Exception:", e)
            return PaymentResponse(result=PaymentResult.FAILED, error_message=str(e))

    async def get_invoice_status(self, request: str) -> PaymentStatus:
        """Get lightning invoice status (incoming)

        Args:
            request (str): lightning invoice request

        Returns:
            str: status
        """
        mint_quote = await get_bolt11_mint_quote(db=self.db, request=request)
        if not mint_quote:
            return PaymentStatus(result=PaymentResult.UNKNOWN)
        if mint_quote.paid:
            return PaymentStatus(result=PaymentResult.SETTLED)
        try:
            # to check the invoice state, we try minting tokens
            await self.mint(mint_quote.amount, quote_id=mint_quote.quote)
            return PaymentStatus(result=PaymentResult.SETTLED)
        except Exception as e:
            print(e)
            return PaymentStatus(result=PaymentResult.FAILED)

    async def get_payment_status(self, request: str) -> PaymentStatus:
        """Get lightning payment status (outgoing)

        Args:
            request (str): lightning invoice request

        Returns:
            str: status
        """

        melt_quote = await get_bolt11_melt_quote(db=self.db, request=request)

        if not melt_quote:
            return PaymentStatus(
                result=PaymentResult.FAILED
            )  # "invoice not found (in db)"
        if melt_quote.paid:
            return PaymentStatus(
                result=PaymentResult.SETTLED, preimage=melt_quote.payment_preimage
            )  # "paid (in db)"
        proofs = await get_proofs(db=self.db, melt_id=melt_quote.quote)
        if not proofs:
            return PaymentStatus(
                result=PaymentResult.FAILED
            )  # "proofs not fount (in db)"
        proofs_states = await self.check_proof_state(proofs)
        if not proofs_states:
            return PaymentStatus(result=PaymentResult.FAILED)  # "states not fount"

        if all([p.state.pending for p in proofs_states.states]):
            return PaymentStatus(result=PaymentResult.PENDING)  # "pending (with check)"
        if any([p.state.spent for p in proofs_states.states]):
            # NOTE: consider adding this check in wallet.py and mark the invoice as paid if all proofs are spent
            return PaymentStatus(result=PaymentResult.SETTLED)  # "paid (with check)"
        if all([p.state.unspent for p in proofs_states.states]):
            return PaymentStatus(result=PaymentResult.FAILED)  # "failed (with check)"
        return PaymentStatus(result=PaymentResult.UNKNOWN)  # "undefined state"

    async def get_balance(self) -> StatusResponse:
        """Get lightning balance

        Returns:
            int: balance in satoshis
        """
        return StatusResponse(error_message=None, balance=self.available_balance * 1000)
