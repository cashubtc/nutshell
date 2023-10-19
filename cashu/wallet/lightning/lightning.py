import bolt11

from ...core.helpers import sum_promises
from ...core.settings import settings
from ...lightning.base import (
    InvoiceResponse,
    PaymentResponse,
    PaymentStatus,
    StatusResponse,
)
from ...wallet.crud import get_lightning_invoice, get_proofs
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

    async def create_invoice(self, amount: int) -> InvoiceResponse:
        """Create lightning invoice

        Args:
            amount (int): amount in satoshis
        Returns:
            str: invoice
        """
        invoice = await self.request_mint(amount)
        return InvoiceResponse(
            ok=True, payment_request=invoice.bolt11, checking_id=invoice.payment_hash
        )

    async def pay_invoice(self, pr: str) -> PaymentResponse:
        """Pay lightning invoice

        Args:
            pr (str): bolt11 payment request

        Returns:
            bool: True if successful
        """
        total_amount, fee_reserve_sat = await self.get_pay_amount_with_fees(pr)
        assert total_amount > 0, "amount is not positive"
        if self.available_balance < total_amount:
            print("Error: Balance too low.")
            return PaymentResponse(ok=False)
        _, send_proofs = await self.split_to_send(self.proofs, total_amount)
        try:
            resp = await self.pay_lightning(send_proofs, pr, fee_reserve_sat)
            if resp.change:
                fees_paid_sat = fee_reserve_sat - sum_promises(resp.change)
            else:
                fees_paid_sat = fee_reserve_sat

            invoice_obj = bolt11.decode(pr)
            return PaymentResponse(
                ok=True,
                checking_id=invoice_obj.payment_hash,
                preimage=resp.preimage,
                fee_msat=fees_paid_sat * 1000,
            )
        except Exception as e:
            print("Exception:", e)
            return PaymentResponse(ok=False, error_message=str(e))

    async def get_invoice_status(self, payment_hash: str) -> PaymentStatus:
        """Get lightning invoice status (incoming)

        Args:
            invoice (str): lightning invoice

        Returns:
            str: status
        """
        invoice = await get_lightning_invoice(
            db=self.db, payment_hash=payment_hash, out=False
        )
        if not invoice:
            return PaymentStatus(paid=None)
        if invoice.paid:
            return PaymentStatus(paid=True)
        try:
            # to check the invoice state, we try minting tokens
            await self.mint(invoice.amount, id=invoice.id)
            return PaymentStatus(paid=True)
        except Exception as e:
            print(e)
            return PaymentStatus(paid=False)

    async def get_payment_status(self, payment_hash: str) -> PaymentStatus:
        """Get lightning payment status (outgoing)

        Args:
            payment_hash (str): lightning invoice payment_hash

        Returns:
            str: status
        """

        # NOTE: consider adding this in wallet.py and update invoice state to paid in DB

        invoice = await get_lightning_invoice(
            db=self.db, payment_hash=payment_hash, out=True
        )

        if not invoice:
            return PaymentStatus(paid=False)  # "invoice not found (in db)"
        if invoice.paid:
            return PaymentStatus(paid=True, preimage=invoice.preimage)  # "paid (in db)"
        proofs = await get_proofs(db=self.db, melt_id=invoice.id)
        if not proofs:
            return PaymentStatus(paid=False)  # "proofs not fount (in db)"
        proofs_states = await self.check_proof_state(proofs)
        if (
            not proofs_states
            or not proofs_states.spendable
            or not proofs_states.pending
        ):
            return PaymentStatus(paid=False)  # "states not fount"

        if all(proofs_states.spendable) and all(proofs_states.pending):
            return PaymentStatus(paid=None)  # "pending (with check)"
        if not any(proofs_states.spendable) and not any(proofs_states.pending):
            # NOTE: consider adding this check in wallet.py and mark the invoice as paid if all proofs are spent
            return PaymentStatus(paid=True)  # "paid (with check)"
        if all(proofs_states.spendable) and not any(proofs_states.pending):
            return PaymentStatus(paid=False)  # "failed (with check)"
        return PaymentStatus(paid=None)  # "undefined state"

    async def get_balance(self) -> StatusResponse:
        """Get lightning balance

        Returns:
            int: balance in satoshis
        """
        return StatusResponse(
            error_message=None, balance_msat=self.available_balance * 1000
        )
