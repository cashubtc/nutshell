from ...core.base import Invoice
from ...core.settings import settings
from ...wallet.crud import get_lightning_invoice, get_proofs
from ..wallet import Wallet


class LightningWallet(Wallet):
    """
    Lightning wallet interface for Cashu
    """

    # wallet: Wallet

    async def async_init(self):
        """Async init for lightning wallet"""
        settings.tor = False
        await self.load_proofs()
        await self.load_mint()

    def __init__(self, *args, **kwargs):
        if not args and not kwargs:
            pass
        super().__init__(*args, **kwargs)

    async def create_invoice(self, amount: int) -> Invoice:
        """Create lightning invoice

        Args:
            amount (int): amount in satoshis
        Returns:
            str: invoice
        """
        invoice = await self.request_mint(amount)
        return invoice

    async def pay_invoice(self, pr: str) -> bool:
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
            return False
        _, send_proofs = await self.split_to_send(self.proofs, total_amount)
        try:
            await self.pay_lightning(send_proofs, pr, fee_reserve_sat)
            return True
        except Exception as e:
            print("Exception:", e)
            return False

    async def get_invoice_status(self, payment_hash: str):
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
            return "not found (in db)"
        if invoice.paid:
            return "paid (in db)"
        try:
            # to check the invoice state, we try minting tokens
            await self.mint(invoice.amount, id=invoice.id)
            return "paid (with check)"
        except Exception as e:
            print(e)
            return "pending"

    async def get_payment_status(self, payment_hash: str):
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
            return "invoice not found (in db)"
        if invoice.paid:
            return "paid (in db)"
        proofs = await get_proofs(db=self.db, melt_id=invoice.id)
        if not proofs:
            return "proofs not fount (in db)"
        proofs_states = await self.check_proof_state(proofs)
        if (
            not proofs_states
            or not proofs_states.spendable
            or not proofs_states.pending
        ):
            return "states not fount"

        if all(proofs_states.spendable) and all(proofs_states.pending):
            return "pending (with check)"
        if not any(proofs_states.spendable) and not any(proofs_states.pending):
            # NOTE: consider adding this check in wallet.py and mark the invoice as paid if all proofs are spent
            return "paid (with check)"
        if all(proofs_states.spendable) and not any(proofs_states.pending):
            return "failed (with check)"
        return "undefined state"

    async def get_balance(self):
        """Get lightning balance

        Returns:
            int: balance in satoshis
        """
        return self.available_balance
