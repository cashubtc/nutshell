from ...core.base import Invoice
from ...core.settings import settings
from ...wallet.crud import get_lightning_invoice, get_proofs
from ..wallet import Wallet


class LightningWallet(Wallet):
    """
    Lightning wallet interface for Cashu
    """

    wallet: Wallet

    @classmethod
    async def async_init(cls, *args, **kwargs):
        """Async init for lightning wallet"""
        settings.tor = False
        self = cls(*args, **kwargs)
        # self.__init__(*args, **kwargs)
        self.wallet = await Wallet.with_db(*args, **kwargs)
        await self.wallet.load_proofs()
        await self.wallet.load_mint()
        return self

    def __init__(self, *args, **kwargs):
        pass
        # settings.tor = False
        # print(kwargs)
        # super().__init__(*args, **kwargs)

        # asyncio.run(self.async_init(url, db, *args, **kwargs))

    async def create_invoice(self, amount: int, memo: str) -> Invoice:
        """Create lightning invoice

        Args:
            amount (int): amount in satoshis
            memo (str): memo for the invoice

        Returns:
            str: invoice
        """
        invoice = await self.wallet.request_mint(amount)
        return invoice

    async def pay_invoice(self, pr: str) -> bool:
        """Pay lightning invoice

        Args:
            pr (str): bolt11 payment request

        Returns:
            bool: True if successful
        """
        total_amount, fee_reserve_sat = await self.wallet.get_pay_amount_with_fees(pr)
        assert total_amount > 0, "amount is not positive"
        if self.wallet.available_balance < total_amount:
            print("Error: Balance too low.")
            return False
        _, send_proofs = await self.wallet.split_to_send(
            self.wallet.proofs, total_amount
        )
        try:
            await self.wallet.pay_lightning(send_proofs, pr, fee_reserve_sat)
            return True
        except Exception as e:
            print(e)
            return False

    async def get_invoice_status(self, payment_hash: str):
        """Get lightning invoice status (incoming)

        Args:
            invoice (str): lightning invoice

        Returns:
            str: status
        """
        invoice = await get_lightning_invoice(
            db=self.wallet.db, payment_hash=payment_hash
        )
        if not invoice:
            return "not found"
        if invoice.paid:
            return "paid"
        try:
            await self.wallet.mint(invoice.amount, hash=invoice.id)
            return "paid"
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
            db=self.wallet.db, payment_hash=payment_hash
        )
        if not invoice:
            return "not found"
        proofs = await get_proofs(db=self.wallet.db, melt_id=invoice.id)
        if not proofs:
            return "not fount"
        proofs_states = await self.wallet.check_proof_state(proofs)
        if (
            not proofs_states
            or not proofs_states.spendable
            or not proofs_states.pending
        ):
            return "not fount"

        if all(proofs_states.spendable) and all(proofs_states.pending):
            return "pending"
        if not any(proofs_states.spendable) and not any(proofs_states.pending):
            return "paid"
        if all(proofs_states.spendable) and not any(proofs_states.pending):
            return "failed"
        return "undefined state"

    async def get_balance(self):
        """Get lightning balance

        Returns:
            int: balance in satoshis
        """
        return self.wallet.available_balance
