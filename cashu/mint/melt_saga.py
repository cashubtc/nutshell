import json
import time
import uuid
from typing import List, Optional, Tuple, TYPE_CHECKING

from loguru import logger

from ..core.base import (
    BlindedMessage,
    BlindedSignature,
    MeltQuote,
    MeltQuoteState,
    MeltSagaState,
    Proof,
    ProofSpentState,
    Saga,
    Unit,
)
from ..core.db import Database
from ..core.errors import LightningPaymentFailedError, TransactionError
from ..lightning.base import PaymentResult, PaymentResponse

if TYPE_CHECKING:
    from .ledger import Ledger


class MeltSaga:
    def __init__(self, ledger: "Ledger", operation_id: Optional[str] = None):
        self.ledger = ledger
        self.operation_id = operation_id or str(uuid.uuid4())
        self.state = MeltSagaState.initial
        self.quote_id: Optional[str] = None
        self.proofs: List[Proof] = []
        self.change_outputs: List[BlindedMessage] = []

    async def setup_melt(
        self,
        proofs: List[Proof],
        quote: MeltQuote,
        outputs: Optional[List[BlindedMessage]] = None,
    ) -> MeltSagaState:
        """
        Step 1: Setup melt operation.
        - Verify inputs and balance.
        - Mark proofs as PENDING.
        - Mark quote as PENDING.
        - Store change outputs (blinded messages).
        - Persist saga state SetupComplete.
        """
        self.quote_id = quote.quote
        self.proofs = proofs
        self.change_outputs = outputs or []

        # 1. Verify inputs (balance check, signatures, etc.) - done by caller usually, but we need to ensure consistency
        # Assuming validations are done before calling this in Ledger.melt, but we need to do DB updates here.

        # 2. DB Transaction (Atomic)
        async with self.ledger.db.get_connection() as conn:
            # Mark proofs as PENDING
            await self.ledger.db_write._verify_spent_proofs_and_set_pending(
                proofs, keysets=self.ledger.keysets, quote_id=quote.quote, conn=conn
            )
            
            # Set quote as PENDING
            previous_state = quote.state
            quote.state = MeltQuoteState.pending
            await self.ledger.crud.update_melt_quote(quote=quote, db=self.ledger.db, conn=conn)
            await self.ledger.events.submit(quote)

            # Store change outputs if present
            if self.change_outputs:
                await self.ledger._store_blinded_messages(
                    self.change_outputs, melt_id=quote.quote, conn=conn
                )

            # Persist Saga State
            saga_data = {
                "quote_id": self.quote_id,
                "proofs": [p.to_dict(include_dleq=True) for p in proofs],
                "outputs": [o.model_dump() for o in self.change_outputs],
                "previous_quote_state": previous_state.value
            }
            
            saga = Saga(
                operation_id=self.operation_id,
                state=MeltSagaState.setup_complete,
                data=json.dumps(saga_data),
                created_at=int(time.time())
            )
            await self.ledger.crud.store_saga_state(db=self.ledger.db, saga=saga, conn=conn)
            
        self.state = MeltSagaState.setup_complete
        logger.debug(f"Melt Saga {self.operation_id}: Setup complete.")
        return self.state

    async def attempt_payment(self) -> PaymentResponse:
        """
        Step 2: Attempt payment.
        - Update saga state to PaymentAttempted.
        - Call LN backend.
        - Transition state based on result.
        """
        if self.state != MeltSagaState.setup_complete:
             # If we are recovering, we might be in PaymentAttempted already
             if self.state != MeltSagaState.payment_attempted:
                raise TransactionError(f"Invalid state for payment: {self.state}")

        # Update state to PaymentAttempted BEFORE calling backend (Write-Ahead Log)
        if self.state != MeltSagaState.payment_attempted:
            self.state = MeltSagaState.payment_attempted
            saga = Saga(
                operation_id=self.operation_id,
                state=self.state,
                data=json.dumps({
                    "quote_id": self.quote_id,
                    "proofs": [p.to_dict(include_dleq=True) for p in self.proofs],
                    "outputs": [o.model_dump() for o in self.change_outputs],
                }),
                created_at=int(time.time())
            )
            await self.ledger.crud.store_saga_state(db=self.ledger.db, saga=saga)

        # Get quote to have full details for payment
        quote = await self.ledger.get_melt_quote(self.quote_id)
        unit, method = self.ledger._verify_and_get_unit_method(quote.unit, quote.method)

        logger.debug(f"Melt Saga {self.operation_id}: Attempting payment for {quote.request}")
        
        try:
            payment = await self.ledger.backends[method][unit].pay_invoice(
                quote, quote.fee_reserve * 1000
            )
        except Exception as e:
            logger.error(f"Exception during pay_invoice: {e}")
            # If we get an exception, we treat it as UNKNOWN/FAILED depending on the error. 
            # But the caller of this method (Ledger.melt) will catch it.
            # We re-raise so the caller can trigger compensation.
            raise e

        if payment.result == PaymentResult.SETTLED:
            self.state = MeltSagaState.payment_confirmed
            # We don't persist PaymentConfirmed because we go straight to finalize
            # If we crash here, we are still in PaymentAttempted, which is fine (recovery will check status)
            return payment
        elif payment.result in [PaymentResult.FAILED, PaymentResult.UNKNOWN]:
             # Raise error to trigger compensation in caller
             raise LightningPaymentFailedError(f"Payment failed: {payment.result}")
        
        return payment

    async def finalize(self, payment: PaymentResponse) -> MeltQuote:
        """
        Step 3: Finalize melt.
        - Mark proofs as SPENT.
        - Update quote to PAID.
        - Sign change outputs.
        - Delete saga state.
        """
        logger.debug(f"Melt Saga {self.operation_id}: Finalizing...")
        
        async with self.ledger.db.get_connection() as conn:
            # 1. Invalidate proofs (Mark as SPENT)
            await self.ledger._invalidate_proofs(proofs=self.proofs, quote_id=self.quote_id, conn=conn)
            # Remove from pending
            await self.ledger.db_write._unset_proofs_pending(self.proofs, keysets=self.ledger.keysets, conn=conn)

            # 2. Update Quote
            quote = await self.ledger.get_melt_quote(self.quote_id)
            quote.state = MeltQuoteState.paid
            quote.paid_time = int(time.time())
            if payment.preimage:
                quote.payment_preimage = payment.preimage
            if payment.fee:
                unit, _ = self.ledger._verify_and_get_unit_method(quote.unit, quote.method)
                quote.fee_paid = payment.fee.to(to_unit=unit, round="up").amount
            
            # Calculate change
            return_promises = []
            if self.change_outputs:
                # logic from ledger.melt
                total_provided = sum([p.amount for p in self.proofs])
                input_fees = self.ledger.get_fees_for_proofs(self.proofs)
                fee_reserve_provided = total_provided - quote.amount - input_fees
                
                return_promises = await self.ledger._generate_change_promises(
                    fee_provided=fee_reserve_provided,
                    fee_paid=quote.fee_paid,
                    outputs=self.change_outputs,
                    melt_id=quote.quote,
                    keyset=self.ledger.keysets[self.change_outputs[0].id],
                )
                quote.change = return_promises

            await self.ledger.crud.update_melt_quote(quote=quote, db=self.ledger.db, conn=conn)
            await self.ledger.events.submit(quote)

            # 3. Delete Saga State
            await self.ledger.crud.delete_saga_state(db=self.ledger.db, operation_id=self.operation_id, conn=conn)

        logger.debug(f"Melt Saga {self.operation_id}: Finalized successfully.")
        return quote

    async def compensate(self):
        """
        Rollback setup.
        - Unset pending proofs.
        - Reset quote to UNPAID.
        - Remove blinded messages.
        - Delete saga state.
        """
        logger.warning(f"Melt Saga {self.operation_id}: Compensating...")
        
        async with self.ledger.db.get_connection() as conn:
            # 1. Unset pending proofs
            await self.ledger.db_write._unset_proofs_pending(
                self.proofs, keysets=self.ledger.keysets, conn=conn
            )
            
            # 2. Reset Quote to UNPAID
            quote = await self.ledger.get_melt_quote(self.quote_id)
            quote.state = MeltQuoteState.unpaid
            await self.ledger.crud.update_melt_quote(quote=quote, db=self.ledger.db, conn=conn)
            await self.ledger.events.submit(quote)

            # 3. Remove blinded messages
            await self.ledger.crud.delete_blinded_messages_melt_id(
                melt_id=self.quote_id, db=self.ledger.db, conn=conn
            )

            # 4. Delete Saga State
            await self.ledger.crud.delete_saga_state(db=self.ledger.db, operation_id=self.operation_id, conn=conn)
            
        logger.debug(f"Melt Saga {self.operation_id}: Compensation complete.")

    @classmethod
    async def load_from_db(cls, ledger: "Ledger", saga_data: Saga) -> "MeltSaga":
        saga = cls(ledger, operation_id=saga_data.operation_id)
        saga.state = saga_data.state
        data = json.loads(saga_data.data)
        saga.quote_id = data["quote_id"]
        saga.proofs = [Proof.from_dict(p) for p in data["proofs"]]
        if "outputs" in data:
            saga.change_outputs = [BlindedMessage(**o) for o in data["outputs"]]
        return saga
