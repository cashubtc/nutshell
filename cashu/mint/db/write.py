import json
from typing import Dict, List, Optional, Tuple, Union

from loguru import logger

from ...core.base import (
    DiscreetLogContract,
    DlcBadInput,
    DlcFundingAck,
    DlcFundingError,
    DlcPayout,
    DlcPayoutForm,
    DlcSettlement,
    DlcSettlementAck,
    DlcSettlementError,
    MeltQuote,
    MeltQuoteState,
    MintKeyset,
    MintQuote,
    MintQuoteState,
    Proof,
    ProofSpentState,
    ProofState,
    Unit,
)
from ...core.db import Connection, Database
from ...core.errors import (
    CashuError,
    DlcAlreadyRegisteredError,
    DlcPayoutFail,
    DlcSettlementFail,
    TokenAlreadySpentError,
    TransactionError,
)
from ..crud import LedgerCrud
from ..events.events import LedgerEventManager
from .read import DbReadHelper


class DbWriteHelper:
    db: Database
    crud: LedgerCrud
    events: LedgerEventManager
    db_read: DbReadHelper

    def __init__(
        self,
        db: Database,
        crud: LedgerCrud,
        events: LedgerEventManager,
        db_read: DbReadHelper,
    ) -> None:
        self.db = db
        self.crud = crud
        self.events = events
        self.db_read = db_read

    async def _verify_spent_proofs_and_set_pending(
        self, proofs: List[Proof], quote_id: Optional[str] = None
    ) -> None:
        """
        Method to check if proofs are already spent. If they are not spent, we check if they are pending.
        If they are not pending, we set them as pending.
        Args:
            proofs (List[Proof]): Proofs to add to pending table.
            quote_id (Optional[str]): Melt quote ID. If it is not set, we assume the pending tokens to be from a swap.
        Raises:
            TransactionError: If any one of the proofs is already spent or pending.
        """
        # first we check whether these proofs are pending already
        try:
            logger.trace("_verify_spent_proofs_and_set_pending acquiring lock")
            async with self.db.get_connection(
                lock_table="proofs_pending",
                lock_timeout=1,
            ) as conn:
                logger.trace("checking whether proofs are already spent")
                await self.db_read._verify_proofs_spendable(proofs, conn)
                logger.trace("checking whether proofs are already pending")
                await self._validate_proofs_pending(proofs, conn)
                for p in proofs:
                    logger.trace(f"crud: setting proof {p.Y} as PENDING")
                    await self.crud.set_proof_pending(
                        proof=p, db=self.db, quote_id=quote_id, conn=conn
                    )
                    logger.trace(f"crud: set proof {p.Y} as PENDING")
            logger.trace("_verify_spent_proofs_and_set_pending released lock")
        except Exception as e:
            logger.error(f"Failed to set proofs pending: {e}")
            raise e
        for p in proofs:
            await self.events.submit(ProofState(Y=p.Y, state=ProofSpentState.pending))

    async def _unset_proofs_pending(self, proofs: List[Proof], spent=True) -> None:
        """Deletes proofs from pending table.

        Args:
            proofs (List[Proof]): Proofs to delete.
            spent (bool): Whether the proofs have been spent or not. Defaults to True.
                This should be False if the proofs were NOT invalidated before calling this function.
                It is used to emit the unspent state for the proofs (otherwise the spent state is emitted
                by the _invalidate_proofs function when the proofs are spent).
        """
        async with self.db.get_connection() as conn:
            for p in proofs:
                logger.trace(f"crud: un-setting proof {p.Y} as PENDING")
                await self.crud.unset_proof_pending(proof=p, db=self.db, conn=conn)

        if not spent:
            for p in proofs:
                await self.events.submit(
                    ProofState(Y=p.Y, state=ProofSpentState.unspent)
                )

    async def _validate_proofs_pending(
        self, proofs: List[Proof], conn: Optional[Connection] = None
    ) -> None:
        """Checks if any of the provided proofs is in the pending proofs table.

        Args:
            proofs (List[Proof]): Proofs to check.

        Raises:
            Exception: At least one of the proofs is in the pending table.
        """
        logger.trace("crud: validating proofs pending")
        pending_proofs = await self.crud.get_proofs_pending(
            Ys=[p.Y for p in proofs], db=self.db, conn=conn
        )
        if not (len(pending_proofs) == 0):
            raise TransactionError("proofs are pending.")

    async def _set_mint_quote_pending(self, quote_id: str) -> MintQuote:
        """Sets the mint quote as pending.

        Args:
            quote (MintQuote): Mint quote to set as pending.
        """
        quote: Union[MintQuote, None] = None
        async with self.db.get_connection(
            lock_table="mint_quotes", lock_select_statement=f"quote='{quote_id}'"
        ) as conn:
            # get mint quote from db and check if it is already pending
            quote = await self.crud.get_mint_quote(
                quote_id=quote_id, db=self.db, conn=conn
            )
            if not quote:
                raise TransactionError("Mint quote not found.")
            if quote.state == MintQuoteState.pending:
                raise TransactionError("Mint quote already pending.")
            if not quote.state == MintQuoteState.paid:
                raise TransactionError("Mint quote is not paid yet.")
            # set the quote as pending
            quote.state = MintQuoteState.pending
            logger.trace(f"crud: setting quote {quote_id} as PENDING")
            await self.crud.update_mint_quote(quote=quote, db=self.db, conn=conn)
        if quote is None:
            raise TransactionError("Mint quote not found.")
        return quote

    async def _unset_mint_quote_pending(
        self, quote_id: str, state: MintQuoteState
    ) -> MintQuote:
        """Unsets the mint quote as pending.

        Args:
            quote (MintQuote): Mint quote to unset as pending.
            state (MintQuoteState): New state of the mint quote.
        """
        quote: Union[MintQuote, None] = None
        async with self.db.get_connection(lock_table="mint_quotes") as conn:
            # get mint quote from db and check if it is pending
            quote = await self.crud.get_mint_quote(
                quote_id=quote_id, db=self.db, conn=conn
            )
            if not quote:
                raise TransactionError("Mint quote not found.")
            if quote.state != MintQuoteState.pending:
                raise TransactionError(
                    f"Mint quote not pending: {quote.state.value}. Cannot set as {state.value}."
                )
            # set the quote as pending
            quote.state = state
            logger.trace(f"crud: setting quote {quote_id} as {state.value}")
            await self.crud.update_mint_quote(quote=quote, db=self.db, conn=conn)
        if quote is None:
            raise TransactionError("Mint quote not found.")

        await self.events.submit(quote)
        return quote

    async def _set_melt_quote_pending(self, quote: MeltQuote) -> MeltQuote:
        """Sets the melt quote as pending.

        Args:
            quote (MeltQuote): Melt quote to set as pending.
        """
        quote_copy = quote.copy()
        async with self.db.get_connection(
            lock_table="melt_quotes",
            lock_select_statement=f"checking_id='{quote.checking_id}'",
        ) as conn:
            # get melt quote from db and check if it is already pending
            quote_db = await self.crud.get_melt_quote(
                checking_id=quote.checking_id, db=self.db, conn=conn
            )
            if not quote_db:
                raise TransactionError("Melt quote not found.")
            if quote_db.state == MeltQuoteState.pending:
                raise TransactionError("Melt quote already pending.")
            # set the quote as pending
            quote_copy.state = MeltQuoteState.pending
            await self.crud.update_melt_quote(quote=quote_copy, db=self.db, conn=conn)

        await self.events.submit(quote_copy)
        return quote_copy

    async def _unset_melt_quote_pending(
        self, quote: MeltQuote, state: MeltQuoteState
    ) -> MeltQuote:
        """Unsets the melt quote as pending.

        Args:
            quote (MeltQuote): Melt quote to unset as pending.
            state (MeltQuoteState): New state of the melt quote.
        """
        quote_copy = quote.copy()
        async with self.db.get_connection(lock_table="melt_quotes") as conn:
            # get melt quote from db and check if it is pending
            quote_db = await self.crud.get_melt_quote(
                checking_id=quote.checking_id, db=self.db, conn=conn
            )
            if not quote_db:
                raise TransactionError("Melt quote not found.")
            if quote_db.state != MeltQuoteState.pending:
                raise TransactionError("Melt quote not pending.")
            # set the quote as pending
            quote_copy.state = state
            await self.crud.update_melt_quote(quote=quote_copy, db=self.db, conn=conn)

        await self.events.submit(quote_copy)
        return quote_copy

    async def _verify_proofs_and_dlc_registrations(
        self,
        registrations: List[Tuple[DiscreetLogContract, DlcFundingAck]],
    ) -> Tuple[List[Tuple[DiscreetLogContract, DlcFundingAck]], List[DlcFundingError]]:
        """
        Method to check if proofs are already spent or registrations already registered. If they are not, we
        set them as spent and registered respectively
        Args:
            registrations (List[Tuple[DiscreetLogContract, DlcFundingAck]]): List of registrations.
        Returns:
            List[Tuple[DiscreetLogContract, DlcFundingAck]]: a list of registered DLCs
            List[DlcFundingError]: a list of errors
        """
        checked: List[Tuple[DiscreetLogContract, DlcFundingAck]] = []
        registered: List[Tuple[DiscreetLogContract, DlcFundingAck]] = []
        errors: List[DlcFundingError]= []
        if len(registrations) == 0:
            logger.trace("Received 0 registrations")
            return [], []
        logger.trace("_verify_proofs_and_dlc_registrations acquiring lock")
        async with self.db.get_connection(lock_table="proofs_used") as conn:
            for registration in registrations:
                reg = registration[0]
                logger.trace("checking whether proofs are already spent")
                try:
                    assert reg.inputs
                    await self.db_read._verify_proofs_spendable(reg.inputs, conn)
                    await self.db_read._verify_dlc_registrable(reg.dlc_root, conn)
                    checked.append(registration)
                except (TokenAlreadySpentError, DlcAlreadyRegisteredError) as e:
                    logger.trace(f"Proofs already spent for registration {reg.dlc_root}")
                    errors.append(DlcFundingError(
                        dlc_root=reg.dlc_root,
                        bad_inputs=[DlcBadInput(
                            index=-1,
                            detail=e.detail
                        )]
                    ))

            for registration in checked:
                reg = registration[0]
                assert reg.inputs
                try:
                    for p in reg.inputs:
                        logger.trace(f"Invalidating proof {p.Y}")
                        await self.crud.invalidate_proof(
                            proof=p, db=self.db, conn=conn
                        )

                    logger.trace(f"Registering DLC {reg.dlc_root}")
                    await self.crud.store_dlc(reg, self.db, conn)
                    registered.append(registration)
                except Exception as e:
                    logger.trace(f"Failed to register {reg.dlc_root}: {str(e)}")
                    errors.append(DlcFundingError(
                        dlc_root=reg.dlc_root,
                        bad_inputs=[DlcBadInput(
                            index=-1,
                            detail=str(e)
                        )]
                    ))
        logger.trace("_verify_proofs_and_dlc_registrations lock released")
        return (registered, errors)

    async def _settle_dlc(
        self,
        settlements: List[DlcSettlement]
    ) -> Tuple[List[DlcSettlementAck], List[DlcSettlementError]]:
        settled = []
        errors = []
        async with self.db.get_connection(lock_table="dlc") as conn:
            for settlement in settlements:
                try:
                    # We verify the dlc_root is in the DB
                    dlc = await self.crud.get_registered_dlc(settlement.dlc_root, self.db, conn)
                    if dlc is None:
                        raise DlcSettlementFail(detail="No DLC with this root hash")
                    if dlc.settled is True:
                        raise DlcSettlementFail(detail="DLC already settled")
                    assert settlement.outcome

                    # Calculate debts map
                    weights = json.loads(settlement.outcome.P)
                    weight_sum = sum(weights.values())
                    debts = dict(((pubkey, dlc.funding_amount * weight // weight_sum) for pubkey, weight in weights.items()))
                    
                    # Update DLC in the database
                    await self.crud.set_dlc_settled_and_debts(settlement.dlc_root, json.dumps(debts), self.db, conn)

                    settled.append(DlcSettlementAck(dlc_root=settlement.dlc_root))
                except (CashuError, Exception) as e:
                    errors.append(DlcSettlementError(
                        dlc_root=settlement.dlc_root,
                        details=f"error with the DB: {str(e)}"
                    ))
        return (settled, errors)


    async def _verify_and_update_dlc_payouts(
        self,
        payouts: List[DlcPayoutForm],
        keysets: Dict[str, MintKeyset],
    ) -> Tuple[List[DlcPayoutForm], List[DlcPayout]]:
        """
        We perform the following checks inside the db lock:
           * Verify dlc_root exists and is settled
           * Verify the debts map contains the referenced public key
           * Verify every blind message from the payout request has keyset ID that
                matches the DLC in its funding unit.
           * Verify the sum of amounts in blind messages is <= than the respective payout amount
        """
        verified = []
        errors = []
        async with self.db.get_connection(lock_table="dlc") as conn:
            for payout in payouts:
                try:
                    dlc = await self.crud.get_registered_dlc(payout.dlc_root, self.db, conn)
                    if dlc is None:
                        raise DlcPayoutFail(detail="No DLC with this root hash")
                    if not dlc.settled:
                        raise DlcPayoutFail(detail="DLC is not settled")
                    if not all([keysets[b.id].unit == Unit[dlc.unit] for b in payout.outputs]):
                        raise DlcPayoutFail(detail="DLC funding unit does not match blind messages unit")
                    if dlc.debts is None:
                        raise DlcPayoutFail(detail="Debts map is empty")
                    if payout.pubkey not in dlc.debts:
                        raise DlcPayoutFail(detail=f"{payout.pubkey}: no such public key in debts map")
                    
                    # We have already checked the amounts before, so we just sum them
                    blind_messages_amount = sum([b.amount for b in payout.outputs])
                    eligible_amount = dlc.debts[payout.pubkey]
                    
                    # Verify the amount of the blind messages is LEQ than the eligible amount
                    if blind_messages_amount != eligible_amount:
                        raise DlcPayoutFail(detail=f"amount requested ({blind_messages_amount}) is bigger than eligible amount ({eligible_amount})")
                    
                    # Remove the payout from the map
                    del dlc.debts[payout.pubkey]

                    # Update the database
                    await self.crud.set_dlc_settled_and_debts(dlc.dlc_root, json.dumps(dlc.debts), self.db, conn)

                    # Append payout to verified results
                    verified.append(payout)
                except (CashuError, Exception) as e:
                    errors.append(DlcPayout(
                        dlc_root=payout.dlc_root,
                        detail=f"DB error: {str(e)}"
                    ))
        return (verified, errors)
            