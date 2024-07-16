from typing import List, Optional, Union

from loguru import logger

from ...core.base import (
    MeltQuote,
    MeltQuoteState,
    MintQuote,
    MintQuoteState,
    Proof,
    ProofSpentState,
    ProofState,
)
from ...core.db import Connection, Database
from ...core.errors import (
    TransactionError,
)
from ..crud import LedgerCrud
from ..events.events import LedgerEventManager


class DbWriteHelper:
    db: Database
    crud: LedgerCrud
    events: LedgerEventManager

    def __init__(
        self, db: Database, crud: LedgerCrud, events: LedgerEventManager
    ) -> None:
        self.db = db
        self.crud = crud
        self.events = events


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
