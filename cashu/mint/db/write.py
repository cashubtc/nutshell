from typing import Dict, List, Optional, Union

from loguru import logger

from ...core.base import (
    MeltQuote,
    MeltQuoteState,
    MintKeyset,
    MintQuote,
    MintQuoteState,
    Proof,
    ProofSpentState,
    ProofState,
)
from ...core.db import Connection, Database
from ...core.errors import (
    ProofsArePendingError,
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
        self,
        proofs: List[Proof],
        keysets: Dict[str, MintKeyset],
        quote_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> None:
        """
        Method to check if proofs are already spent. If they are not spent, we check if they are pending.
        If they are not pending, we set them as pending.
        Args:
            proofs (List[Proof]): Proofs to add to pending table.
            keysets (Dict[str, MintKeyset]): Keysets of the mint (needed to update keyset balances)
            quote_id (Optional[str]): Melt quote ID. If it is not set, we assume the pending tokens to be from a swap.
        Raises:
            TransactionError: If any one of the proofs is already spent or pending.
        """
        # first we check whether these proofs are pending already
        try:
            logger.trace("_verify_spent_proofs_and_set_pending acquiring lock")
            async with self.db.get_connection(
                conn=conn,
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
                    await self.crud.bump_keyset_balance(
                        db=self.db,
                        keyset=keysets[p.id],
                        amount=-p.amount,
                        conn=conn,
                    )
                    logger.trace(f"crud: set proof {p.Y} as PENDING")
            logger.trace("_verify_spent_proofs_and_set_pending released lock")
        except Exception as e:
            logger.error(f"Failed to set proofs pending: {e}")
            raise e
        for p in proofs:
            await self.events.submit(ProofState(Y=p.Y, state=ProofSpentState.pending))

    async def _unset_proofs_pending(
        self,
        proofs: List[Proof],
        keysets: Dict[str, MintKeyset],
        spent=True,
        conn: Optional[Connection] = None,
    ) -> None:
        """Deletes proofs from pending table.

        Args:
            proofs (List[Proof]): Proofs to delete.
            keysets (Dict[str, MintKeyset]): Keysets of the mint (needed to update keyset balances)
            spent (bool): Whether the proofs have been spent or not. Defaults to True.
                This should be False if the proofs were NOT invalidated before calling this function.
                It is used to emit the unspent state for the proofs (otherwise the spent state is emitted
                by the _invalidate_proofs function when the proofs are spent).
            conn (Optional[Connection]): Connection to use. If not set, a new connection will be created.
        """
        async with self.db.get_connection(conn) as conn:
            for p in proofs:
                logger.trace(f"crud: un-setting proof {p.Y} as PENDING")
                await self.crud.unset_proof_pending(proof=p, db=self.db, conn=conn)
                await self.crud.bump_keyset_balance(
                    db=self.db,
                    keyset=keysets[p.id],
                    amount=p.amount,
                    conn=conn,
                )

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
        if pending_proofs:
            raise ProofsArePendingError()

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
            if quote.pending:
                raise TransactionError("Mint quote already pending.")
            if not quote.paid:
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
            # set the quote to previous state
            quote.state = state
            logger.trace(f"crud: setting quote {quote_id} as {state.value}")
            await self.crud.update_mint_quote(quote=quote, db=self.db, conn=conn)
        if quote is None:
            raise TransactionError("Mint quote not found.")

        await self.events.submit(quote)
        return quote

    async def _set_melt_quote_pending(
        self, quote: MeltQuote, conn: Optional[Connection] = None
    ) -> MeltQuote:
        """Sets the melt quote as pending.

        Args:
            quote (MeltQuote): Melt quote to set as pending.
        """
        quote_copy = quote.model_copy()
        if not quote.checking_id:
            raise TransactionError("Melt quote doesn't have checking ID.")
        async with self.db.get_connection(
            conn=conn,
            lock_table="melt_quotes",
            lock_select_statement=f"checking_id='{quote.checking_id}'",
        ) as conn:
            # get all melt quotes with same checking_id from db and check if there is one already pending or paid
            quotes_db = await self.crud.get_melt_quotes_by_checking_id(
                checking_id=quote.checking_id, db=self.db, conn=conn
            )
            if len(quotes_db) == 0:
                raise TransactionError("Melt quote not found.")
            if any(
                [
                    quote.state in [MeltQuoteState.pending, MeltQuoteState.paid]
                    for quote in quotes_db
                ]
            ):
                raise TransactionError("Melt quote already paid or pending.")
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
        Raises:
            TransactionError: If the melt quote is not found or not pending.
        """
        quote_copy = quote.model_copy()
        async with self.db.get_connection(lock_table="melt_quotes") as conn:
            # get melt quote from db and check if it is pending
            quote_db = await self.crud.get_melt_quote(
                quote_id=quote.quote, db=self.db, conn=conn
            )
            if not quote_db:
                raise TransactionError("Melt quote not found.")
            if quote_db.state != MeltQuoteState.pending:
                raise TransactionError("Melt quote not pending.")
            # set the quote to previous state
            quote_copy.state = state

            # unset outputs
            quote_copy.outputs = None
            await self.crud.update_melt_quote(quote=quote_copy, db=self.db, conn=conn)

        await self.events.submit(quote_copy)
        return quote_copy

    async def _update_mint_quote_state(self, quote_id: str, state: MintQuoteState):
        async with self.db.get_connection(lock_table="mint_quotes") as conn:
            mint_quote = await self.crud.get_mint_quote(
                quote_id=quote_id, db=self.db, conn=conn
            )
            if not mint_quote:
                raise TransactionError("Mint quote not found.")
            mint_quote.state = state
            await self.crud.update_mint_quote(quote=mint_quote, db=self.db, conn=conn)

    async def _update_melt_quote_state(
        self,
        quote_id: str,
        state: MeltQuoteState,
    ):
        """Updates the state of a melt quote.

        Args:
            quote_id (str): ID of the melt quote to update.
            state (MeltQuoteState): New state of the melt quote.

        Raises:
            TransactionError: If the melt quote is not found.
        """
        async with self.db.get_connection(lock_table="melt_quotes") as conn:
            melt_quote = await self.crud.get_melt_quote(
                quote_id=quote_id, db=self.db, conn=conn
            )
            if not melt_quote:
                raise TransactionError("Melt quote not found.")
            melt_quote.state = state
            await self.crud.update_melt_quote(quote=melt_quote, db=self.db, conn=conn)

    async def _store_melt_quote(self, quote: MeltQuote):
        """Stores a melt quote in the database. Will fail if a quote with the same checking_id is already pending or paid.

        Args:
            quote (MeltQuote): Melt quote to store.

        Raises:
            TransactionError: If a quote with the same checking_id is already pending or paid.
        """
        async with self.db.get_connection(
            lock_table="melt_quotes",
            lock_select_statement=f"checking_id='{quote.checking_id}'",
        ) as conn:
            # get all melt quotes with same checking_id from db and check if there is one already pending or paid
            quotes_db = await self.crud.get_melt_quotes_by_checking_id(
                checking_id=quote.checking_id, db=self.db, conn=conn
            )
            if any(
                [
                    quote.state in [MeltQuoteState.pending, MeltQuoteState.paid]
                    for quote in quotes_db
                ]
            ):
                raise TransactionError("Melt quote already paid or pending.")

            # store the melt quote
            await self.crud.store_melt_quote(quote=quote, db=self.db, conn=conn)
