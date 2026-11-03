import secrets
import time
import uuid
from typing import Callable, Dict, List, Optional, Union

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
from ...core.db import Connection, Database, LockOptions
from ...core.errors import (
    InvoiceAlreadyPaidError,
    ProofsArePendingError,
    QuoteAlreadyIssuedError,
    QuoteNotPaidError,
    QuotePendingError,
    TransactionError,
)
from ...core.settings import settings
from ..crud import LedgerCrud
from ..events.events import LedgerEventManager
from .read import DbReadHelper


def _uuid7() -> str:
    """Time-ordered UUID (RFC 9562, version 7) using the stdlib only."""
    timestamp_ms = time.time_ns() // 1_000_000
    value = (
        (timestamp_ms & 0xFFFFFFFFFFFF) << 80
        | 0x7 << 76
        | secrets.randbits(12) << 64
        | 0x2 << 62
        | secrets.randbits(62)
    )
    return str(uuid.UUID(int=value))


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

    @staticmethod
    def _set_mint_quote_state(quote: MintQuote, state: MintQuoteState) -> None:
        """Set a mint quote state and its corresponding timestamps."""
        now = int(time.time())
        quote.state = state
        quote.updated_at = now
        if state == MintQuoteState.issued and not quote.issued_time:
            quote.issued_time = now

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
            conn (Optional[Connection]): Connection to use. If not set, a new connection will be created.
        Raises:
            TransactionError: If any one of the proofs is already spent or pending.
        """
        # first we check whether these proofs are pending already
        try:
            logger.trace("_verify_spent_proofs_and_set_pending acquiring lock")
            async with self.db.get_connection(
                locks=[LockOptions(table="proofs_pending", timeout=1)],
                conn=conn,
            ) as conn:
                logger.trace("checking whether proofs are already spent")
                await self.db_read._verify_proofs_spendable(proofs, conn)
                logger.trace("checking whether proofs are already pending")
                await self._validate_proofs_pending(proofs, conn)

                amounts_by_keyset: Dict[str, int] = {}
                for proof in proofs:
                    amounts_by_keyset[proof.id] = (
                        amounts_by_keyset.get(proof.id, 0) + proof.amount
                    )

                for keyset_id, amount in sorted(amounts_by_keyset.items()):
                    debited = await self.crud.try_debit_keyset_balance(
                        db=self.db,
                        keyset=keysets[keyset_id],
                        amount=amount,
                        conn=conn,
                    )
                    if not debited:
                        raise TransactionError(
                            "keyset balance is insufficient for redemption"
                        )

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

    async def _unset_proofs_pending(
        self,
        proofs: List[Proof],
        keysets: Dict[str, MintKeyset],
        spent=True,
        conn: Optional[Connection] = None,
        emit_events: bool = True,
    ) -> None:
        """Deletes proofs from pending table.

        Args:
            proofs (List[Proof]): Proofs to delete.
            keysets (Dict[str, MintKeyset]): Keysets of the mint (needed to update keyset balances)
            spent (bool): Whether the proofs have been spent or not. Defaults to True.
                This should be False if the proofs were NOT invalidated before calling this function.
                It is used to emit the unspent state for the proofs (otherwise the spent state is emitted
                by the invalidate_proofs function when the proofs are spent).
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

        if not spent and emit_events:
            for p in proofs:
                await self.events.submit(
                    ProofState(Y=p.Y, state=ProofSpentState.unspent)
                )

    async def finalize_pending_proofs(
        self,
        proofs: List[Proof],
        keysets: Dict[str, MintKeyset],
        quote_id: Optional[str] = None,
        keyset_fees: Optional[Dict[str, int]] = None,
        conn: Optional[Connection] = None,
        emit_events: bool = True,
    ) -> None:
        """Atomically convert pending proofs into spent proofs.

        Pending proofs have already reserved their keyset balance. Releasing that
        reservation before invalidating them lets the final checked debit represent
        the single durable spend.
        """
        async with self.db.get_connection(conn) as conn:
            await self._unset_proofs_pending(proofs, keysets, spent=True, conn=conn)
            await self.invalidate_proofs(
                proofs=proofs,
                keysets=keysets,
                quote_id=quote_id,
                keyset_fees=keyset_fees,
                conn=conn,
                emit_events=emit_events,
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
            locks=[
                LockOptions(
                    table="mint_quotes",
                    select_statement="quote = :quote",
                    parameters={"quote": quote_id},
                )
            ],
        ) as conn:
            # get mint quote from db and check if it is already pending
            quote = await self.crud.get_mint_quote(
                quote_id=quote_id, db=self.db, conn=conn
            )
            if not quote:
                raise TransactionError("Mint quote not found.")
            if quote.pending:
                raise QuotePendingError("Mint quote already pending.")
            if quote.issued:
                raise QuoteAlreadyIssuedError(
                    f"Mint quote {quote_id} is already issued."
                )
            if not quote.paid:
                raise QuoteNotPaidError("Mint quote is not paid yet.")
            # set the quote as pending
            self._set_mint_quote_state(quote, MintQuoteState.pending)
            logger.trace(f"crud: setting quote {quote_id} as PENDING")
            await self.crud.update_mint_quote(quote=quote, db=self.db, conn=conn)
        if quote is None:
            raise TransactionError("Mint quote not found.")
        return quote

    async def _set_mint_quotes_pending(self, quote_ids: List[str]) -> List[MintQuote]:
        """Sets multiple mint quotes as pending.

        Args:
            quote_ids (List[str]): List of mint quote IDs to set as pending.
        """
        if not quote_ids:
            return []

        quotes: List[MintQuote] = []
        # Sort quote_ids to ensure consistent locking order
        sorted_quote_ids = sorted(quote_ids)
        lock_parameters = {f"quote_{i}": q for i, q in enumerate(sorted_quote_ids)}
        lock_select_statement = (
            "quote IN ("
            + ", ".join([f":quote_{i}" for i in range(len(sorted_quote_ids))])
            + ")"
        )

        async with self.db.get_connection(
            locks=[
                LockOptions(
                    table="mint_quotes",
                    select_statement=lock_select_statement,
                    parameters=lock_parameters,
                )
            ],
        ) as conn:
            for quote_id in quote_ids:
                quote = await self.crud.get_mint_quote(
                    quote_id=quote_id, db=self.db, conn=conn
                )
                if not quote:
                    raise TransactionError(f"Mint quote {quote_id} not found.")
                if quote.pending:
                    raise QuotePendingError(f"Mint quote {quote_id} already pending.")
                if quote.issued:
                    raise QuoteAlreadyIssuedError(
                        f"Mint quote {quote_id} is already issued."
                    )
                if not quote.paid:
                    raise QuoteNotPaidError(f"Mint quote {quote_id} is not paid yet.")

                # set the quote as pending
                self._set_mint_quote_state(quote, MintQuoteState.pending)
                logger.trace(f"crud: setting quote {quote_id} as PENDING")
                await self.crud.update_mint_quote(quote=quote, db=self.db, conn=conn)
                quotes.append(quote)
        return quotes

    async def _unset_mint_quote_pending(
        self, quote_id: str, state: MintQuoteState
    ) -> MintQuote:
        """Unsets the mint quote as pending.

        Args:
            quote (MintQuote): Mint quote to unset as pending.
            state (MintQuoteState): New state of the mint quote.
        """
        quote: Union[MintQuote, None] = None
        async with self.db.get_connection(
            locks=[
                LockOptions(
                    table="mint_quotes",
                    select_statement="quote = :quote",
                    parameters={"quote": quote_id},
                )
            ],
        ) as conn:
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
            self._set_mint_quote_state(quote, state)
            logger.trace(f"crud: setting quote {quote_id} as {state.value}")
            await self.crud.update_mint_quote(quote=quote, db=self.db, conn=conn)
        if quote is None:
            raise TransactionError("Mint quote not found.")

        await self.events.submit(quote)
        return quote

    async def _unset_mint_quotes_pending(
        self, quote_ids: List[str], state: MintQuoteState
    ) -> List[MintQuote]:
        """Unsets multiple mint quotes as pending.

        Args:
            quote_ids (List[str]): List of mint quote IDs to unset as pending.
            state (MintQuoteState): New state of the mint quotes.
        """
        if not quote_ids:
            return []

        quotes: List[MintQuote] = []
        lock_parameters = {f"quote_{i}": q for i, q in enumerate(quote_ids)}
        lock_select_statement = (
            "quote IN ("
            + ", ".join([f":quote_{i}" for i in range(len(quote_ids))])
            + ")"
        )

        async with self.db.get_connection(
            locks=[
                LockOptions(
                    table="mint_quotes",
                    select_statement=lock_select_statement,
                    parameters=lock_parameters,
                )
            ],
        ) as conn:
            for quote_id in quote_ids:
                quote = await self.crud.get_mint_quote(
                    quote_id=quote_id, db=self.db, conn=conn
                )
                if not quote:
                    raise TransactionError(f"Mint quote {quote_id} not found.")
                if quote.state != MintQuoteState.pending:
                    raise TransactionError(
                        f"Mint quote {quote_id} not pending: {quote.state.value}. Cannot set as {state.value}."
                    )
                # set the quote to previous state
                self._set_mint_quote_state(quote, state)
                logger.trace(f"crud: setting quote {quote_id} as {state.value}")
                await self.crud.update_mint_quote(quote=quote, db=self.db, conn=conn)
                quotes.append(quote)

        for quote in quotes:
            await self.events.submit(quote)
        return quotes

    async def _set_melt_quote_pending(
        self,
        quote: MeltQuote,
        conn: Optional[Connection] = None,
        get_checking_id: Optional[Callable[[MeltQuote], str]] = None,
    ) -> MeltQuote:
        """Sets the melt quote as pending.

        Args:
            quote (MeltQuote): Melt quote to set as pending.
            conn (Optional[Connection]): Connection to use. If not set, a new connection will be created.
            get_checking_id: Optional derivation using the newly assigned attempt.
        """
        quote_copy = quote.model_copy()
        if not quote.checking_id:
            raise TransactionError("Melt quote doesn't have checking ID.")
        async with self.db.get_connection(
            locks=[
                LockOptions(
                    table="melt_quotes",
                    select_statement=(
                        "checking_id = :checking_id OR request = :request"
                    ),
                    parameters={
                        "checking_id": quote.checking_id,
                        "request": quote.request,
                    },
                )
            ],
            conn=conn,
        ) as conn:
            quotes_by_checking_id = await self.crud.get_melt_quotes_by_checking_id(
                checking_id=quote.checking_id, db=self.db, conn=conn
            )
            quotes_by_request = await self.crud.get_melt_quotes_by_request(
                request=quote.request, db=self.db, conn=conn
            )
            quotes_db = list(
                {
                    existing.quote: existing
                    for existing in quotes_by_checking_id + quotes_by_request
                }.values()
            )
            if len(quotes_db) == 0:
                raise TransactionError("Melt quote not found.")
            if any([quote.state == MeltQuoteState.paid for quote in quotes_db]):
                raise InvoiceAlreadyPaidError("Melt quote already paid or pending.")
            if any([quote.state == MeltQuoteState.pending for quote in quotes_db]):
                raise QuotePendingError("Melt quote already paid or pending.")
            current_quote = next((q for q in quotes_db if q.quote == quote.quote), None)
            if current_quote is None:
                raise TransactionError("Melt quote not found.")
            quote_copy.attempt = _uuid7()
            if get_checking_id is not None:
                # Persist the backend identifier with the pending state.
                quote_copy.checking_id = get_checking_id(quote_copy)
            quote_copy.state = MeltQuoteState.pending
            # Persist execution ownership with the pending state.
            quote_copy.melt_lock = str(uuid.uuid4())
            quote_copy.melt_lock_expires_at = (
                await self._lease_time(conn) + settings.mint_melt_lease_seconds
            )
            # Record the send outcome before completing reconciliation.
            quote_copy.payment_uncertain = True
            await self.crud.update_melt_quote(quote=quote_copy, db=self.db, conn=conn)

        await self.events.submit(quote_copy)
        return quote_copy

    async def _unset_melt_quote_pending(
        self,
        quote: MeltQuote,
        state: MeltQuoteState,
        conn: Optional[Connection] = None,
    ) -> MeltQuote:
        """Unsets the melt quote as pending.

        Args:
            quote (MeltQuote): Melt quote to unset as pending.
            state (MeltQuoteState): New state of the melt quote.
            conn (Optional[Connection]): Connection to use. If not set, a new connection will be created.
        Raises:
            TransactionError: If the melt quote is not found or not pending.
        """
        async with self.db.get_connection(
            locks=[
                LockOptions(
                    table="melt_quotes",
                    select_statement="quote = :quote",
                    parameters={"quote": quote.quote},
                )
            ],
            conn=conn,
        ) as conn:
            # get melt quote from db and check if it is pending
            quote_db = await self.crud.get_melt_quote(
                quote_id=quote.quote, db=self.db, conn=conn
            )
            if not quote_db:
                raise TransactionError("Melt quote not found.")
            if quote_db.state != MeltQuoteState.pending:
                raise TransactionError("Melt quote not pending.")
            if not await self.can_finalize_melt_quote(
                quote_db, quote.attempt, quote.melt_lock or None, conn
            ):
                raise TransactionError("Melt execution lease lost.")
            # Apply the transition to the row read within this transaction.
            quote_db.state = state
            quote_db.melt_lock = ""
            quote_db.melt_lock_expires_at = 0
            await self.crud.update_melt_quote(quote=quote_db, db=self.db, conn=conn)

        await self.events.submit(quote_db)
        return quote_db

    async def _update_mint_quote_state(self, quote_id: str, state: MintQuoteState):
        async with self.db.get_connection(
            locks=[
                LockOptions(
                    table="mint_quotes",
                    select_statement="quote = :quote",
                    parameters={"quote": quote_id},
                )
            ],
        ) as conn:
            mint_quote = await self.crud.get_mint_quote(
                quote_id=quote_id, db=self.db, conn=conn
            )
            if not mint_quote:
                raise TransactionError("Mint quote not found.")
            mint_quote.state = state
            mint_quote.updated_at = int(time.time())
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
        async with self.db.get_connection(
            locks=[
                LockOptions(
                    table="melt_quotes",
                    select_statement="quote = :quote",
                    parameters={"quote": quote_id},
                )
            ],
        ) as conn:
            melt_quote = await self.crud.get_melt_quote(
                quote_id=quote_id, db=self.db, conn=conn
            )
            if not melt_quote:
                raise TransactionError("Melt quote not found.")
            if melt_quote.locked:
                raise TransactionError(
                    "Melt quote is locked by an in-flight payment executor. "
                    "Release the lock explicitly first (UnlockNut05Quote)."
                )
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
            locks=[
                LockOptions(
                    table="melt_quotes",
                    select_statement=(
                        "checking_id = :checking_id OR request = :request"
                    ),
                    parameters={
                        "checking_id": quote.checking_id,
                        "request": quote.request,
                    },
                )
            ],
        ) as conn:
            quotes_by_checking_id = await self.crud.get_melt_quotes_by_checking_id(
                checking_id=quote.checking_id, db=self.db, conn=conn
            )
            quotes_by_request = await self.crud.get_melt_quotes_by_request(
                request=quote.request, db=self.db, conn=conn
            )
            quotes_db = {
                existing.quote: existing
                for existing in quotes_by_checking_id + quotes_by_request
            }.values()
            if any([quote.state == MeltQuoteState.paid for quote in quotes_db]):
                raise InvoiceAlreadyPaidError("Melt quote already paid or pending.")
            if any([quote.state == MeltQuoteState.pending for quote in quotes_db]):
                raise QuotePendingError("Melt quote already paid or pending.")

            # store the melt quote
            await self.crud.store_melt_quote(quote=quote, db=self.db, conn=conn)

    async def verify_and_set_melt_quote_pending(
        self,
        quote: MeltQuote,
        proofs: List[Proof],
        keysets: Dict[str, MintKeyset],
        conn: Optional[Connection] = None,
        get_checking_id: Optional[Callable[[MeltQuote], str]] = None,
    ) -> MeltQuote:
        """Sets the melt quote and proofs as pending in a single transaction.

        Args:
            quote (MeltQuote): Melt quote to set as pending.
            proofs (List[Proof]): Proofs to set as pending.
            keysets (Dict[str, MintKeyset]): Keysets for updating balances.
            conn (Optional[Connection]): Database connection to reuse.
            get_checking_id: Optional derivation using the newly assigned attempt.

        Returns:
            MeltQuote: Updated melt quote object.
        """
        # Locks are ordered by table name (melt_quotes before proofs_pending),
        # so declare both upfront to keep the global lock order.
        async with self.db.get_connection(
            locks=[
                LockOptions(
                    table="melt_quotes",
                    select_statement="checking_id = :checking_id",
                    parameters={"checking_id": quote.checking_id},
                ),
                LockOptions(table="proofs_pending", timeout=1),
            ],
            conn=conn,
        ) as conn:
            await self._verify_spent_proofs_and_set_pending(
                proofs, keysets, quote_id=quote.quote, conn=conn
            )
            quote = await self._set_melt_quote_pending(
                quote, conn=conn, get_checking_id=get_checking_id
            )

        return quote

    async def _lease_time(self, conn: Connection) -> float:
        row = await conn.fetchone(f"SELECT {self.db.epoch_now} AS lease_now")
        assert row is not None
        return float(row["lease_now"])

    async def melt_lease_valid(self, quote: MeltQuote, conn: Connection) -> bool:
        return bool(quote.melt_lock) and (
            quote.melt_lock_expires_at > await self._lease_time(conn)
        )

    async def can_finalize_melt_quote(
        self,
        quote: MeltQuote,
        expected_attempt: Optional[str],
        lock_token: Optional[str],
        conn: Connection,
    ) -> bool:
        """Check execution-attempt and lease ownership for finalization."""
        if expected_attempt is not None and quote.attempt != expected_attempt:
            return False
        if lock_token is None:
            return not quote.melt_lock
        return quote.melt_lock == lock_token and await self.melt_lease_valid(
            quote, conn
        )

    async def renew_melt_quote_lease(self, quote: MeltQuote) -> bool:
        """Only a still-valid owner may renew; an expired lease cannot be revived."""
        async with self.db.get_connection(
            locks=[
                LockOptions(
                    table="melt_quotes",
                    select_statement="quote = :quote",
                    parameters={"quote": quote.quote},
                )
            ]
        ) as conn:
            result = await conn.execute(
                f"""UPDATE {self.db.table_with_schema("melt_quotes")}
                SET melt_lock_expires_at = {self.db.epoch_now} + :ttl
                WHERE quote = :quote AND attempt = :attempt AND melt_lock = :owner
                AND state IN ('PENDING', 'PAID') AND melt_lock_expires_at > {self.db.epoch_now}
                """,
                {
                    "quote": quote.quote,
                    "attempt": quote.attempt,
                    "owner": quote.melt_lock,
                    "ttl": settings.mint_melt_lease_seconds,
                },
            )
            return result.rowcount > 0

    async def claim_melt_quote_lease(self, quote: MeltQuote) -> Optional[MeltQuote]:
        """Claim recovery of the same attempt, without authorizing another send."""
        async with self.db.get_connection(
            locks=[
                LockOptions(
                    table="melt_quotes",
                    select_statement="quote = :quote",
                    parameters={"quote": quote.quote},
                )
            ]
        ) as conn:
            current = await self.crud.get_melt_quote(
                quote_id=quote.quote, db=self.db, conn=conn
            )
            if not current or current.attempt != quote.attempt:
                return None
            if not (current.pending or current.paid):
                return None
            if await self.melt_lease_valid(current, conn):
                return None
            current.melt_lock = str(uuid.uuid4())
            current.melt_lock_expires_at = (
                await self._lease_time(conn) + settings.mint_melt_lease_seconds
            )
            await self.crud.update_melt_quote(quote=current, db=self.db, conn=conn)
            return current

    async def unlock_melt_quote(self, quote_id: str, lock_token: str) -> None:
        """Release the melt execution lock if it is still held by `lock_token`.

        Called whenever an executor exits. Terminal finalization already clears
        the lock, so this is then a no-op. Otherwise the quote and proofs stay
        PENDING and status pollers or reconciliation may resolve the payment.
        """
        async with self.db.get_connection(
            locks=[
                LockOptions(
                    table="melt_quotes",
                    select_statement="quote = :quote",
                    parameters={"quote": quote_id},
                )
            ],
        ) as conn:
            await conn.execute(
                f"""
                UPDATE {self.db.table_with_schema("melt_quotes")}
                SET melt_lock = '', melt_lock_expires_at = 0
                WHERE quote = :quote AND melt_lock = :lock_token
                """,
                {"quote": quote_id, "lock_token": lock_token},
            )

    async def force_unlock_melt_quote(self, quote_id: str) -> bool:
        """Release the melt execution lock regardless of the holder (operator
        override). Returns True if a lock was released.

        The quote and proofs stay in their current states. Late executor
        writes are fenced, and recovery keeps uncertain payments pending.
        """
        async with self.db.get_connection(
            locks=[
                LockOptions(
                    table="melt_quotes",
                    select_statement="quote = :quote",
                    parameters={"quote": quote_id},
                )
            ],
        ) as conn:
            result = await conn.execute(
                f"""
                UPDATE {self.db.table_with_schema("melt_quotes")}
                SET melt_lock = '', melt_lock_expires_at = 0
                WHERE quote = :quote AND melt_lock != ''
                """,
                {"quote": quote_id},
            )
        return result.rowcount > 0

    async def unset_melt_quote_pending_and_proofs(
        self,
        quote: MeltQuote,
        proofs: List[Proof],
        keysets: Dict[str, MintKeyset],
        state: MeltQuoteState,
    ) -> MeltQuote:
        """Unsets the melt quote and proofs as pending in a single transaction.

        Args:
            quote (MeltQuote): Melt quote to update.
            proofs (List[Proof]): Proofs to unset as pending.
            keysets (Dict[str, MintKeyset]): Keysets for updating balances.
            state (MeltQuoteState): New state for the melt quote (e.g. UNPAID).
        """
        # Locks are ordered by table name (melt_quotes before proofs_pending),
        # so declare both upfront to keep the global lock order.
        async with self.db.get_connection(
            locks=[
                LockOptions(
                    table="melt_quotes",
                    select_statement="quote = :quote",
                    parameters={"quote": quote.quote},
                ),
                LockOptions(table="proofs_pending", timeout=1),
            ],
        ) as conn:
            quote = await self._unset_melt_quote_pending(quote, state, conn=conn)
            await self._unset_proofs_pending(proofs, keysets, spent=False, conn=conn)
            # Clean up blinded messages associated with this melt
            await self.crud.delete_blinded_messages_melt_id(
                melt_id=quote.quote, db=self.db, conn=conn
            )

        return quote

    async def invalidate_proofs(
        self,
        proofs: List[Proof],
        keysets: Dict[str, MintKeyset],
        quote_id: Optional[str] = None,
        keyset_fees: Optional[Dict[str, int]] = None,
        conn: Optional[Connection] = None,
        emit_events: bool = True,
    ) -> None:
        """Invalidates proofs (spends them) and updates keyset balances and fees.

        Args:
            proofs (List[Proof]): Proofs to invalidate.
            keysets (Dict[str, MintKeyset]): Keysets to update.
            quote_id (Optional[str]): Melt quote ID if applicable.
            keyset_fees (Optional[Dict[str, int]]): Fees paid per keyset.
            conn (Optional[Connection]): Database connection.
        """
        async with self.db.get_connection(conn) as conn:
            amounts_by_keyset: Dict[str, int] = {}
            for proof in proofs:
                amounts_by_keyset[proof.id] = (
                    amounts_by_keyset.get(proof.id, 0) + proof.amount
                )

            for keyset_id, amount in sorted(amounts_by_keyset.items()):
                debited = await self.crud.try_debit_keyset_balance(
                    db=self.db,
                    keyset=keysets[keyset_id],
                    amount=amount,
                    conn=conn,
                )
                if not debited:
                    raise TransactionError(
                        "keyset balance is insufficient for redemption"
                    )

            # Invalidate proofs (spend them) after their final debit succeeds.
            for p in proofs:
                logger.trace(f"Invalidating proof {p.Y}")
                await self.crud.invalidate_proof(
                    proof=p, db=self.db, quote_id=quote_id, conn=conn
                )
                if emit_events:
                    await self.events.submit(
                        ProofState(
                            Y=p.Y,
                            state=ProofSpentState.spent,
                            witness=p.witness or None,
                        )
                    )

            # Update fees
            if keyset_fees:
                for keyset_id, fee in keyset_fees.items():
                    if fee > 0:
                        await self.crud.bump_keyset_fees_paid(
                            keyset=keysets[keyset_id],
                            amount=fee,
                            db=self.db,
                            conn=conn,
                        )

    async def set_melt_quote_paid_and_invalidate_proofs(
        self,
        quote: MeltQuote,
        proofs: List[Proof],
        keysets: Dict[str, MintKeyset],
        keyset_fees: Dict[str, int],
    ) -> MeltQuote:
        """Sets the melt quote as PAID and invalidates proofs in a single transaction.

        Args:
            quote (MeltQuote): Melt quote to set as PAID.
            proofs (List[Proof]): Proofs to invalidate (spend).
            keysets (Dict[str, MintKeyset]): Keysets for updating balances/fees.
            keyset_fees (Dict[str, int]): Fees paid per keyset.
        """
        # Locks are ordered by table name (melt_quotes before proofs_pending),
        # so declare both upfront to keep the global lock order.
        async with self.db.get_connection(
            locks=[
                LockOptions(
                    table="melt_quotes",
                    select_statement="quote = :quote",
                    parameters={"quote": quote.quote},
                ),
                LockOptions(table="proofs_pending", timeout=1),
            ],
        ) as conn:
            # Load the quote within the finalization transaction.
            quote_db = await self.crud.get_melt_quote(
                quote_id=quote.quote, db=self.db, conn=conn
            )
            if not quote_db:
                raise TransactionError("Melt quote not found.")

            if not await self.can_finalize_melt_quote(
                quote_db, quote.attempt, quote.melt_lock or None, conn
            ):
                raise TransactionError("Melt execution lease lost.")

            # 1. Release the pending reservation and debit the final spend.
            await self.finalize_pending_proofs(
                proofs=proofs,
                keysets=keysets,
                quote_id=quote.quote,
                keyset_fees=keyset_fees,
                conn=conn,
            )

            # 2. Update melt quote to PAID
            if quote_db.state != MeltQuoteState.paid:
                quote_db.state = MeltQuoteState.paid
                quote_db.paid_time = int(time.time())
            quote_db.melt_lock = ""
            quote_db.melt_lock_expires_at = 0
            await self.crud.update_melt_quote(quote=quote_db, db=self.db, conn=conn)

        # Events
        await self.events.submit(quote_db)

        return quote_db
