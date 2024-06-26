import asyncio
from typing import List, Optional

from loguru import logger

from ...core.base import Proof, ProofSpentState, ProofState
from ...core.db import Connection, Database, get_db_connection
from ...core.errors import (
    TransactionError,
)
from ..crud import LedgerCrud
from ..events.events import LedgerEventManager


class DbWriteHelper:
    db: Database
    crud: LedgerCrud
    events: LedgerEventManager
    proofs_pending_lock: asyncio.Lock = (
        asyncio.Lock()
    )  # holds locks for proofs_pending database

    def __init__(
        self, db: Database, crud: LedgerCrud, events: LedgerEventManager
    ) -> None:
        self.db = db
        self.crud = crud
        self.events = events

    async def _set_proofs_pending(
        self, proofs: List[Proof], quote_id: Optional[str] = None
    ) -> None:
        """If none of the proofs is in the pending table (_validate_proofs_pending), adds proofs to
        the list of pending proofs or removes them. Used as a mutex for proofs.

        Args:
            proofs (List[Proof]): Proofs to add to pending table.
            quote_id (Optional[str]): Melt quote ID. If it is not set, we assume the pending tokens to be from a swap.

        Raises:
            Exception: At least one proof already in pending table.
        """
        # first we check whether these proofs are pending already
        async with self.proofs_pending_lock:
            async with get_db_connection(self.db) as conn:
                await self._validate_proofs_pending(proofs, conn)
                try:
                    for p in proofs:
                        await self.crud.set_proof_pending(
                            proof=p, db=self.db, quote_id=quote_id, conn=conn
                        )
                        await self.events.submit(
                            ProofState(Y=p.Y, state=ProofSpentState.pending)
                        )
                except Exception as e:
                    logger.error(f"Failed to set proofs pending: {e}")
                    raise TransactionError("Failed to set proofs pending.")

    async def _unset_proofs_pending(self, proofs: List[Proof], spent=True) -> None:
        """Deletes proofs from pending table.

        Args:
            proofs (List[Proof]): Proofs to delete.
            spent (bool): Whether the proofs have been spent or not. Defaults to True.
                This should be False if the proofs were NOT invalidated before calling this function.
                It is used to emit the unspent state for the proofs (otherwise the spent state is emitted
                by the _invalidate_proofs function when the proofs are spent).
        """
        async with self.proofs_pending_lock:
            async with get_db_connection(self.db) as conn:
                for p in proofs:
                    await self.crud.unset_proof_pending(proof=p, db=self.db, conn=conn)
                    if not spent:
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
        if not (
            len(
                await self.crud.get_proofs_pending(
                    Ys=[p.Y for p in proofs], db=self.db, conn=conn
                )
            )
            == 0
        ):
            raise TransactionError("proofs are pending.")
