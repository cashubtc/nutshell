from typing import Dict, List, Optional

from ...core.base import Proof, ProofSpentState, ProofState
from ...core.db import Connection, Database
from ...core.errors import TokenAlreadySpentError
from ..crud import LedgerCrud


class DbReadHelper:
    db: Database
    crud: LedgerCrud

    def __init__(self, db: Database, crud: LedgerCrud) -> None:
        self.db = db
        self.crud = crud

    async def _get_proofs_pending(
        self, Ys: List[str], conn: Optional[Connection] = None
    ) -> Dict[str, Proof]:
        """Returns a dictionary of only those proofs that are pending.
        The key is the Y=h2c(secret) and the value is the proof.
        """
        async with self.db.get_connection(conn) as conn:
            proofs_pending = await self.crud.get_proofs_pending(
                Ys=Ys, db=self.db, conn=conn
            )
        proofs_pending_dict = {p.Y: p for p in proofs_pending}
        return proofs_pending_dict

    async def _get_proofs_spent(
        self, Ys: List[str], conn: Optional[Connection] = None
    ) -> Dict[str, Proof]:
        """Returns a dictionary of all proofs that are spent.
        The key is the Y=h2c(secret) and the value is the proof.
        """
        proofs_spent_dict: Dict[str, Proof] = {}
        # check used secrets in database
        async with self.db.get_connection(conn) as conn:
            spent_proofs = await self.crud.get_proofs_used(db=self.db, Ys=Ys, conn=conn)
        proofs_spent_dict = {p.Y: p for p in spent_proofs}
        return proofs_spent_dict

    async def get_proofs_states(
        self, Ys: List[str], conn: Optional[Connection] = None
    ) -> List[ProofState]:
        """Checks if provided proofs are spend or are pending.
        Used by wallets to check if their proofs have been redeemed by a receiver or they are still in-flight in a transaction.

        Returns two lists that are in the same order as the provided proofs. Wallet must match the list
        to the proofs they have provided in order to figure out which proof is spendable or pending
        and which isn't.

        Args:
            Ys (List[str]): List of Y's of proofs to check

        Returns:
            List[bool]: List of which proof is still spendable (True if still spendable, else False)
            List[bool]: List of which proof are pending (True if pending, else False)
        """
        states: List[ProofState] = []
        async with self.db.get_connection(conn) as conn:
            proofs_spent = await self._get_proofs_spent(Ys, conn)
            proofs_pending = await self._get_proofs_pending(Ys, conn)
            for Y in Ys:
                if Y not in proofs_spent and Y not in proofs_pending:
                    states.append(ProofState(Y=Y, state=ProofSpentState.unspent))
                elif Y not in proofs_spent and Y in proofs_pending:
                    states.append(ProofState(Y=Y, state=ProofSpentState.pending))
                else:
                    states.append(
                        ProofState(
                            Y=Y,
                            state=ProofSpentState.spent,
                            witness=proofs_spent[Y].witness,
                        )
                    )
        return states

    async def _verify_proofs_spendable(
        self, proofs: List[Proof], conn: Optional[Connection] = None
    ):
        """Checks the database to see if any of the proofs are already spent.

        Args:
            proofs (List[Proof]): Proofs to verify
            conn (Optional[Connection]): Database connection to use. Defaults to None.

        Raises:
            TokenAlreadySpentError: If any of the proofs are already spent
        """
        async with self.db.get_connection(conn) as conn:
            if not len(await self._get_proofs_spent([p.Y for p in proofs], conn)) == 0:
                raise TokenAlreadySpentError()
