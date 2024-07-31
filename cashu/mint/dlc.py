from ..core.nuts import DLC_NUT
from ..core.base import Proof
from ..core.secret import Secret, SecretKind
from ..core.errors import TransactionError
from .features import LedgerFeatures

from json.decoder import JSONDecodeError

from typing import List, Tuple, Dict
class LedgerDLC(LedgerFeatures):

    async def filter_sct_proofs(self, proofs: List[Proof]) -> Tuple[List[Proof], List[Proof]]:
        deserializable = []
        non_sct_proofs = []
        for p in proofs:
            try:
                Secret.deserialize(p.secret)
                deserializable.append(p)
            except JSONDecodeError:
                non_sct_proofs.append(p)

        sct_proofs = list(filter(lambda p: Secret.deserialize(p.secret).kind == SecretKind.SCT.value, deserializable))
        non_sct_proofs += list(filter(lambda p: p not in sct_proofs, deserializable))
        return (sct_proofs, non_sct_proofs)

    async def get_dlc_fees(self, fa_unit: str) -> Dict[str, int]:
        try:
            fees = self.mint_features()[DLC_NUT]
            assert isinstance(fees, dict)
            fees = fees['fees']
            assert isinstance(fees, dict)
            fees = fees[fa_unit]
            assert isinstance(fees, dict)
            return fees
        except Exception as e:
            raise TransactionError("could not get fees for the specified funding_amount denomination")