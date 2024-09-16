from typing import Dict

from ..core.errors import TransactionError
from ..core.nuts import DLC_NUT
from .features import LedgerFeatures


class LedgerDLC(LedgerFeatures):

    async def get_dlc_fees(self, fa_unit: str) -> Dict[str, int]:
        try:
            fees = self.mint_features()[DLC_NUT]
            assert isinstance(fees, dict)
            fees = fees['fees']
            assert isinstance(fees, dict)
            fees = fees[fa_unit]
            assert isinstance(fees, dict)
            return fees
        except Exception:
            raise TransactionError("could not get fees for the specified funding_amount denomination")
