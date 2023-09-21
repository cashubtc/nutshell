import time
from typing import List, Union

from loguru import logger

from .secret import Secret, SecretKind


class HTLCSecret(Secret):
    @classmethod
    def from_secret(cls, secret: Secret):
        assert secret.kind == SecretKind.HTLC, "Secret is not a HTLC secret"
        # NOTE: exclude tags in .dict() because it doesn't deserialize it properly
        # need to add it back in manually with tags=secret.tags
        return cls(**secret.dict(exclude={"tags"}), tags=secret.tags)

    def get_htlc_pubkey_from_secret(self) -> List[str]:
        """Gets the HTLC pubkey from a Secret depending on the locktime

        Args:
            secret (Secret): HTLC Secret in ecash token

        Returns:
            str: pubkey to use for HTLC, empty string if anyone can spend (locktime passed)
        """
        # check if locktime is passed and if so, only return refund pubkeys
        now = time.time()
        if self.locktime and self.locktime < now:
            logger.trace(f"htlc locktime ran out ({self.locktime}<{now}).")
            # check tags if a refund pubkey is present.
            # If yes, we demand the signature to be from the refund pubkey if it is present
            return self.tags.get_tag_all("refund")

        return ["unsolvable"]

    @property
    def locktime(self) -> Union[None, int]:
        locktime = self.tags.get_tag("locktime")
        return int(locktime) if locktime else None
