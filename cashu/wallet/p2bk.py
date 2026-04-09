from datetime import datetime, timedelta
from typing import List, Optional, Tuple

from ..core.base import Proof
from ..core.crypto.secp import PrivateKey
from ..core.db import Database
from ..core.p2bk import (
    blind_pubkeys,
    derive_blinded_private_key,
)
from ..core.p2pk import (
    P2PKSecret,
    SigFlags,
)
from ..core.secret import SecretKind, Tags
from .protocols import SupportsDb, SupportsPrivateKey


class WalletP2BK(SupportsPrivateKey, SupportsDb):
    db: Database
    private_key: PrivateKey

    async def create_p2bk_lock(
        self,
        data: str,
        locktime_seconds: Optional[int] = None,
        tags: Optional[Tags] = None,
        sig_all: bool = False,
        n_sigs: int = 1,
        ephemeral_privkey: Optional[PrivateKey] = None,
    ) -> Tuple[P2PKSecret, str]:
        """Generate a P2BK-blinded P2PK secret.
        Blinds pubkeys in [data, ...pubkeys, ...refund] slot order using ECDH.

        Args:
            data: Receiver's public key to lock to.
            locktime_seconds: Locktime in seconds.
            tags: Tags (may contain pubkeys, refund keys).
            sig_all: Whether to use SIG_ALL spending condition.
            n_sigs: Number of signatures required.
            ephemeral_privkey: Ephemeral private key (reuse for SIG_ALL across outputs).

        Returns:
            Tuple of (P2PKSecret with blinded keys, ephemeral pubkey E hex).
        """

        if not tags:
            tags = Tags()

        if locktime_seconds:
            tags["locktime"] = str(
                int((datetime.now() + timedelta(seconds=locktime_seconds)).timestamp())
            )
        tags["sigflag"] = (
            SigFlags.SIG_ALL.value if sig_all else SigFlags.SIG_INPUTS.value
        )
        if n_sigs > 1:
            tags["n_sigs"] = str(n_sigs)

        # Collect pubkeys from tags before blinding
        additional_pubkeys = tags.get_tag_all("pubkeys")
        refund_pubkeys = tags.get_tag_all("refund")

        # Per-key ECDH: each pubkey P_i gets its own Zx_i = x(e * P_i).
        # Multi-party refund keys are handled correctly by this approach.
        blinded_data, blinded_additional, blinded_refund, ephemeral_pubkey_hex = (
            blind_pubkeys(
                data_pubkey=data,
                additional_pubkeys=additional_pubkeys,
                refund_pubkeys=refund_pubkeys,
                ephemeral_privkey=ephemeral_privkey,
            )
        )

        # Rebuild tags with blinded keys.
        # Tags stores multi-value as [key, v1, v2, ...]; list assignment is safe.
        blinded_tags = Tags()
        for tag in tags.root:
            if tag[0] == "pubkeys":
                blinded_tags["pubkeys"] = blinded_additional
            elif tag[0] == "refund":
                blinded_tags["refund"] = blinded_refund
            else:
                blinded_tags.root.append(tag)

        return P2PKSecret(
            kind=SecretKind.P2PK.value,
            data=blinded_data,
            tags=blinded_tags,
        ), ephemeral_pubkey_hex

    def _derive_p2bk_signing_key(self, proof: Proof) -> Optional[PrivateKey]:
        """If proof has p2pk_e, derive the blinded private key for our slot.

        Returns the blinded private key if we can unblind a slot, else None.
        """
        if not proof.p2pk_e:
            return None
        secret = P2PKSecret.deserialize(proof.secret)

        all_blinded_pubkeys = (
            [secret.data]
            + secret.tags.get_tag_all("pubkeys")
            + secret.tags.get_tag_all("refund")
        )
        for i, blinded_pk in enumerate(all_blinded_pubkeys):
            try:
                derived = derive_blinded_private_key(
                    privkey=self.private_key,
                    ephemeral_pubkey_hex=proof.p2pk_e,
                    blinded_pubkey_hex=blinded_pk,
                    slot_index=i,
                )
            except Exception:
                # Slot value is not a valid pubkey (e.g. HTLC preimage hash)
                continue
            if derived is not None:
                return derived
        return None

    def filter_p2bk_proofs(self, proofs: List[Proof]) -> List[Proof]:
        """Filter P2BK proofs (those with p2pk_e) that we can unblind."""
        return [
            p for p in proofs
            if p.p2pk_e and self._derive_p2bk_signing_key(p) is not None
        ]
