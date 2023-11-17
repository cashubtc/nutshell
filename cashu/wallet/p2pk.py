from datetime import datetime, timedelta
from typing import List, Optional

from loguru import logger

from ..core.base import (
    BlindedMessage,
    P2PKWitness,
    Proof,
)
from ..core.crypto.secp import PrivateKey
from ..core.db import Database
from ..core.p2pk import (
    P2PKSecret,
    SigFlags,
    sign_p2pk_sign,
)
from ..core.secret import Secret, SecretKind, Tags
from .protocols import SupportsDb, SupportsPrivateKey


class WalletP2PK(SupportsPrivateKey, SupportsDb):
    db: Database
    private_key: Optional[PrivateKey] = None
    # ---------- P2PK ----------

    async def create_p2pk_pubkey(self):
        assert (
            self.private_key
        ), "No private key set in settings. Set NOSTR_PRIVATE_KEY in .env"
        public_key = self.private_key.pubkey
        # logger.debug(f"Private key: {self.private_key.bech32()}")
        assert public_key
        return public_key.serialize().hex()

    async def create_p2pk_lock(
        self,
        pubkey: str,
        locktime_seconds: Optional[int] = None,
        tags: Optional[Tags] = None,
        sig_all: bool = False,
        n_sigs: int = 1,
    ) -> P2PKSecret:
        logger.debug(f"Provided tags: {tags}")
        if not tags:
            tags = Tags()
            logger.debug(f"Before tags: {tags}")
        if locktime_seconds:
            tags["locktime"] = str(
                int((datetime.now() + timedelta(seconds=locktime_seconds)).timestamp())
            )
        tags["sigflag"] = (
            SigFlags.SIG_ALL.value if sig_all else SigFlags.SIG_INPUTS.value
        )
        if n_sigs > 1:
            tags["n_sigs"] = str(n_sigs)
        logger.debug(f"After tags: {tags}")
        return P2PKSecret(
            kind=SecretKind.P2PK.value,
            data=pubkey,
            tags=tags,
        )

    async def sign_p2pk_proofs(self, proofs: List[Proof]) -> List[str]:
        assert (
            self.private_key
        ), "No private key set in settings. Set NOSTR_PRIVATE_KEY in .env"
        private_key = self.private_key
        assert private_key.pubkey
        logger.trace(
            f"Signing with private key: {private_key.serialize()} public key:"
            f" {private_key.pubkey.serialize().hex()}"
        )
        for proof in proofs:
            logger.trace(f"Signing proof: {proof}")
            logger.trace(f"Signing message: {proof.secret}")

        signatures = [
            sign_p2pk_sign(
                message=proof.secret.encode("utf-8"),
                private_key=private_key,
            )
            for proof in proofs
        ]
        logger.debug(f"Signatures: {signatures}")
        return signatures

    async def sign_p2pk_outputs(self, outputs: List[BlindedMessage]) -> List[str]:
        assert (
            self.private_key
        ), "No private key set in settings. Set NOSTR_PRIVATE_KEY in .env"
        private_key = self.private_key
        assert private_key.pubkey
        return [
            sign_p2pk_sign(
                message=output.B_.encode("utf-8"),
                private_key=private_key,
            )
            for output in outputs
        ]

    async def add_p2pk_witnesses_to_outputs(
        self, outputs: List[BlindedMessage]
    ) -> List[BlindedMessage]:
        """Takes a list of outputs and adds a P2PK signatures to each.
        Args:
            outputs (List[BlindedMessage]): Outputs to add P2PK signatures to
        Returns:
            List[BlindedMessage]: Outputs with P2PK signatures added
        """
        p2pk_signatures = await self.sign_p2pk_outputs(outputs)
        for o, s in zip(outputs, p2pk_signatures):
            o.witness = P2PKWitness(signatures=[s]).json()
        return outputs

    async def add_witnesses_to_outputs(
        self, proofs: List[Proof], outputs: List[BlindedMessage]
    ) -> List[BlindedMessage]:
        """Adds witnesses to outputs if the inputs (proofs) indicate an appropriate signature flag

        Args:
            proofs (List[Proof]): Inputs to the transaction
            outputs (List[BlindedMessage]): Outputs to add witnesses to
        Returns:
            List[BlindedMessage]: Outputs with signatures added
        """
        # first we check whether all tokens have serialized secrets as their secret
        try:
            for p in proofs:
                Secret.deserialize(p.secret)
        except Exception:
            # if not, we do not add witnesses (treat as regular token secret)
            return outputs

        # if any of the proofs provided require SIG_ALL, we must provide it
        if any([
            P2PKSecret.deserialize(p.secret).sigflag == SigFlags.SIG_ALL for p in proofs
        ]):
            outputs = await self.add_p2pk_witnesses_to_outputs(outputs)
        return outputs

    async def add_p2pk_witnesses_to_proofs(self, proofs: List[Proof]) -> List[Proof]:
        p2pk_signatures = await self.sign_p2pk_proofs(proofs)
        logger.debug(f"Unlock signatures for {len(proofs)} proofs: {p2pk_signatures}")
        logger.debug(f"Proofs: {proofs}")
        # attach unlock signatures to proofs
        assert len(proofs) == len(p2pk_signatures), "wrong number of signatures"
        for p, s in zip(proofs, p2pk_signatures):
            # if there are already signatures, append
            if p.witness and P2PKWitness.from_witness(p.witness).signatures:
                signatures = P2PKWitness.from_witness(p.witness).signatures
                p.witness = P2PKWitness(signatures=signatures + [s]).json()
            else:
                p.witness = P2PKWitness(signatures=[s]).json()
        return proofs

    async def add_witnesses_to_proofs(self, proofs: List[Proof]) -> List[Proof]:
        """Adds witnesses to proofs for P2PK redemption.

        This method parses the secret of each proof and determines the correct
        witness type and adds it to the proof if we have it available.

        Note: In order for this method to work, all proofs must have the same secret type.
        For P2PK, we use an individual signature for each token in proofs.

        Args:
            proofs (List[Proof]): List of proofs to add witnesses to

        Returns:
            List[Proof]: List of proofs with witnesses added
        """

        # iterate through proofs and produce witnesses for each

        # first we check whether all tokens have serialized secrets as their secret
        try:
            for p in proofs:
                Secret.deserialize(p.secret)
        except Exception:
            # if not, we do not add witnesses (treat as regular token secret)
            return proofs
        logger.debug("Spending conditions detected.")
        # P2PK signatures
        if all([
            Secret.deserialize(p.secret).kind == SecretKind.P2PK.value for p in proofs
        ]):
            logger.debug("P2PK redemption detected.")
            proofs = await self.add_p2pk_witnesses_to_proofs(proofs)

        return proofs
