from datetime import datetime, timedelta
from typing import List, Optional

from loguru import logger

from cashu.core.htlc import HTLCSecret

from ..core.base import (
    BlindedMessage,
    HTLCWitness,
    P2PKWitness,
    Proof,
)
from ..core.crypto.secp import PrivateKey
from ..core.db import Database
from ..core.p2pk import (
    P2PKSecret,
    SigFlags,
    schnorr_sign,
)
from ..core.secret import Secret, SecretKind, Tags
from .protocols import SupportsDb, SupportsPrivateKey


class WalletP2PK(SupportsPrivateKey, SupportsDb):
    db: Database
    private_key: PrivateKey
    # ---------- P2PK ----------

    async def create_p2pk_pubkey(self):
        """Create a P2PK public key from the private key."""
        assert (
            self.private_key
        ), "No private key set in settings. Set NOSTR_PRIVATE_KEY in .env"
        public_key = self.private_key.pubkey
        # logger.debug(f"Private key: {self.private_key.bech32()}")
        assert public_key
        return public_key.serialize().hex()

    async def create_p2pk_lock(
        self,
        data: str,
        locktime_seconds: Optional[int] = None,
        tags: Optional[Tags] = None,
        sig_all: bool = False,
        n_sigs: int = 1,
    ) -> P2PKSecret:
        """Generate a P2PK secret with the given pubkeys, locktime, tags, and signature flag.

        Args:
            data (str): Public key to lock to.
            locktime_seconds (Optional[int], optional): Locktime in seconds. Defaults to None.
            tags (Optional[Tags], optional): Tags to add to the secret. Defaults to None.
            sig_all (bool, optional): Whether to use SIG_ALL spending condition. Defaults to False.
            n_sigs (int, optional): Number of signatures required. Defaults to 1.

        Returns:
            P2PKSecret: P2PK secret with the given pubkeys, locktime, tags, and signature flag.
        """
        logger.debug(f"Provided tags: {tags}")
        if not tags:
            tags = Tags()
            logger.debug(f"Before tags: {tags}")
        if locktime_seconds:
            tags["locktime"] = str(
                int((datetime.now() + timedelta(seconds=locktime_seconds)).timestamp())
            )
        if sig_all:
            tags["sigflag"] = SigFlags.SIG_ALL.value
        if n_sigs > 1:
            tags["n_sigs"] = str(n_sigs)
        logger.debug(f"After tags: {tags}")
        return P2PKSecret(
            kind=SecretKind.P2PK.value,
            data=data,
            tags=tags,
        )

    def signatures_proofs_sig_inputs(self, proofs: List[Proof]) -> List[str]:
        """Signs proof secrets with the private key of the wallet.
        This method is used to sign P2PK SIG_INPUTS proofs.

        Args:
            proofs (List[Proof]): Proofs to sign

        Returns:
            List[str]: List of signatures for each proof
        """
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
            schnorr_sign(
                message=proof.secret.encode("utf-8"),
                private_key=private_key,
            ).hex()
            for proof in proofs
        ]
        logger.debug(f"Signatures: {signatures}")
        return signatures

    def schnorr_sign_message(self, message: str) -> str:
        """Sign a message with the private key of the wallet."""
        private_key = self.private_key
        assert private_key.pubkey
        return schnorr_sign(
            message=message.encode("utf-8"),
            private_key=private_key,
        ).hex()

    def _inputs_require_sigall(self, proofs: List[Proof]) -> bool:
        """
        Check if any input requires sigall spending condition.
        """
        for proof in proofs:
            try:
                secret = Secret.deserialize(proof.secret)
                try:
                    p2pk_secret = P2PKSecret.from_secret(secret)
                    if p2pk_secret.sigflag is SigFlags.SIG_ALL:
                        return True
                except Exception:
                    pass
                try:
                    htlc_secret = HTLCSecret.from_secret(secret)
                    if htlc_secret.sigflag is SigFlags.SIG_ALL:
                        return True
                except Exception:
                    pass
            except Exception:
                # secret is not a spending condition so we treat is a normal secret
                pass
        return False

    def add_witness_swap_sig_all(
        self,
        proofs: List[Proof],
        outputs: List[BlindedMessage],
        message_to_sign: Optional[str] = None,
    ) -> List[Proof]:
        """Determine whether the first input's sig flag is SIG_ALL ()"""
        if not self._inputs_require_sigall(proofs):
            return proofs
        try:
            logger.debug("Input requires SIG_ALL")
            proofs_to_sign = self.filter_proofs_locked_to_our_pubkey(proofs)
            if len(proofs_to_sign) != len(proofs):
                raise Exception("Proofs not locked to our pubkey")
            secrets = set([Secret.deserialize(p.secret) for p in proofs])
            if not len(secrets) == 1:
                raise Exception("Secrets not identical")
            message_to_sign = message_to_sign or "".join(
                [p.secret for p in proofs] + [o.B_ for o in outputs]
            )
            signature = self.schnorr_sign_message(message_to_sign)
            # add witness to only the first proof
            signed_proofs = self.add_signatures_to_proofs([proofs[0]], [signature])
            proofs[0].witness = signed_proofs[0].witness
            logger.debug(
                f"SIGALL Adding witness to proof: {proofs[0].secret} with signature: {signature}"
            )
        except Exception:
            logger.error("not all secrets are the same, skipping SIG_ALL signature")
            return proofs
        return proofs

    def sign_proofs_inplace_swap(
        self, proofs: List[Proof], outputs: List[BlindedMessage]
    ) -> List[Proof]:
        """Adds witnesses to outputs if the inputs (proofs) indicate an appropriate signature flag

        Args:
            proofs (List[Proof]): Inputs to the transaction
            outputs (List[BlindedMessage]): Outputs to add witnesses to
        Returns:
            List[BlindedMessage]: Outputs with signatures added
        """
        # sign proofs if they are P2PK SIG_INPUTS
        proofs = self.add_witnesses_sig_inputs(proofs)
        # sign first proof if swap is SIG_ALL
        proofs = self.add_witness_swap_sig_all(proofs, outputs)

        return proofs

    def sign_proofs_inplace_melt(
        self, proofs: List[Proof], outputs: List[BlindedMessage], quote_id: str
    ) -> List[Proof]:
        # sign proofs if they are P2PK SIG_INPUTS
        proofs = self.add_witnesses_sig_inputs(proofs)
        message_to_sign = (
            "".join([p.secret for p in proofs] + [o.B_ for o in outputs]) + quote_id
        )
        # sign first proof if swap is SIG_ALL
        return self.add_witness_swap_sig_all(proofs, outputs, message_to_sign)

    def add_signatures_to_proofs(
        self, proofs: List[Proof], signatures: List[str]
    ) -> List[Proof]:
        """Add signatures to proofs. Signatures are added as witnesses to the proofs in place.

        Args:
            proofs (List[Proof]): Proofs to add signatures to.
            signatures (List[str]): Signatures to add to the proofs.

        Returns:
            List[Proof]: Proofs with signatures added.
        """

        # attach unlock signatures to proofs
        assert len(proofs) == len(signatures), "wrong number of signatures"
        for p, s in zip(proofs, signatures):
            if Secret.deserialize(p.secret).kind == SecretKind.P2PK.value:
                # if there are already signatures, append
                if p.witness and P2PKWitness.from_witness(p.witness).signatures:
                    proof_signatures = P2PKWitness.from_witness(p.witness).signatures
                    if proof_signatures and s not in proof_signatures:
                        p.witness = P2PKWitness(
                            signatures=proof_signatures + [s]
                        ).json()
                else:
                    p.witness = P2PKWitness(signatures=[s]).json()
            elif Secret.deserialize(p.secret).kind == SecretKind.HTLC.value:
                # if there are already signatures, append
                if p.witness and HTLCWitness.from_witness(p.witness).signatures:
                    witness = HTLCWitness.from_witness(p.witness)
                    proof_signatures = witness.signatures
                    if proof_signatures and s not in proof_signatures:
                        p.witness = HTLCWitness(
                            preimage=witness.preimage, signatures=proof_signatures + [s]
                        ).json()
                else:
                    if p.witness:
                        witness = HTLCWitness.from_witness(p.witness)
                        p.witness = HTLCWitness(
                            preimage=witness.preimage, signatures=[s]
                        ).json()
                    else:
                        p.witness = HTLCWitness(signatures=[s]).json()
            else:
                raise Exception("Secret kind not supported")

        return proofs

    def filter_proofs_locked_to_our_pubkey(self, proofs: List[Proof]) -> List[Proof]:
        """This method assumes that secrets are all P2PK!"""
        # filter proofs that require our pubkey
        assert self.private_key.pubkey
        our_pubkey = self.private_key.pubkey.serialize().hex()
        our_pubkey_proofs = []
        for p in proofs:
            secret = P2PKSecret.deserialize(p.secret)
            pubkeys = (
                [secret.data]
                + secret.tags.get_tag_all("pubkeys")
                + secret.tags.get_tag_all("refund")
            )
            if our_pubkey in pubkeys:
                # we are one of the signers
                our_pubkey_proofs.append(p)
        logger.debug(
            f"Locked proofs containing our public key: {len(our_pubkey_proofs)}"
        )
        return our_pubkey_proofs

    def sign_p2pk_sig_inputs(self, proofs: List[Proof]) -> List[Proof]:
        """Signs P2PK SIG_INPUTS proofs with the private key of the wallet. Ignores proofs that
           aren't locked to our public key (filters them out before returning).
        Args:
            proofs (List[Proof]): Proofs to sign
        Returns:
            List[Proof]: List of proofs with signatures added
        """
        # filter proofs that are P2PK
        p2pk_proofs = []
        for p in proofs:
            try:
                secret = Secret.deserialize(p.secret)
                if secret.kind == SecretKind.P2PK.value:
                    p2pk_proofs.append(p)
                if secret.kind == SecretKind.HTLC.value and (
                    secret.tags.get_tag("pubkeys") or secret.tags.get_tag("refund")
                ):
                    # HTLC secret with pubkeys tag is a P2PK secret
                    p2pk_proofs.append(p)
            except Exception:
                pass

        if not p2pk_proofs:
            return []

        # filter proofs that that are P2PK and SIG_INPUTS
        sig_inputs_proofs = [
            p
            for p in p2pk_proofs
            if P2PKSecret.deserialize(p.secret).sigflag == SigFlags.SIG_INPUTS
        ]
        if not sig_inputs_proofs:
            return []

        our_pubkey_proofs = self.filter_proofs_locked_to_our_pubkey(sig_inputs_proofs)
        p2pk_signatures = self.signatures_proofs_sig_inputs(our_pubkey_proofs)
        signed_proofs = self.add_signatures_to_proofs(
            our_pubkey_proofs, p2pk_signatures
        )
        return signed_proofs

    def add_witnesses_sig_inputs(self, proofs: List[Proof]) -> List[Proof]:
        """Adds witnesses to proofs for P2PK redemption.

        This method parses the secret of each proof and determines the correct
        witness type and adds it to the proof if we have it available.

        Args:
            proofs (List[Proof]): List of proofs to add witnesses to

        Returns:
            List[Proof]: List of proofs with witnesses added
        """
        # sign P2PK SIG_INPUTS proofs
        signed_proofs = self.sign_p2pk_sig_inputs(proofs)
        # replace the original proofs with the signed ones
        signed_proofs_secrets = [p.secret for p in signed_proofs]
        for p in proofs:
            if p.secret in signed_proofs_secrets:
                proofs[proofs.index(p)] = signed_proofs[
                    signed_proofs_secrets.index(p.secret)
                ]

        # TODO: Sign HTLCs that require signatures as well

        return proofs
