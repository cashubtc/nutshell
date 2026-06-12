import time
from dataclasses import dataclass
from hashlib import sha256
from typing import List, Optional

from loguru import logger

from ..core.base import BlindedMessage, HTLCWitness, P2PKWitness, Proof
from ..core.crypto.secp import PublicKey
from ..core.errors import (
    TransactionError,
)
from ..core.htlc import HTLCSecret
from ..core.p2pk import (
    P2PKSecret,
    SigFlags,
    sig_all_melt_message,
    sig_all_swap_message,
    verify_schnorr_signature,
)
from ..core.secret import Secret, SecretKind


@dataclass
class SpendPath:
    pubkeys: List[str]
    required_sigs: int


@dataclass
class SpendingRequirements:
    preimage_hash: str | None
    primary_path: SpendPath
    refund_path: SpendPath | None


@dataclass
class WitnessForP2pkOrHtlc:
    preimage: str | None
    signatures: List[str]

    @classmethod
    def from_p2pk_witness(cls, witness: Optional[str]) -> "WitnessForP2pkOrHtlc":
        if witness is None:
            return cls(preimage=None, signatures=[])

        try:
            parsed = P2PKWitness.from_witness(witness)
            return cls(preimage=None, signatures=parsed.signatures)
        except Exception:
            return cls(preimage=None, signatures=[])

    @classmethod
    def from_htlc_witness(cls, witness: Optional[str]) -> "WitnessForP2pkOrHtlc":
        if witness is None:
            return cls(preimage=None, signatures=[])

        try:
            parsed = HTLCWitness.from_witness(witness)
            return cls(
                preimage=parsed.preimage, signatures=list(parsed.signatures or [])
            )
        except Exception:
            return cls(preimage=None, signatures=[])


class LedgerSpendingConditions:
    def _verify_input_output_spending_conditions(
        self,
        proofs: List[Proof],
        outputs: List[BlindedMessage],
        quote: Optional[str] = None,
    ) -> bool:
        """
        This is the central function for all NUT-10 spending conditions. Any
        swap or melt will give the inputs and outputs to this function.
        This either returns True, if the token has no spending conditions or
        it satisifies them, or it raises an error.
        """
        if self._at_least_one_proof_has_sig_all(proofs):
            # At least one proof has SIG_ALL in it, therefore we delegate all
            # enforcement to SIG_ALL-aware enforcement:
            return self._verify_sigall_spending_conditions(proofs, outputs, quote)
        else:
            # otherwise, check each proof in turn and enforce any conditions
            # such as P2PK and HTLC:
            for proof in proofs:
                self._verify_input_spending_conditions(proof)
            return True

    def _verify_sigall_spending_conditions(
        self,
        proofs: List[Proof],
        outputs: List[BlindedMessage],
        quote: Optional[str] = None,
    ) -> bool:
        """
        Verify grouped spending conditions for a SIG_ALL transaction.

        This function is only called after the mint has already determined that at
        least one input requires `SIG_ALL`.

        It enforces the grouped-input invariants for SIG_ALL:

        - all proofs must represent the same spending condition
        - in practice, that means the same secret kind, `Secret.data`, and `Secret.tags`
        - therefore all grouped proofs must also be `SIG_ALL`

        After those shared invariants are enforced, this function resolves the
        typed secret, derives `SpendingRequirements`, normalizes the first
        proof's witness, and applies the unified spending-requirements verifier.

        This verifier returns `True` on success and raises on failure.
        """

        assert self._at_least_one_proof_has_sig_all(proofs), (
            "_verify_sigall_spending_conditions() called without any SIG_ALL proofs"
        )

        # Raise if the secrets (ignoring nonce) are not identical to each other:

        unique_secret = self._verify_all_secrets_equal_and_return(proofs)

        # The secrets are now known to be identical, and since at least one had
        # SIG_ALL, they all have SIG_ALL.

        # In SIG_ALL, we use only the witness that's in the first proof:

        first_proof = proofs[0]

        # Compute the grouped message that the signing pubkeys are expected to sign:

        if quote is None:
            message_to_sign = sig_all_swap_message(proofs, outputs)
        else:
            message_to_sign = sig_all_melt_message(proofs, outputs, quote)

        # Now split depending on whether the secret kind is P2PK or HTLC:

        if SecretKind(unique_secret.kind) == SecretKind.P2PK:
            secret_lock_p2pk: P2PKSecret = P2PKSecret.from_secret(unique_secret)
            assert secret_lock_p2pk.sigflag == SigFlags.SIG_ALL
            return self._verify_p2pk_or_htlc_spending_requirements(
                self._get_spending_requirements(secret_lock_p2pk),
                WitnessForP2pkOrHtlc.from_p2pk_witness(first_proof.witness),
                message_to_sign,
            )
        elif SecretKind(unique_secret.kind) == SecretKind.HTLC:
            secret_lock_htlc: HTLCSecret = HTLCSecret.from_secret(unique_secret)
            assert secret_lock_htlc.sigflag == SigFlags.SIG_ALL
            return self._verify_p2pk_or_htlc_spending_requirements(
                self._get_spending_requirements(secret_lock_htlc),
                WitnessForP2pkOrHtlc.from_htlc_witness(first_proof.witness),
                message_to_sign,
            )
        else:
            # not a P2PK or HTLC secret
            raise TransactionError("secret kind not supported for SIG_ALL.")

    def _verify_input_spending_conditions(self, proof: Proof) -> bool:
        """
        Verify spending conditions for a single non-SIG_ALL proof.

        This function is used only when the transaction is not being verified in
        grouped `SIG_ALL` mode. In that case, each proof is validated independently
        according to the spending condition encoded in its `secret`.

        Behavior:

        - if `proof.secret` is not a structured spending-condition secret, the proof is
          treated as a plain proof and any witness data is ignored
        - if the secret kind is `P2PK`, verification is delegated to the shared
          P2PK/HTLC spending-requirements verifier
        - if the secret kind is `HTLC`, the HTLC-specific preimage requirements are
          enforced within the shared P2PK/HTLC spending-requirements verifier

        This verifier returns `True` on success and raises on failure.
        """

        try:
            secret = Secret.deserialize(proof.secret)
            logger.trace(f"proof.secret: {proof.secret}")
            logger.trace(f"secret: {secret}")
        except Exception:
            # secret is not a NUT-10 spending condition so we treat it as a
            # plain secret and ignore any witness data.
            return True

        # If we get here, the secret is a NUT-10 secret.

        # P2PK
        if SecretKind(secret.kind) == SecretKind.P2PK:
            p2pk_secret = P2PKSecret.from_secret(secret)
            return self._verify_p2pk_or_htlc_sig_inputs(proof, p2pk_secret)

        # HTLC
        if SecretKind(secret.kind) == SecretKind.HTLC:
            htlc_secret = HTLCSecret.from_secret(secret)
            return self._verify_p2pk_or_htlc_sig_inputs(proof, htlc_secret)

        # no spending condition present, or it's an unsupported 'kind', in which
        # case it's suggested to allow anyone-can-spend:
        #   "If the mint does not support spending conditions or a specific kind
        #    of spending condition, proofs may be treated as a regular
        #    anyone-can-spend tokens."
        # https://github.com/cashubtc/nuts/blob/main/10.md
        return True

    def _at_least_one_proof_has_sig_all(self, proofs: List[Proof]) -> bool:
        """
        Check if any input requires sigall spending condition.
        """
        for proof in proofs:
            if self._proof_has_sig_all(proof):
                return True

        # All proofs have been checked, and there is no SIG_ALL
        return False

    def _proof_has_sig_all(self, proof: Proof) -> bool:
        """
        Check if a single proof encodes a SIG_ALL spending condition.
        """
        try:
            secret = Secret.deserialize(proof.secret)
        except Exception:
            # secret is not a spending condition so we treat is a normal secret
            return False

        if SecretKind(secret.kind) == SecretKind.P2PK:
            return P2PKSecret.from_secret(secret).sigflag == SigFlags.SIG_ALL

        if SecretKind(secret.kind) == SecretKind.HTLC:
            return HTLCSecret.from_secret(secret).sigflag == SigFlags.SIG_ALL

        return False

    def _verify_all_secrets_equal_and_return(self, proofs: List[Proof]) -> Secret:
        """
        Verify that all secrets are equal (kind, data, tags)

        Raise if they are different. If all identical, return that unique Secret
        """
        secrets = set()
        for proof in proofs:
            secrets.add(Secret.deserialize(proof.secret))

        if len(secrets) != 1:
            raise TransactionError("not all secrets are equal.")

        return secrets.pop()

    def _verify_p2pk_or_htlc_sig_inputs(
        self,
        proof: Proof,
        secret: P2PKSecret | HTLCSecret,
    ) -> bool:
        """
        Verify a single non-SIG_ALL P2PK or HTLC input.

        This helper is used only when the transaction is not being validated in
        grouped `SIG_ALL` mode. It computes `SpendingRequirements`, parses the
        appropriate witness type for the secret kind, and delegates the actual
        path enforcement to the shared P2PK/HTLC spending-requirements verifier.
        The signed message is always derived from `proof.secret` in this mode.

        This verifier returns `True` on success and raises on failure.
        """

        message_to_sign = proof.secret

        assert secret.sigflag != SigFlags.SIG_ALL, (
            "SIG_ALL proofs must be verified using a different method."
        )

        requirements = self._get_spending_requirements(secret)
        if SecretKind(secret.kind) == SecretKind.P2PK:
            assert isinstance(secret, P2PKSecret)
            return self._verify_p2pk_or_htlc_spending_requirements(
                requirements,
                WitnessForP2pkOrHtlc.from_p2pk_witness(proof.witness),
                message_to_sign,
            )

        assert isinstance(secret, HTLCSecret)
        return self._verify_p2pk_or_htlc_spending_requirements(
            requirements,
            WitnessForP2pkOrHtlc.from_htlc_witness(proof.witness),
            message_to_sign,
        )

    def _get_spending_requirements(
        self,
        secret: P2PKSecret | HTLCSecret,
    ) -> SpendingRequirements:
        current_time = time.time()
        locktime_passed = secret.locktime is not None and secret.locktime < current_time

        if SecretKind(secret.kind) == SecretKind.P2PK:
            pubkeys = [secret.data] + secret.tags.get_tag_all("pubkeys")
            required_sigs = secret.n_sigs or 1
            preimage_hash = None
        else:
            # HTLC
            preimage_hash = secret.data
            pubkeys = secret.tags.get_tag_all("pubkeys")
            required_sigs = 0 if not pubkeys else secret.n_sigs or 1

        if pubkeys:
            pubkeys = self._validate_pubkeys(pubkeys)

        refund_path = None
        if locktime_passed:
            refund_pubkeys = secret.tags.get_tag_all("refund")
            if refund_pubkeys:
                refund_pubkeys = self._validate_pubkeys(refund_pubkeys)
                refund_path = SpendPath(
                    pubkeys=refund_pubkeys,
                    required_sigs=secret.n_sigs_refund or 1,
                )
            else:
                refund_path = SpendPath(pubkeys=[], required_sigs=0)

        return SpendingRequirements(
            preimage_hash=preimage_hash,  # None, for P2PK
            primary_path=SpendPath(
                pubkeys=pubkeys,
                required_sigs=required_sigs,
            ),
            refund_path=refund_path,
        )

    def _verify_p2pk_or_htlc_spending_requirements(
        self,
        requirements: SpendingRequirements,
        witness: WitnessForP2pkOrHtlc,
        message_to_sign: str,
    ) -> bool:
        # Contract: this verifier returns True on success and raises on failure.
        primary_path_error: Optional[Exception] = None

        # Try the primary path first. Any failure here is remembered and only
        # raised later if the refund path also cannot spend.
        try:
            # For HTLC-like requirements, the primary
            # path additionally requires a matching preimage.
            if requirements.preimage_hash is not None:
                if witness.preimage is None:
                    raise TransactionError("no HTLC preimage provided")
                self._verify_htlc_preimage(requirements.preimage_hash, witness.preimage)

            if self._verify_p2pk_signatures(
                message_to_sign,
                requirements.primary_path.pubkeys,
                witness.signatures,
                requirements.primary_path.required_sigs,
            ):
                logger.trace(
                    "Spending condition satisfied via primary (non-refund) path"
                )
                return True
        except Exception as exc:
            # Primary-path failures do not immediately abort spending, because
            # an expired lock may still be spendable via the refund path.
            primary_path_error = exc

        # If the primary path did not succeed, try the refund path next.
        # The refund_path is only present if the locktime has expired; this
        # is handled when the SpendingRequirements object is constructed.
        if requirements.refund_path:
            try:
                if self._verify_p2pk_signatures(
                    message_to_sign,
                    requirements.refund_path.pubkeys,
                    witness.signatures,
                    requirements.refund_path.required_sigs,
                ):
                    logger.trace("Spending condition satisfied via refund pubkeys.")
                    return True
            except Exception as exc:
                primary_path_error = exc

        # No path succeeded, so surface the best available error.
        if primary_path_error:
            raise primary_path_error

        return True

    def _validate_pubkeys(self, pubkeys: List[str]) -> List[str]:
        # The pubkeys must be distinct on their x-coordinates
        pubkeys = [p.lower() for p in pubkeys]

        if len(set(pubkeys)) != len(pubkeys):
            raise TransactionError("pubkeys must be unique.")

        x_only_pubkeys = [p[2:66] if len(p) in [66, 130] else p for p in pubkeys]
        if len(set(x_only_pubkeys)) != len(x_only_pubkeys):
            raise TransactionError("pubkeys must have unique x-coordinates.")

        return pubkeys

    def _verify_p2pk_signatures(
        self,
        message_to_sign: str,
        pubkeys: List[str],
        signatures: List[str],
        n_sigs_required: int,
    ) -> bool:
        if n_sigs_required < 0:
            raise TransactionError("n_sigs may not be negative.")

        # Count the number of *distinct* pubkeys for which we a valid
        # signature of the message. Return true if that count is at
        # least n_sigs_required
        if n_sigs_required == 0:
            return True

        pubkeys = self._validate_pubkeys(pubkeys)
        signatures = [s.lower() for s in signatures]

        logger.trace(f"pubkeys: {pubkeys}")
        unique_pubkeys = set(pubkeys)

        # verify that signatures are present
        if not signatures:
            # no signature present although secret indicates one
            raise TransactionError("no signatures in proof.")

        # INPUTS: check signatures against pubkey
        # we expect the signature to be on the pubkey (=message) itself

        # check if enough pubkeys or signatures are present
        if len(pubkeys) < n_sigs_required or len(signatures) < n_sigs_required:
            raise TransactionError(
                f"not enough pubkeys ({len(pubkeys)}) or signatures ({len(signatures)}) present for n_sigs ({n_sigs_required})."
            )

        n_pubkeys_with_valid_sigs = 0
        # loop over all unique pubkeys in input
        for pubkey in unique_pubkeys:
            for i, input_sig in enumerate(signatures):
                logger.trace(f"verifying signature {input_sig} by pubkey {pubkey}.")
                logger.trace(f"Message: {message_to_sign}")
                if verify_schnorr_signature(
                    message=message_to_sign.encode("utf-8"),
                    pubkey=PublicKey(bytes.fromhex(pubkey)),
                    signature=bytes.fromhex(input_sig),
                ):
                    n_pubkeys_with_valid_sigs += 1
                    logger.trace(
                        f"signature on input is valid: {input_sig} on {pubkey}."
                    )
                    signatures.pop(i)
                    break

        # check if we have enough valid signatures
        if n_pubkeys_with_valid_sigs < n_sigs_required:
            raise TransactionError(
                f"signature threshold not met. {n_pubkeys_with_valid_sigs} <"
                f" {n_sigs_required}."
            )

        logger.trace(
            f"{n_pubkeys_with_valid_sigs} of {n_sigs_required} valid signatures found."
        )
        logger.trace("p2pk signature on inputs is valid.")

        return True

    def _verify_htlc_preimage(
        self,
        preimage_hash: str,
        preimage: Optional[str],
    ) -> bool:
        if not preimage:
            raise TransactionError("no HTLC preimage provided")

        try:
            if len(preimage) != 64:
                raise TransactionError("HTLC preimage must be 64 characters hex.")
            if sha256(bytes.fromhex(preimage)).digest() != bytes.fromhex(preimage_hash):
                raise TransactionError("HTLC preimage does not match.")
        except ValueError:
            raise TransactionError("invalid preimage for HTLC: not a hex string.")

        return True
