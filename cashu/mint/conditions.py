import hashlib
import time
from typing import List

from loguru import logger

from ..core.base import BlindedMessage, HTLCWitness, Proof
from ..core.crypto.secp import PublicKey
from ..core.errors import (
    TransactionError,
)
from ..core.htlc import HTLCSecret
from ..core.p2pk import (
    P2PKSecret,
    SigFlags,
    verify_p2pk_signature,
)
from ..core.secret import Secret, SecretKind


class LedgerSpendingConditions:
    def _verify_p2pk_spending_conditions(self, proof: Proof, secret: Secret) -> bool:
        """
        Verify P2PK spending condition for a single input.

        We return True:
        - if the secret is not a P2PKSecret spending condition
        - if the locktime has passed and no refund pubkey is present

        We raise an exception:
        - if the pubkeys in the secret are not unique
        - if no signatures are present
        - if the signatures are not unique
        - if n_sigs is not positive
        - if n_sigs is larger than the number of provided signatures
        - if no valid signatures are present
        - if the signature threshold is not met
        """
        if SecretKind(secret.kind) != SecretKind.P2PK:
            # not a P2PK secret
            return True

        p2pk_secret = P2PKSecret.from_secret(secret)

        # extract pubkeys that we require signatures from depending on whether the
        # locktime has passed (refund) or not (pubkeys in secret.data and in tags)
        # This is implemented in get_p2pk_pubkey_from_secret()
        pubkeys = p2pk_secret.get_p2pk_pubkey_from_secret()
        # we will get an empty list if the locktime has passed and no refund pubkey is present
        if not pubkeys:
            return True

        assert len(set(pubkeys)) == len(pubkeys), "pubkeys must be unique."
        logger.trace(f"pubkeys: {pubkeys}")

        # verify that signatures are present
        if not proof.p2pksigs:
            # no signature present although secret indicates one
            logger.error(f"no p2pk signatures in proof: {proof.p2pksigs}")
            raise TransactionError("no p2pk signatures in proof.")

        # we make sure that there are no duplicate signatures
        if len(set(proof.p2pksigs)) != len(proof.p2pksigs):
            raise TransactionError("p2pk signatures must be unique.")

        # we parse the secret as a P2PK commitment
        # assert len(proof.secret.split(":")) == 5, "p2pk secret format invalid."

        # INPUTS: check signatures proof.p2pksigs against pubkey
        # we expect the signature to be on the pubkey (=message) itself
        n_sigs_required = p2pk_secret.n_sigs or 1
        assert n_sigs_required > 0, "n_sigs must be positive."

        # check if enough signatures are present
        assert (
            len(proof.p2pksigs) >= n_sigs_required
        ), f"not enough signatures provided: {len(proof.p2pksigs)} < {n_sigs_required}."

        n_valid_sigs_per_output = 0
        # loop over all signatures in output
        for input_sig in proof.p2pksigs:
            for pubkey in pubkeys:
                logger.trace(f"verifying signature {input_sig} by pubkey {pubkey}.")
                logger.trace(f"Message: {p2pk_secret.serialize().encode('utf-8')}")
                if verify_p2pk_signature(
                    message=p2pk_secret.serialize().encode("utf-8"),
                    pubkey=PublicKey(bytes.fromhex(pubkey), raw=True),
                    signature=bytes.fromhex(input_sig),
                ):
                    n_valid_sigs_per_output += 1
                    logger.trace(
                        f"p2pk signature on input is valid: {input_sig} on {pubkey}."
                    )

        # check if we have enough valid signatures
        assert n_valid_sigs_per_output, "no valid signature provided for input."
        assert n_valid_sigs_per_output >= n_sigs_required, (
            f"signature threshold not met. {n_valid_sigs_per_output} <"
            f" {n_sigs_required}."
        )

        logger.trace(
            f"{n_valid_sigs_per_output} of {n_sigs_required} valid signatures found."
        )
        logger.trace(proof.p2pksigs)
        logger.trace("p2pk signature on inputs is valid.")

        return True

    def _verify_htlc_spending_conditions(self, proof: Proof, secret: Secret) -> bool:
        """
        Verify HTLC spending condition for a single input.

        We return True:
        - if the secret is not a HTLCSecret spending condition

        We first verify the time lock. If the locktime has passed, we require
        a valid signature if a 'refund' pubkey is present. If it isn't present,
        anyone can spend.

        We return True:
        - if 'refund' pubkeys are present and a valid signature is provided for one of them
        We raise an exception:
        - if 'refund' but no valid signature is present


        We then verify the hash lock. We require a valid preimage. We require a valid
        signature if 'pubkeys' are present. If they aren't present, anyone who provides
        a valid preimage can spend.

        We raise an exception:
        - if no preimage is provided
        - if preimage does not match the hash lock in the secret

        We return True:
        - if 'pubkeys' are present and a valid signature is provided for one of them

        We raise an exception:
        - if 'pubkeys' are present but no valid signature is provided
        """

        if SecretKind(secret.kind) != SecretKind.HTLC:
            # not a P2PK secret
            return True
        htlc_secret = HTLCSecret.from_secret(secret)

        # time lock
        # check if locktime is in the past
        if htlc_secret.locktime and htlc_secret.locktime < time.time():
            refund_pubkeys = htlc_secret.tags.get_tag_all("refund")
            if refund_pubkeys:
                assert proof.witness, TransactionError("no HTLC refund signature.")
                signature = HTLCWitness.from_witness(proof.witness).signature
                assert signature, TransactionError("no HTLC refund signature provided")
                for pubkey in refund_pubkeys:
                    if verify_p2pk_signature(
                        message=htlc_secret.serialize().encode("utf-8"),
                        pubkey=PublicKey(bytes.fromhex(pubkey), raw=True),
                        signature=bytes.fromhex(signature),
                    ):
                        # a signature matches
                        return True
                raise TransactionError("HTLC refund signatures did not match.")
            # no pubkeys given in secret, anyone can spend
            return True

        # hash lock
        assert proof.htlcpreimage, TransactionError("no HTLC preimage provided")

        # first we check whether a correct preimage was included
        if not hashlib.sha256(
            bytes.fromhex(proof.htlcpreimage)
        ).digest() == bytes.fromhex(htlc_secret.data):
            raise TransactionError("HTLC preimage does not match.")

        # then we check whether a signature is required
        hashlock_pubkeys = htlc_secret.tags.get_tag_all("pubkeys")
        if hashlock_pubkeys:
            assert proof.witness, TransactionError("no HTLC hash lock signature.")
            signature = HTLCWitness.from_witness(proof.witness).signature
            assert signature, TransactionError("HTLC no hash lock signatures provided.")
            for pubkey in hashlock_pubkeys:
                if verify_p2pk_signature(
                    message=htlc_secret.serialize().encode("utf-8"),
                    pubkey=PublicKey(bytes.fromhex(pubkey), raw=True),
                    signature=bytes.fromhex(signature),
                ):
                    # a signature matches
                    return True
                # none of the pubkeys had a match
                raise TransactionError("HTLC hash lock signatures did not match.")
        # no pubkeys were included, anyone can spend
        return True

    def _verify_input_spending_conditions(self, proof: Proof) -> bool:
        """
        Verify spending conditions:
         Condition: P2PK - Checks if signature in proof.witness is valid for pubkey in proof.secret
         Condition: HTLC - Checks if preimage in proof.witness is valid for hash in proof.secret
        """

        try:
            secret = Secret.deserialize(proof.secret)
            logger.trace(f"proof.secret: {proof.secret}")
            logger.trace(f"secret: {secret}")
        except Exception:
            # secret is not a spending condition so we treat is a normal secret
            return True

        # P2PK
        if SecretKind(secret.kind) == SecretKind.P2PK:
            return self._verify_p2pk_spending_conditions(proof, secret)

        # HTLC
        if SecretKind(secret.kind) == SecretKind.HTLC:
            return self._verify_htlc_spending_conditions(proof, secret)

        # no spending condition present
        return True

    # ------ output spending conditions ------

    def _verify_output_p2pk_spending_conditions(
        self, proofs: List[Proof], outputs: List[BlindedMessage]
    ) -> bool:
        """
        If sigflag==SIG_ALL in proof.secret, check if outputs
        contain valid signatures for pubkeys in proof.secret.

        We return True
        - if not all proof.secret are Secret spending condition
        - if not all secrets are P2PKSecret spending condition
        - if not all signature.sigflag are SIG_ALL

        We raise an exception:
        - if not all pubkeys in all secrets are the same
        - if not all n_sigs in all secrets are the same
        - if not all signatures in all outputs are unique
        - if not all signatures in all outputs are valid
        - if no valid signatures are present
        - if the signature threshold is not met

        We return True if we successfully validated the spending condition.
        """

        try:
            secrets_generic = [Secret.deserialize(p.secret) for p in proofs]
            p2pk_secrets = [
                P2PKSecret.from_secret(secret) for secret in secrets_generic
            ]
        except Exception:
            # secret is not a spending condition so we treat is a normal secret
            return True

        # check if all secrets are P2PK
        # NOTE: This is redundant, because P2PKSecret.from_secret() already checks for the kind
        # Leaving it in for explicitness
        if not all([
            SecretKind(secret.kind) == SecretKind.P2PK for secret in p2pk_secrets
        ]):
            # not all secrets are P2PK
            return True

        # check if all secrets are sigflag==SIG_ALL
        if not all([secret.sigflag == SigFlags.SIG_ALL for secret in p2pk_secrets]):
            # not all secrets have sigflag==SIG_ALL
            return True

        # extract all pubkeys and n_sigs from secrets
        pubkeys_per_proof = [
            secret.get_p2pk_pubkey_from_secret() for secret in p2pk_secrets
        ]
        n_sigs_per_proof = [secret.n_sigs for secret in p2pk_secrets]

        # all pubkeys and n_sigs must be the same
        assert (
            len(set([tuple(pubs_output) for pubs_output in pubkeys_per_proof])) == 1
        ), "pubkeys in all proofs must match."
        assert len(set(n_sigs_per_proof)) == 1, "n_sigs in all proofs must match."

        # TODO: add limit for maximum number of pubkeys

        # validation successful

        pubkeys: List[str] = pubkeys_per_proof[0]
        # if n_sigs is None, we set it to 1
        n_sigs: int = n_sigs_per_proof[0] or 1

        logger.trace(f"pubkeys: {pubkeys}")

        # loop over all outputs and check if the signatures are valid for pubkeys with a threshold of n_sig
        for output in outputs:
            # we expect the signature to be on the pubkey (=message) itself
            p2pksigs = output.p2pksigs
            assert p2pksigs, "no signatures in output."
            # TODO: add limit for maximum number of signatures

            # we check whether any signature is duplicate
            assert len(set(p2pksigs)) == len(
                p2pksigs
            ), "duplicate signatures in output."

            n_valid_sigs_per_output = 0
            # loop over all signatures in output
            for sig in p2pksigs:
                for pubkey in pubkeys:
                    if verify_p2pk_signature(
                        message=output.B_.encode("utf-8"),
                        pubkey=PublicKey(bytes.fromhex(pubkey), raw=True),
                        signature=bytes.fromhex(sig),
                    ):
                        n_valid_sigs_per_output += 1
            assert n_valid_sigs_per_output, "no valid signature provided for output."
            assert (
                n_valid_sigs_per_output >= n_sigs
            ), f"signature threshold not met. {n_valid_sigs_per_output} < {n_sigs}."

            logger.trace(
                f"{n_valid_sigs_per_output} of {n_sigs} valid signatures found."
            )
            logger.trace(p2pksigs)
            logger.trace("p2pk signatures on output is valid.")
        return True

    def _verify_output_spending_conditions(
        self, proofs: List[Proof], outputs: List[BlindedMessage]
    ) -> bool:
        """
        Verify spending conditions:
         Condition: P2PK - If sigflag==SIG_ALL in proof.secret, check if outputs contain valid signatures for pubkeys in proof.secret.
        """

        return self._verify_output_p2pk_spending_conditions(proofs, outputs)
