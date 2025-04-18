import hashlib
import time
from typing import List, Union

from loguru import logger

from ..core.base import BlindedMessage, P2PKWitness, Proof
from ..core.crypto.secp import PublicKey
from ..core.errors import (
    TransactionError,
)
from ..core.htlc import HTLCSecret
from ..core.p2pk import (
    P2PKSecret,
    SigFlags,
    verify_schnorr_signature,
)
from ..core.secret import Secret, SecretKind


class LedgerSpendingConditions:
    def _verify_p2pk_spending_conditions(
        self, proof: Proof, secret: Secret, message_to_sign: str | None = None
    ) -> bool:
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
        if p2pk_secret.sigflag != SigFlags.SIG_INPUTS:
            # not a SIG_INPUTS secret
            return True

        message_to_sign = message_to_sign or proof.secret

        # extract pubkeys that we require signatures from depending on whether the
        # locktime has passed (refund) or not (pubkeys in secret.data and in tags)

        # the pubkey in the data field is the pubkey to use for P2PK
        pubkeys: List[str] = [p2pk_secret.data]

        # get all additional pubkeys from tags for multisig
        pubkeys += p2pk_secret.tags.get_tag_all("pubkeys")

        # check if locktime is passed and if so, only consider refund pubkeys
        now = time.time()
        if p2pk_secret.locktime and p2pk_secret.locktime < now:
            logger.trace(f"p2pk locktime ran out ({p2pk_secret.locktime}<{now}).")
            # If a refund pubkey is present, we demand the signature to be from it
            refund_pubkeys = p2pk_secret.tags.get_tag_all("refund")
            n_sigs_refund = p2pk_secret.n_sigs_refund or 1
            if not refund_pubkeys:
                # no refund pubkey is present, anyone can spend
                return True
            return self._verify_p2pk_signatures(
                message_to_sign,
                refund_pubkeys,
                proof.p2pksigs,
                n_sigs_refund,
            )

        # require signatures from pubkeys
        return self._verify_p2pk_signatures(
            message_to_sign, pubkeys, proof.p2pksigs, p2pk_secret.n_sigs or 1
        )

    def _verify_htlc_spending_conditions(
        self, proof: Proof, secret: Secret, message_to_sign: str | None = None
    ) -> bool:
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
        message_to_sign = message_to_sign or proof.secret

        # time lock
        # check if locktime is in the past
        if htlc_secret.locktime and htlc_secret.locktime < time.time():
            refund_pubkeys = htlc_secret.tags.get_tag_all("refund")
            n_sigs_refund = htlc_secret.n_sigs_refund or 1
            if refund_pubkeys:
                return self._verify_p2pk_signatures(
                    message_to_sign,
                    refund_pubkeys,
                    proof.p2pksigs,
                    n_sigs_refund,
                )
            # no pubkeys given in secret, anyone can spend
            return True

        # hash lock
        assert proof.htlcpreimage, TransactionError("no HTLC preimage provided")

        # verify correct preimage (the hashlock)
        if not hashlib.sha256(
            bytes.fromhex(proof.htlcpreimage)
        ).digest() == bytes.fromhex(htlc_secret.data):
            raise TransactionError("HTLC preimage does not match.")

        # check whether signatures are required
        hashlock_pubkeys = htlc_secret.tags.get_tag_all("pubkeys")
        if hashlock_pubkeys:
            return self._verify_p2pk_signatures(
                message_to_sign,
                hashlock_pubkeys,
                proof.htlcsigs or [],
                htlc_secret.n_sigs or 1,
            )

        # no pubkeys given in secret, anyone can spend
        return True

    def _verify_p2pk_signatures(
        self,
        message_to_sign: str,
        pubkeys: List[str],
        signatures: List[str],
        n_sigs_required: int,
    ) -> bool:
        assert len(set(pubkeys)) == len(pubkeys), "pubkeys must be unique."
        logger.trace(f"pubkeys: {pubkeys}")

        # verify that signatures are present
        if not signatures:
            # no signature present although secret indicates one
            raise TransactionError("no signatures in proof.")

        # we make sure that there are no duplicate signatures
        if len(set(signatures)) != len(signatures):
            raise TransactionError("signatures must be unique.")

        # INPUTS: check signatures against pubkey
        # we expect the signature to be on the pubkey (=message) itself
        n_sigs_required = n_sigs_required or 1
        if not n_sigs_required > 0:
            raise TransactionError("n_sigs must be positive.")

        # check if enough pubkeys or signatures are present
        if len(pubkeys) < n_sigs_required or len(signatures) < n_sigs_required:
            raise TransactionError(
                f"not enough pubkeys ({len(pubkeys)}) or signatures ({len(signatures)}) present for n_sigs ({n_sigs_required})."
            )

        n_pubkeys_with_valid_sigs = 0
        # loop over all pubkeys in input
        for pubkey in pubkeys:
            for input_sig in signatures:
                logger.trace(f"verifying signature {input_sig} by pubkey {pubkey}.")
                logger.trace(f"Message: {message_to_sign}")
                if verify_schnorr_signature(
                    message=message_to_sign.encode("utf-8"),
                    pubkey=PublicKey(bytes.fromhex(pubkey), raw=True),
                    signature=bytes.fromhex(input_sig),
                ):
                    n_pubkeys_with_valid_sigs += 1
                    logger.trace(
                        f"signature on input is valid: {input_sig} on {pubkey}."
                    )
                    break

        # check if we have enough valid signatures
        assert n_pubkeys_with_valid_sigs >= n_sigs_required, (
            f"signature threshold not met. {n_pubkeys_with_valid_sigs} <"
            f" {n_sigs_required}."
        )

        logger.trace(
            f"{n_pubkeys_with_valid_sigs} of {n_sigs_required} valid signatures found."
        )
        logger.trace("p2pk signature on inputs is valid.")

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

    def _inputs_require_sigall(self, proofs: List[Proof]) -> bool:
        """
        Check if any input requires sigall spending condition.
        """
        for proof in proofs:
            try:
                secret = Secret.deserialize(proof.secret)
                try:
                    p2pk_secret = P2PKSecret.from_secret(secret)
                    if p2pk_secret.sigflag == SigFlags.SIG_ALL:
                        return True
                except Exception:
                    pass
                try:
                    htlc_secret = HTLCSecret.from_secret(secret)
                    if htlc_secret.sigflag == SigFlags.SIG_ALL:
                        return True
                except Exception:
                    pass
            except Exception:
                # secret is not a spending condition so we treat is a normal secret
                pass
        return False

    def _verify_all_secrets_equal_and_return(self, proofs: List[Proof]) -> Secret:
        """
        Verify that all secrets are equal (kind, data, tags) and return them
        """
        secrets = set()
        for proof in proofs:
            secrets.add(Secret.deserialize(proof.secret))

        if len(secrets) != 1:
            raise TransactionError("not all secrets are equal.")

        return secrets.pop()

    def _verify_sigall_spending_conditions(
        self, proofs: List[Proof], outputs: List[BlindedMessage]
    ) -> bool:
        """
        If sigflag==SIG_ALL in any proof.secret, perform a signature check on all
        inputs (proofs) and outputs (outputs) together.

        # We return True
        # - if not all proof.secret are Secret spending condition
        # - if not all secrets are P2PKSecret spending condition
        # - if not all signature.sigflag are SIG_ALL

        We raise an exception:
        - if one input is SIG_ALL but not all inputs are SIG_ALL
        - if not all secret kinds are the same
        - if not all pubkeys in all secrets are the same
        - if not all n_sigs in all secrets are the same
        - if not all signatures in all outputs are unique
        - if not all signatures in all outputs are valid
        - if no valid signatures are present
        - if the signature threshold is not met

        We return True if we successfully validated the spending condition.
        """

        if not self._inputs_require_sigall(proofs):
            # no input requires sigall spending condition
            return True

        # verify that all secrets are of the same kind
        try:
            secret = self._verify_all_secrets_equal_and_return(proofs)
        except Exception:
            # not all secrets are equal, we fail
            return False

        # now we can enforce that all inputs are SIG_ALL
        secret_lock: Union[P2PKSecret, HTLCSecret]
        if SecretKind(secret.kind) == SecretKind.P2PK:
            secret_lock = P2PKSecret.from_secret(secret)
        elif SecretKind(secret.kind) == SecretKind.HTLC:
            secret_lock = HTLCSecret.from_secret(secret)
        else:
            # not a P2PK or HTLC secret
            return False

        pubkeys = [secret_lock.data] + secret_lock.tags.get_tag_all("pubkeys")
        n_sigs = secret_lock.n_sigs or 1

        now = time.time()
        if secret_lock.locktime and secret_lock.locktime < now:
            # locktime has passed, we only require the refund pubkeys and n_sigs_refund
            pubkeys = secret_lock.tags.get_tag_all("refund")
            n_sigs = secret_lock.n_sigs_refund or 1

        # if no pubkeys are present, anyone can spend
        if not pubkeys:
            return True

        logger.trace(f"pubkeys: {pubkeys}")

        message_to_sign = "".join([p.secret for p in proofs] + [o.B_ for o in outputs])
        first_proof = proofs[0]
        assert first_proof.witness
        signatures = P2PKWitness.from_witness(first_proof.witness).signatures
        n_valid_sigs = 0
        for p in pubkeys:
            for s in signatures:
                if verify_schnorr_signature(
                    message=message_to_sign.encode("utf-8"),
                    pubkey=PublicKey(bytes.fromhex(p), raw=True),
                    signature=bytes.fromhex(s),
                ):
                    n_valid_sigs += 1
                    break
        if n_valid_sigs < n_sigs:
            raise TransactionError(
                f"signature threshold not met. {n_valid_sigs} < {n_sigs}."
            )
        return True

    def _verify_input_output_spending_conditions(
        self, proofs: List[Proof], outputs: List[BlindedMessage]
    ) -> bool:
        """
        Verify spending conditions:
         Condition: If sigflag==SIG_ALL in any proof.secret of the kind P2PK or HTLC
            we require signatures on all inputs and outputs together.

            Implicitly enforces many other conditions such as all input Secrets
            being the same except for the nonce (see verify_same_kinds_and_return()).
        """

        return self._verify_sigall_spending_conditions(proofs, outputs)
