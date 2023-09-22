import hashlib
import time
from typing import List

from loguru import logger

from ..core.base import (
    BlindedMessage,
    Proof,
)
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
from ..core.script import verify_bitcoin_script
from ..core.secret import Secret, SecretKind


class LedgerSpendingConditions:
    def _verify_input_spending_conditions(self, proof: Proof) -> bool:
        """
        Verify spending conditions:
         Condition: P2SH - Witnesses proof.p2shscript
         Condition: P2PK - Witness: proof.p2pksigs

        """
        # P2SH
        try:
            secret = Secret.deserialize(proof.secret)
            logger.trace(f"proof.secret: {proof.secret}")
            logger.trace(f"secret: {secret}")
        except Exception:
            # secret is not a spending condition so we treat is a normal secret
            return True
        if secret.kind == SecretKind.P2SH:
            p2pk_secret = P2PKSecret.from_secret(secret)
            # check if locktime is in the past
            now = time.time()
            if p2pk_secret.locktime and p2pk_secret.locktime < now:
                logger.trace(f"p2sh locktime ran out ({p2pk_secret.locktime}<{now}).")
                return True
            logger.trace(f"p2sh locktime still active ({p2pk_secret.locktime}>{now}).")

            if (
                proof.p2shscript is None
                or proof.p2shscript.script is None
                or proof.p2shscript.signature is None
            ):
                # no script present although secret indicates one
                raise TransactionError("no script in proof.")

            # execute and verify P2SH
            txin_p2sh_address, valid = verify_bitcoin_script(
                proof.p2shscript.script, proof.p2shscript.signature
            )
            if not valid:
                raise TransactionError("script invalid.")
            # check if secret commits to script address
            assert secret.data == str(txin_p2sh_address), (
                f"secret does not contain correct P2SH address: {secret.data} is not"
                f" {txin_p2sh_address}."
            )
            return True

        # P2PK
        if secret.kind == SecretKind.P2PK:
            p2pk_secret = P2PKSecret.from_secret(secret)
            # check if locktime is in the past
            pubkeys = p2pk_secret.get_p2pk_pubkey_from_secret()
            assert len(set(pubkeys)) == len(pubkeys), "pubkeys must be unique."
            logger.trace(f"pubkeys: {pubkeys}")
            # we will get an empty list if the locktime has passed and no refund pubkey is present
            if not pubkeys:
                return True

            # now we check the signature
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
            assert len(proof.p2pksigs) >= n_sigs_required, (
                f"not enough signatures provided: {len(proof.p2pksigs)} <"
                f" {n_sigs_required}."
            )

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
                            f"p2pk signature on input is valid: {input_sig} on"
                            f" {pubkey}."
                        )
                        continue
                    else:
                        logger.trace(
                            f"p2pk signature on input is invalid: {input_sig} on"
                            f" {pubkey}."
                        )
            # check if we have enough valid signatures
            assert n_valid_sigs_per_output, "no valid signature provided for input."
            assert n_valid_sigs_per_output >= n_sigs_required, (
                f"signature threshold not met. {n_valid_sigs_per_output} <"
                f" {n_sigs_required}."
            )
            logger.trace(
                f"{n_valid_sigs_per_output} of {n_sigs_required} valid signatures"
                " found."
            )

            logger.trace(proof.p2pksigs)
            logger.trace("p2pk signature on inputs is valid.")

            return True

        # HTLC
        if secret.kind == SecretKind.HTLC:
            htlc_secret = HTLCSecret.from_secret(secret)
            # time lock
            # check if locktime is in the past
            if htlc_secret.locktime and htlc_secret.locktime < time.time():
                refund_pubkeys = htlc_secret.tags.get_tag_all("refund")
                if refund_pubkeys:
                    assert proof.htlcsignature, TransactionError(
                        "no HTLC refund signature provided"
                    )
                    for pubkey in refund_pubkeys:
                        if verify_p2pk_signature(
                            message=htlc_secret.serialize().encode("utf-8"),
                            pubkey=PublicKey(bytes.fromhex(pubkey), raw=True),
                            signature=bytes.fromhex(proof.htlcsignature),
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
            if hashlock_pubkeys and not proof.htlcsignature:
                # none of the pubkeys had a match
                raise TransactionError("HTLC no hash lock signatures provided.")
            for pubkey in hashlock_pubkeys:
                if verify_p2pk_signature(
                    message=htlc_secret.serialize().encode("utf-8"),
                    pubkey=PublicKey(bytes.fromhex(pubkey), raw=True),
                    signature=bytes.fromhex(proof.htlcsignature),
                ):
                    # a signature matches
                    return True
            if hashlock_pubkeys:
                # none of the pubkeys had a match
                raise TransactionError("HTLC hash lock signatures did not match.")
            # no pubkeys were included, anyone can spend
            return True

        # no spending condition present
        return True

    def _verify_output_spending_conditions(
        self, proofs: List[Proof], outputs: List[BlindedMessage]
    ) -> bool:
        """
        Verify spending conditions:
         Condition: P2PK - Witness: output.p2pksigs

        """
        # P2SH
        pubkeys_per_proof = []
        n_sigs = []
        for proof in proofs:
            try:
                secret = P2PKSecret.deserialize(proof.secret)
                # get all p2pk pubkeys from secrets
                pubkeys_per_proof.append(secret.get_p2pk_pubkey_from_secret())
                # get signature threshold from secrets
                n_sigs.append(secret.n_sigs)
            except Exception:
                # secret is not a spending condition so we treat is a normal secret
                return True
        # for all proofs all pubkeys must be the same
        assert (
            len(set([tuple(pubs_output) for pubs_output in pubkeys_per_proof])) == 1
        ), "pubkeys in all proofs must match."
        pubkeys = pubkeys_per_proof[0]
        if not pubkeys:
            # no pubkeys present
            return True

        logger.trace(f"pubkeys: {pubkeys}")
        # TODO: add limit for maximum number of pubkeys

        # for all proofs all n_sigs must be the same
        assert len(set(n_sigs)) == 1, "n_sigs in all proofs must match."
        n_sigs_required = n_sigs[0] or 1

        # first we check if all secrets are P2PK
        if not all(
            [Secret.deserialize(p.secret).kind == SecretKind.P2PK for p in proofs]
        ):
            # not all secrets are P2PK
            return True

        # now we check if any of the secrets has sigflag==SIG_ALL
        if not any(
            [
                P2PKSecret.deserialize(p.secret).sigflag == SigFlags.SIG_ALL
                for p in proofs
            ]
        ):
            # no secret has sigflag==SIG_ALL
            return True

        # loop over all outputs and check if the signatures are valid for pubkeys with a threshold of n_sig
        for output in outputs:
            # we expect the signature to be on the pubkey (=message) itself
            assert output.p2pksigs, "no signatures in output."
            # TODO: add limit for maximum number of signatures

            # we check whether any signature is duplicate
            assert len(set(output.p2pksigs)) == len(
                output.p2pksigs
            ), "duplicate signatures in output."

            n_valid_sigs_per_output = 0
            # loop over all signatures in output
            for output_sig in output.p2pksigs:
                for pubkey in pubkeys:
                    if verify_p2pk_signature(
                        message=output.B_.encode("utf-8"),
                        pubkey=PublicKey(bytes.fromhex(pubkey), raw=True),
                        signature=bytes.fromhex(output_sig),
                    ):
                        n_valid_sigs_per_output += 1
            assert n_valid_sigs_per_output, "no valid signature provided for output."
            assert n_valid_sigs_per_output >= n_sigs_required, (
                f"signature threshold not met. {n_valid_sigs_per_output} <"
                f" {n_sigs_required}."
            )
            logger.trace(
                f"{n_valid_sigs_per_output} of {n_sigs_required} valid signatures"
                " found."
            )
            logger.trace(output.p2pksigs)
            logger.trace("p2pk signatures on output is valid.")

        return True
