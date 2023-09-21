import asyncio
import math
import time
from typing import Dict, List, Literal, Optional, Set, Tuple, Union

from loguru import logger

from ..core import bolt11
from ..core.base import (
    BlindedMessage,
    BlindedSignature,
    Invoice,
    MintKeyset,
    MintKeysets,
    Proof,
)
from ..core.crypto import b_dhke
from ..core.crypto.keys import derive_pubkey, random_hash
from ..core.crypto.secp import PublicKey
from ..core.db import Connection, Database
from ..core.errors import (
    InvoiceNotPaidError,
    KeysetError,
    KeysetNotFoundError,
    LightningError,
    NoSecretInProofsError,
    NotAllowedError,
    SecretTooLongError,
    TokenAlreadySpentError,
    TransactionError,
)
from ..core.helpers import fee_reserve, sum_proofs
from ..core.p2pk import (
    P2PKSecret,
    Secret,
    SecretKind,
    SigFlags,
    verify_p2pk_signature,
)
from ..core.script import verify_bitcoin_script
from ..core.settings import settings
from ..core.split import amount_split
from ..lightning.base import Wallet
from ..mint.crud import LedgerCrud


class Ledger:
    locks: Dict[str, asyncio.Lock] = {}  # holds multiprocessing locks
    proofs_pending_lock: asyncio.Lock = (
        asyncio.Lock()
    )  # holds locks for proofs_pending database

    def __init__(
        self,
        db: Database,
        seed: str,
        lightning: Wallet,
        derivation_path="",
        crud=LedgerCrud,
    ):
        self.proofs_used: Set[str] = set()
        self.master_key = seed
        self.derivation_path = derivation_path

        self.db = db
        self.crud = crud
        self.lightning = lightning
        self.pubkey = derive_pubkey(self.master_key)
        self.keysets = MintKeysets([])

    async def load_used_proofs(self):
        """Load all used proofs from database."""
        logger.trace("crud: loading used proofs")
        proofs_used = await self.crud.get_proofs_used(db=self.db)
        logger.trace(f"crud: loaded {len(proofs_used)} used proofs")
        self.proofs_used = set(proofs_used)

    async def load_keyset(self, derivation_path, autosave=True):
        """Load the keyset for a derivation path if it already exists. If not generate new one and store in the db.

        Args:
            derivation_path (_type_): Derivation path from which the keyset is generated.
            autosave (bool, optional): Store newly-generated keyset if not already in database. Defaults to True.

        Returns:
            MintKeyset: Keyset
        """
        keyset = MintKeyset(
            seed=self.master_key,
            derivation_path=derivation_path,
            version=settings.version,
        )
        # load the keyest from db
        logger.trace(f"crud: loading keyset for {derivation_path}")
        tmp_keyset_local: List[MintKeyset] = await self.crud.get_keyset(
            derivation_path=derivation_path, db=self.db
        )
        logger.trace(f"crud: loaded {len(tmp_keyset_local)} keysets")
        if tmp_keyset_local:
            # we have a keyset for this derivation path
            keyset = tmp_keyset_local[0]
            # we need to initialize it
            keyset.generate_keys(self.master_key)

        else:
            # no keyset for this derivation path yet
            # we generate a new keyset
            logger.debug(f"Generating new keyset {keyset.id}.")
            keyset = MintKeyset(
                seed=self.master_key,
                derivation_path=derivation_path,
                version=settings.version,
            )
            if autosave:
                logger.debug(f"crud: storing new keyset {keyset.id}.")
                await self.crud.store_keyset(keyset=keyset, db=self.db)
                logger.trace(f"crud: stored new keyset {keyset.id}.")

        # store the new keyset in the current keysets
        if keyset.id:
            self.keysets.keysets[keyset.id] = keyset
        logger.debug(f"Loaded keyset {keyset.id}.")
        return keyset

    async def init_keysets(self, autosave=True):
        """Initializes all keysets of the mint from the db. Loads all past keysets and generate their keys. Then load the current keyset.

        Args:
            autosave (bool, optional): Whether the current keyset should be saved if it is
            not in the database yet. Will be passed to `self.load_keyset` where it is
            generated from `self.derivation_path`. Defaults to True.
        """
        # load all past keysets from db
        logger.trace("crud: loading keysets")
        tmp_keysets: List[MintKeyset] = await self.crud.get_keyset(db=self.db)
        logger.trace(f"crud: loaded {len(tmp_keysets)} keysets")
        # add keysets from db to current keysets
        for k in tmp_keysets:
            if k.id and k.id not in self.keysets.keysets:
                self.keysets.keysets[k.id] = k

        # generate keys for all keysets in the database
        for _, v in self.keysets.keysets.items():
            # we already generated the keys for this keyset
            if v.id and v.public_keys and len(v.public_keys):
                continue
            logger.debug(f"Generating keys for keyset {v.id}")
            v.generate_keys(self.master_key)

        logger.debug(
            f"Initialized {len(self.keysets.keysets)} keysets from the database."
        )
        # load the current keyset
        self.keyset = await self.load_keyset(self.derivation_path, autosave)

    async def _generate_promises(
        self, B_s: List[BlindedMessage], keyset: Optional[MintKeyset] = None
    ) -> list[BlindedSignature]:
        """Generates promises that sum to the given amount.

        Args:
            B_s (List[BlindedMessage]): _description_
            keyset (Optional[MintKeyset], optional): _description_. Defaults to None.

        Returns:
            list[BlindedSignature]: _description_
        """
        return [
            await self._generate_promise(
                b.amount, PublicKey(bytes.fromhex(b.B_), raw=True), keyset
            )
            for b in B_s
        ]

    async def _generate_promise(
        self, amount: int, B_: PublicKey, keyset: Optional[MintKeyset] = None
    ) -> BlindedSignature:
        """Generates a promise (Blind signature) for given amount and returns a pair (amount, C').

        Args:
            amount (int): Amount of the promise.
            B_ (PublicKey): Blinded secret (point on curve)
            keyset (Optional[MintKeyset], optional): Which keyset to use. Private keys will be taken from this keyset. Defaults to None.

        Returns:
            BlindedSignature: Generated promise.
        """
        keyset = keyset if keyset else self.keyset
        logger.trace(f"Generating promise with keyset {keyset.id}.")
        private_key_amount = keyset.private_keys[amount]
        C_ = b_dhke.step2_bob(B_, private_key_amount)
        logger.trace(f"crud: _generate_promise storing promise for {amount}")
        await self.crud.store_promise(
            amount=amount,
            B_=B_.serialize().hex(),
            C_=C_.serialize().hex(),
            id=keyset.id,
            db=self.db,
        )
        logger.trace(f"crud: _generate_promise stored promise for {amount}")
        return BlindedSignature(id=keyset.id, amount=amount, C_=C_.serialize().hex())

    def _check_spendable(self, proof: Proof):
        """Checks whether the proof was already spent."""
        return proof.secret not in self.proofs_used

    async def _check_pending(self, proofs: List[Proof]):
        """Checks whether the proof is still pending."""
        proofs_pending = await self.crud.get_proofs_pending(db=self.db)
        pending_secrets = [pp.secret for pp in proofs_pending]
        pending_states = [
            True if p.secret in pending_secrets else False for p in proofs
        ]
        return pending_states

    def _verify_secret_criteria(self, proof: Proof) -> Literal[True]:
        """Verifies that a secret is present and is not too long (DOS prevention)."""
        if proof.secret is None or proof.secret == "":
            raise NoSecretInProofsError()
        if len(proof.secret) > 512:
            raise SecretTooLongError()
        return True

    def _verify_proof_bdhke(self, proof: Proof):
        """Verifies that the proof of promise was issued by this ledger."""
        if not self._check_spendable(proof):
            raise TokenAlreadySpentError()
        # if no keyset id is given in proof, assume the current one
        if not proof.id:
            private_key_amount = self.keyset.private_keys[proof.amount]
        else:
            assert proof.id in self.keysets.keysets, f"keyset {proof.id} unknown"
            logger.trace(
                f"Validating proof with keyset {self.keysets.keysets[proof.id].id}."
            )
            # use the appropriate active keyset for this proof.id
            private_key_amount = self.keysets.keysets[proof.id].private_keys[
                proof.amount
            ]

        C = PublicKey(bytes.fromhex(proof.C), raw=True)
        return b_dhke.verify(private_key_amount, C, proof.secret)

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

        # no spending contition
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

    def _verify_input_output_amounts(
        self, inputs: List[Proof], outputs: List[BlindedMessage]
    ) -> bool:
        """Verifies that inputs have at least the same amount as outputs"""
        input_amount = sum([p.amount for p in inputs])
        output_amount = sum([o.amount for o in outputs])
        return input_amount >= output_amount

    def _verify_no_duplicate_proofs(self, proofs: List[Proof]) -> bool:
        secrets = [p.secret for p in proofs]
        if len(secrets) != len(list(set(secrets))):
            return False
        return True

    def _verify_no_duplicate_outputs(self, outputs: List[BlindedMessage]) -> bool:
        B_s = [od.B_ for od in outputs]
        if len(B_s) != len(list(set(B_s))):
            return False
        return True

    def _verify_amount(self, amount: int) -> int:
        """Any amount used should be a positive integer not larger than 2^MAX_ORDER."""
        valid = (
            isinstance(amount, int) and amount > 0 and amount < 2**settings.max_order
        )
        logger.trace(f"Verifying amount {amount} is valid: {valid}")
        if not valid:
            raise NotAllowedError("invalid amount: " + str(amount))
        return amount

    def _verify_equation_balanced(
        self,
        proofs: List[Proof],
        outs: Union[List[BlindedSignature], List[BlindedMessage]],
    ) -> None:
        """Verify that Σinputs - Σoutputs = 0.
        Outputs can be BlindedSignature or BlindedMessage.
        """
        sum_inputs = sum(self._verify_amount(p.amount) for p in proofs)
        sum_outputs = sum(self._verify_amount(p.amount) for p in outs)
        assert (
            sum_outputs - sum_inputs == 0
        ), "inputs do not have same amount as outputs"

    async def _request_lightning_invoice(self, amount: int):
        """Generate a Lightning invoice using the funding source backend.

        Args:
            amount (int): Amount of invoice (in Satoshis)

        Raises:
            Exception: Error with funding source.

        Returns:
            Tuple[str, str]: Bolt11 invoice and payment hash (for lookup)
        """
        logger.trace(
            "_request_lightning_invoice: Requesting Lightning invoice for"
            f" {amount} satoshis."
        )
        error, balance = await self.lightning.status()
        logger.trace(f"_request_lightning_invoice: Lightning wallet balance: {balance}")
        if error:
            raise LightningError(f"Lightning wallet not responding: {error}")
        (
            ok,
            checking_id,
            payment_request,
            error_message,
        ) = await self.lightning.create_invoice(amount, "Cashu deposit")
        logger.trace(
            f"_request_lightning_invoice: Lightning invoice: {payment_request}"
        )
        return payment_request, checking_id

    async def _check_lightning_invoice(
        self, amount: int, hash: str, conn: Optional[Connection] = None
    ) -> Literal[True]:
        """Checks with the Lightning backend whether an invoice stored with `hash` was paid.

        Args:
            amount (int): Amount of the outputs the wallet wants in return (in Satoshis).
            hash (str): Hash to look up Lightning invoice by.

        Raises:
            Exception: Invoice not found.
            Exception: Tokens for invoice already issued.
            Exception: Amount larger than invoice amount.
            Exception: Invoice not paid yet
            e: Update database and pass through error.

        Returns:
            bool: True if invoice has been paid, else False
        """
        logger.trace(f"crud: _check_lightning_invoice: checking invoice {hash}")
        invoice: Union[Invoice, None] = await self.crud.get_lightning_invoice(
            hash=hash, db=self.db, conn=conn
        )
        logger.trace(f"crud: _check_lightning_invoice: invoice: {invoice}")
        if invoice is None:
            raise LightningError("invoice not found.")
        if invoice.issued:
            raise LightningError("tokens already issued for this invoice.")
        assert invoice.payment_hash, "invoice has no payment hash."

        # set this invoice as issued
        logger.trace(f"crud: setting invoice {invoice.payment_hash} as issued")
        await self.crud.update_lightning_invoice(
            hash=hash, issued=True, db=self.db, conn=conn
        )
        logger.trace(f"crud: invoice {invoice.payment_hash} set as issued")

        try:
            if amount > invoice.amount:
                raise LightningError(
                    f"requested amount too high: {amount}. Invoice amount:"
                    f" {invoice.amount}"
                )
            logger.trace(
                f"_check_lightning_invoice: checking invoice {invoice.payment_hash}"
            )
            status = await self.lightning.get_invoice_status(invoice.payment_hash)
            logger.trace(
                f"_check_lightning_invoice: invoice {invoice.payment_hash} status:"
                f" {status}"
            )
            if status.paid:
                return status.paid
            else:
                raise InvoiceNotPaidError()
        except Exception as e:
            # unset issued
            logger.trace(f"crud: unsetting invoice {invoice.payment_hash} as issued")
            await self.crud.update_lightning_invoice(
                hash=hash, issued=False, db=self.db, conn=conn
            )
            logger.trace(f"crud: invoice {invoice.payment_hash} unset as issued")
            raise e

    async def _pay_lightning_invoice(self, invoice: str, fee_limit_msat: int):
        """Pays a Lightning invoice via the funding source backend.

        Args:
            invoice (str): Bolt11 Lightning invoice
            fee_limit_msat (int): Maximum fee reserve for payment (in Millisatoshi)

        Raises:
            Exception: Funding source error.

        Returns:
            Tuple[bool, string, int]: Returns payment status, preimage of invoice, paid fees (in Millisatoshi)
        """
        logger.trace(f"_pay_lightning_invoice: paying Lightning invoice {invoice}")
        error, balance = await self.lightning.status()
        logger.trace(f"_pay_lightning_invoice: Lightning wallet balance: {balance}")
        if error:
            raise LightningError(f"Lightning wallet not responding: {error}")
        (
            ok,
            checking_id,
            fee_msat,
            preimage,
            error_message,
        ) = await self.lightning.pay_invoice(invoice, fee_limit_msat=fee_limit_msat)
        logger.trace(f"_pay_lightning_invoice: Lightning payment status: {ok}")
        # make sure that fee is positive
        fee_msat = abs(fee_msat) if fee_msat else fee_msat
        return ok, preimage, fee_msat

    async def _invalidate_proofs(self, proofs: List[Proof]):
        """Adds secrets of proofs to the list of known secrets and stores them in the db.
        Removes proofs from pending table. This is executed if the ecash has been redeemed.

        Args:
            proofs (List[Proof]): Proofs to add to known secret table.
        """
        # Mark proofs as used and prepare new promises
        proof_msgs = set([p.secret for p in proofs])
        self.proofs_used |= proof_msgs
        # store in db
        logger.trace("crud: storing proofs")
        for p in proofs:
            await self.crud.invalidate_proof(proof=p, db=self.db)
        logger.trace("crud: stored proofs")

    async def _set_proofs_pending(
        self, proofs: List[Proof], conn: Optional[Connection] = None
    ):
        """If none of the proofs is in the pending table (_validate_proofs_pending), adds proofs to
        the list of pending proofs or removes them. Used as a mutex for proofs.

        Args:
            proofs (List[Proof]): Proofs to add to pending table.

        Raises:
            Exception: At least one proof already in pending table.
        """
        # first we check whether these proofs are pending aready
        async with self.proofs_pending_lock:
            await self._validate_proofs_pending(proofs, conn)
            for p in proofs:
                try:
                    logger.trace(
                        f"crud: _set_proofs_pending setting proof {p.secret} as pending"
                    )
                    await self.crud.set_proof_pending(proof=p, db=self.db, conn=conn)
                    logger.trace(
                        f"crud: _set_proofs_pending proof {p.secret} set as pending"
                    )
                except Exception:
                    raise TransactionError("proofs already pending.")

    async def _unset_proofs_pending(
        self, proofs: List[Proof], conn: Optional[Connection] = None
    ):
        """Deletes proofs from pending table.

        Args:
            proofs (List[Proof]): Proofs to delete.
        """
        # we try: except: this block in order to avoid that any errors here
        # could block the _invalidate_proofs() call that happens afterwards.
        async with self.proofs_pending_lock:
            try:
                for p in proofs:
                    logger.trace(
                        f"crud: _unset_proofs_pending unsetting proof {p.secret} as"
                        " pending"
                    )
                    await self.crud.unset_proof_pending(proof=p, db=self.db, conn=conn)
                    logger.trace(
                        f"crud: _unset_proofs_pending proof {p.secret} unset as pending"
                    )
            except Exception as e:
                print(e)
                pass

    async def _validate_proofs_pending(
        self, proofs: List[Proof], conn: Optional[Connection] = None
    ):
        """Checks if any of the provided proofs is in the pending proofs table.

        Args:
            proofs (List[Proof]): Proofs to check.

        Raises:
            Exception: At least one of the proofs is in the pending table.
        """
        logger.trace("crud: _validate_proofs_pending validating proofs")
        proofs_pending = await self.crud.get_proofs_pending(db=self.db, conn=conn)
        logger.trace("crud: _validate_proofs_pending got proofs pending")
        for p in proofs:
            for pp in proofs_pending:
                if p.secret == pp.secret:
                    raise TransactionError("proofs are pending.")

    async def _verify_proofs_and_outputs(
        self, proofs: List[Proof], outputs: Optional[List[BlindedMessage]] = None
    ):
        """Checks all proofs and outputs for validity.

        Args:
            proofs (List[Proof]): List of proofs to check.
            outputs (Optional[List[BlindedMessage]], optional): List of outputs to check.
            Must be provided for /split but not for /melt. Defaults to None.

        Raises:
            Exception: Scripts did not validate.
            Exception: Criteria for provided secrets not met.
            Exception: Duplicate proofs provided.
            Exception: BDHKE verification failed.
        """
        # Verify inputs

        # Verify secret criteria
        if not all([self._verify_secret_criteria(p) for p in proofs]):
            raise TransactionError("secrets do not match criteria.")
        # verify that only unique proofs were used
        if not self._verify_no_duplicate_proofs(proofs):
            raise TransactionError("duplicate proofs.")
        # Verify input spending conditions
        if not all([self._verify_input_spending_conditions(p) for p in proofs]):
            raise TransactionError("validation of input spending conditions failed.")
        # Verify ecash signatures
        if not all([self._verify_proof_bdhke(p) for p in proofs]):
            raise TransactionError("could not verify proofs.")

        if not outputs:
            return

        # Verify outputs

        # verify that only unique outputs were used
        if not self._verify_no_duplicate_outputs(outputs):
            raise TransactionError("duplicate promises.")
        if not self._verify_input_output_amounts(proofs, outputs):
            raise TransactionError("input amounts less than output.")
        # Verify output spending conditions
        if outputs and not self._verify_output_spending_conditions(proofs, outputs):
            raise TransactionError("validation of output spending conditions failed.")

    async def _generate_change_promises(
        self,
        total_provided: int,
        invoice_amount: int,
        ln_fee_msat: int,
        outputs: Optional[List[BlindedMessage]],
        keyset: Optional[MintKeyset] = None,
    ):
        """Generates a set of new promises (blinded signatures) from a set of blank outputs
        (outputs with no or ignored amount) by looking at the difference between the Lightning
        fee reserve provided by the wallet and the actual Lightning fee paid by the mint.

        If there is a positive difference, produces maximum `n_return_outputs` new outputs
        with values close or equal to the fee difference. If the given number of `outputs` matches
        the equation defined in NUT-08, we can be sure to return the overpaid fee perfectly.
        Otherwise, a smaller amount will be returned.

        Args:
            total_provided (int): Amount of the proofs provided by the wallet.
            invoice_amount (int): Amount of the invoice to be paid.
            ln_fee_msat (int): Actually paid Lightning network fees.
            outputs (Optional[List[BlindedMessage]]): Outputs to sign for returning the overpaid fees.

        Raises:
            Exception: Output validation failed.

        Returns:
            List[BlindedSignature]: Signatures on the outputs.
        """
        # we make sure that the fee is positive
        ln_fee_msat = abs(ln_fee_msat)

        ln_fee_sat = math.ceil(ln_fee_msat / 1000)
        user_paid_fee_sat = total_provided - invoice_amount
        overpaid_fee_sat = user_paid_fee_sat - ln_fee_sat
        logger.debug(
            f"Lightning fee was: {ln_fee_sat}. User paid: {user_paid_fee_sat}. "
            f"Returning difference: {overpaid_fee_sat}."
        )

        if overpaid_fee_sat > 0 and outputs is not None:
            return_amounts = amount_split(overpaid_fee_sat)

            # We return at most as many outputs as were provided or as many as are
            # required to pay back the overpaid fee.
            n_return_outputs = min(len(outputs), len(return_amounts))

            # we only need as many outputs as we have change to return
            outputs = outputs[:n_return_outputs]
            # we sort the return_amounts in descending order so we only
            # take the largest values in the next step
            return_amounts_sorted = sorted(return_amounts, reverse=True)
            # we need to imprint these amounts into the blanket outputs
            for i in range(len(outputs)):
                outputs[i].amount = return_amounts_sorted[i]  # type: ignore
            if not self._verify_no_duplicate_outputs(outputs):
                raise TransactionError("duplicate promises.")
            return_promises = await self._generate_promises(outputs, keyset)
            return return_promises
        else:
            return []

    # Public methods
    def get_keyset(self, keyset_id: Optional[str] = None):
        """Returns a dictionary of hex public keys of a specific keyset for each supported amount"""
        if keyset_id and keyset_id not in self.keysets.keysets:
            raise KeysetNotFoundError()
        keyset = self.keysets.keysets[keyset_id] if keyset_id else self.keyset
        assert keyset.public_keys, KeysetError("no public keys for this keyset")
        return {a: p.serialize().hex() for a, p in keyset.public_keys.items()}

    async def request_mint(self, amount: int):
        """Returns Lightning invoice and stores it in the db.

        Args:
            amount (int): Amount of the mint request in Satoshis.

        Raises:
            Exception: Invoice creation failed.

        Returns:
            Tuple[str, str]: Bolt11 invoice and a hash (for looking it up later)
        """
        logger.trace("called request_mint")
        if settings.mint_max_peg_in and amount > settings.mint_max_peg_in:
            raise NotAllowedError(
                f"Maximum mint amount is {settings.mint_max_peg_in} sat."
            )
        if settings.mint_peg_out_only:
            raise NotAllowedError("Mint does not allow minting new tokens.")

        logger.trace(f"requesting invoice for {amount} satoshis")
        payment_request, payment_hash = await self._request_lightning_invoice(amount)
        logger.trace(f"got invoice {payment_request} with hash {payment_hash}")
        assert payment_request and payment_hash, LightningError(
            "could not fetch invoice from Lightning backend"
        )

        invoice = Invoice(
            amount=amount,
            hash=random_hash(),
            pr=payment_request,
            payment_hash=payment_hash,  # what we got from the backend
            issued=False,
        )
        logger.trace(f"crud: storing invoice {invoice.hash} in db")
        await self.crud.store_lightning_invoice(invoice=invoice, db=self.db)
        logger.trace(f"crud: stored invoice {invoice.hash} in db")
        return payment_request, invoice.hash

    async def mint(
        self,
        B_s: List[BlindedMessage],
        hash: Optional[str] = None,
        keyset: Optional[MintKeyset] = None,
    ):
        """Mints a promise for coins for B_.

        Args:
            B_s (List[BlindedMessage]): Outputs (blinded messages) to sign.
            hash (Optional[str], optional): Hash of (paid) Lightning invoice. Defaults to None.
            keyset (Optional[MintKeyset], optional): Keyset to use. If not provided, uses active keyset. Defaults to None.

        Raises:
            Exception: Lightning invvoice is not paid.
            Exception: Lightning is turned on but no payment hash is provided.
            Exception: Something went wrong with the invoice check.
            Exception: Amount too large.

        Returns:
            List[BlindedSignature]: Signatures on the outputs.
        """
        logger.trace("called mint")
        amounts = [b.amount for b in B_s]
        amount = sum(amounts)

        if settings.lightning:
            if not hash:
                raise NotAllowedError("no hash provided.")
            self.locks[hash] = (
                self.locks.get(hash) or asyncio.Lock()
            )  # create a new lock if it doesn't exist
            async with self.locks[hash]:
                # will raise an exception if the invoice is not paid or tokens are already issued
                await self._check_lightning_invoice(amount, hash)
            del self.locks[hash]

        for amount in amounts:
            if amount not in [2**i for i in range(settings.max_order)]:
                raise NotAllowedError(
                    f"Can only mint amounts with 2^n up to {2**settings.max_order}."
                )

        promises = await self._generate_promises(B_s, keyset)
        logger.trace("generated promises")
        return promises

    async def melt(
        self, proofs: List[Proof], invoice: str, outputs: Optional[List[BlindedMessage]]
    ):
        """Invalidates proofs and pays a Lightning invoice.

        Args:
            proofs (List[Proof]): Proofs provided for paying the Lightning invoice
            invoice (str): bolt11 Lightning invoice.
            outputs (Optional[List[BlindedMessage]]): Blank outputs for returning overpaid fees to the wallet.

        Raises:
            e: Lightning payment unsuccessful

        Returns:
            List[BlindedMessage]: Signed outputs for returning overpaid fees to wallet.
        """

        logger.trace("melt called")

        await self._set_proofs_pending(proofs)

        try:
            await self._verify_proofs_and_outputs(proofs)
            logger.trace("verified proofs")

            total_provided = sum_proofs(proofs)
            invoice_obj = bolt11.decode(invoice)
            invoice_amount = math.ceil(invoice_obj.amount_msat / 1000)
            if settings.mint_max_peg_out and invoice_amount > settings.mint_max_peg_out:
                raise NotAllowedError(
                    f"Maximum melt amount is {settings.mint_max_peg_out} sat."
                )
            fees_msat = await self.check_fees(invoice)
            assert (
                total_provided >= invoice_amount + fees_msat / 1000
            ), TransactionError("provided proofs not enough for Lightning payment.")

            # promises to return for overpaid fees
            return_promises: List[BlindedSignature] = []

            if settings.lightning:
                logger.trace("paying lightning invoice")
                status, preimage, fee_msat = await self._pay_lightning_invoice(
                    invoice, fees_msat
                )
                logger.trace("paid lightning invoice")
            else:
                status, preimage, fee_msat = True, "preimage", 0

            logger.trace(
                f"status: {status}, preimage: {preimage}, fee_msat: {fee_msat}"
            )

            if status:
                logger.trace("invalidating proofs")
                await self._invalidate_proofs(proofs)
                logger.trace("invalidated proofs")
                # prepare change to compensate wallet for overpaid fees
                assert fee_msat is not None, TransactionError("fees not valid")
                if outputs:
                    return_promises = await self._generate_change_promises(
                        total_provided=total_provided,
                        invoice_amount=invoice_amount,
                        ln_fee_msat=fee_msat,
                        outputs=outputs,
                    )
            else:
                logger.trace("lightning payment unsuccessful")
                raise LightningError("Lightning payment unsuccessful.")

        except Exception as e:
            logger.trace(f"exception: {e}")
            raise e
        finally:
            # delete proofs from pending list
            await self._unset_proofs_pending(proofs)

        return status, preimage, return_promises

    async def check_proof_state(
        self, proofs: List[Proof]
    ) -> Tuple[List[bool], List[bool]]:
        """Checks if provided proofs are spend or are pending.
        Used by wallets to check if their proofs have been redeemed by a receiver or they are still in-flight in a transaction.

        Returns two lists that are in the same order as the provided proofs. Wallet must match the list
        to the proofs they have provided in order to figure out which proof is spendable or pending
        and which isn't.

        Args:
            proofs (List[Proof]): List of proofs to check.

        Returns:
            List[bool]: List of which proof is still spendable (True if still spendable, else False)
            List[bool]: List of which proof are pending (True if pending, else False)
        """
        spendable = [self._check_spendable(p) for p in proofs]
        pending = await self._check_pending(proofs)
        return spendable, pending

    async def check_fees(self, pr: str):
        """Returns the fee reserve (in sat) that a wallet must add to its proofs
        in order to pay a Lightning invoice.

        Args:
            pr (str): Bolt11 encoded payment request. Lightning invoice.

        Returns:
            int: Fee in Satoshis.
        """
        # hack: check if it's internal, if it exists, it will return paid = False,
        # if id does not exist (not internal), it returns paid = None
        if settings.lightning:
            decoded_invoice = bolt11.decode(pr)
            amount = math.ceil(decoded_invoice.amount_msat / 1000)
            logger.trace(
                "check_fees: checking lightning invoice:"
                f" {decoded_invoice.payment_hash}"
            )
            paid = await self.lightning.get_invoice_status(decoded_invoice.payment_hash)
            logger.trace(f"check_fees: paid: {paid}")
            internal = paid.paid is False
        else:
            amount = 0
            internal = True
        fees_msat = fee_reserve(amount * 1000, internal)
        fee_sat = math.ceil(fees_msat / 1000)
        return fee_sat

    async def split(
        self,
        *,
        proofs: List[Proof],
        outputs: List[BlindedMessage],
        keyset: Optional[MintKeyset] = None,
        amount: Optional[int] = None,  # backwards compatibility < 0.13.0
    ):
        """Consumes proofs and prepares new promises based on the amount split. Used for splitting tokens
        Before sending or for redeeming tokens for new ones that have been received by another wallet.

        Args:
            proofs (List[Proof]): Proofs to be invalidated for the split.
            amount (int): Amount at which the split should happen.
            outputs (List[BlindedMessage]): New outputs that should be signed in return.
            keyset (Optional[MintKeyset], optional): Keyset to use. Uses default keyset if not given. Defaults to None.

        Raises:
            Exception: Validation of proofs or outputs failed

        Returns:
            Tuple[List[BlindSignature],List[BlindSignature]]: Promises on both sides of the split.
        """
        logger.trace("split called")

        await self._set_proofs_pending(proofs)

        total_amount = sum_proofs(proofs)

        try:
            logger.trace("verifying _verify_split_amount")
            # verify that amount is kosher
            self._verify_amount(total_amount)

            # verify overspending attempt
            self._verify_equation_balanced(proofs, outputs)

            logger.trace("verifying proofs: _verify_proofs_and_outputs")
            await self._verify_proofs_and_outputs(proofs, outputs)
            logger.trace("verified proofs and outputs")
            # Mark proofs as used and prepare new promises
            logger.trace("invalidating proofs")
            await self._invalidate_proofs(proofs)
            logger.trace("invalidated proofs")
        except Exception as e:
            logger.trace(f"split failed: {e}")
            raise e
        finally:
            # delete proofs from pending list
            await self._unset_proofs_pending(proofs)

        # BEGIN backwards compatibility < 0.13.0
        if amount is not None:
            logger.debug(
                "Split: Client provided `amount` - backwards compatibility response pre"
                " 0.13.0"
            )
            # split outputs according to amount
            total = sum_proofs(proofs)
            if amount > total:
                raise Exception("split amount is higher than the total sum.")
            outs_fst = amount_split(total - amount)
            B_fst = [od for od in outputs[: len(outs_fst)]]
            B_snd = [od for od in outputs[len(outs_fst) :]]

            # generate promises
            prom_fst = await self._generate_promises(B_fst, keyset)
            prom_snd = await self._generate_promises(B_snd, keyset)
            promises = prom_fst + prom_snd
        # END backwards compatibility < 0.13.0
        else:
            promises = await self._generate_promises(outputs, keyset)

        # verify amounts in produced promises
        self._verify_equation_balanced(proofs, promises)

        logger.trace("split successful")
        return promises
        return prom_fst, prom_snd

    async def restore(
        self, outputs: List[BlindedMessage]
    ) -> Tuple[List[BlindedMessage], List[BlindedSignature]]:
        promises: List[BlindedSignature] = []
        return_outputs: List[BlindedMessage] = []
        async with self.db.connect() as conn:
            for output in outputs:
                logger.trace(f"looking for promise: {output}")
                promise = await self.crud.get_promise(
                    B_=output.B_, db=self.db, conn=conn
                )
                if promise is not None:
                    # BEGIN backwards compatibility mints pre `m007_proofs_and_promises_store_id`
                    # add keyset id to promise if not present only if the current keyset
                    # is the only one ever used
                    if not promise.id and len(self.keysets.keysets) == 1:
                        promise.id = self.keyset.id
                    # END backwards compatibility
                    promises.append(promise)
                    return_outputs.append(output)
                    logger.trace(f"promise found: {promise}")
        return return_outputs, promises
