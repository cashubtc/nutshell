import math
from typing import Dict, List, Literal, Optional, Set, Union

from loguru import logger

from ..core import bolt11, legacy
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
from ..core.db import Database
from ..core.helpers import fee_reserve, sum_proofs
from ..core.script import verify_script
from ..core.settings import settings
from ..core.split import amount_split
from ..lightning.base import Wallet
from ..mint.crud import LedgerCrud


class Ledger:
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
        proofs_used = await self.crud.get_proofs_used(db=self.db)
        self.proofs_used = set(proofs_used)

    async def load_keyset(self, derivation_path, autosave=True):
        """Load current keyset keyset or generate new one.

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
        # check if current keyset is stored in db and store if not
        logger.debug(f"Active keyset: {keyset.id}")
        tmp_keyset_local: List[MintKeyset] = await self.crud.get_keyset(
            id=keyset.id, db=self.db
        )
        if not len(tmp_keyset_local) and autosave:
            logger.debug(f"Storing new keyset {keyset.id}.")
            await self.crud.store_keyset(keyset=keyset, db=self.db)

        # store the new keyset in the current keysets
        if keyset.id:
            self.keysets.keysets[keyset.id] = keyset
        return keyset

    async def init_keysets(self, autosave=True):
        """Initializes all keysets of the mint from the db.

        Args:
            autosave (bool, optional): Whether the current keyset should be saved if it is
            not in the database yet. Will be passed to `self.load_keyset` where it is
            generated from `self.derivation_path`. Defaults to True.
        """
        # load all past keysets from db
        tmp_keysets: List[MintKeyset] = await self.crud.get_keyset(db=self.db)
        # add keysets from db to current keysets
        for k in tmp_keysets:
            if k.id and k.id not in self.keysets.keysets:
                self.keysets.keysets[k.id] = k

        logger.debug(
            f"We initialized {len(self.keysets.keysets)} previous keysets from the database."
        )

        # generate all private keys, public keys, and keyset id from the derivation path for all keysets that are not yet generated
        for _, v in self.keysets.keysets.items():
            # we already generated the keys for this keyset
            if v.id and v.public_keys and len(v.public_keys):
                continue
            logger.debug(f"Generating keys for keyset {v.id}")
            v.generate_keys(self.master_key)

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
        await self.crud.store_promise(
            amount=amount, B_=B_.serialize().hex(), C_=C_.serialize().hex(), db=self.db
        )
        return BlindedSignature(id=keyset.id, amount=amount, C_=C_.serialize().hex())

    def _check_spendable(self, proof: Proof):
        """Checks whether the proof was already spent."""
        return not proof.secret in self.proofs_used

    def _verify_secret_criteria(self, proof: Proof) -> Literal[True]:
        """Verifies that a secret is present and is not too long (DOS prevention)."""
        if proof.secret is None or proof.secret == "":
            raise Exception("no secret in proof.")
        if len(proof.secret) > 64:
            raise Exception("secret too long.")
        return True

    def _verify_proof_bdhke(self, proof: Proof):
        """Verifies that the proof of promise was issued by this ledger."""
        if not self._check_spendable(proof):
            raise Exception(f"tokens already spent. Secret: {proof.secret}")
        # if no keyset id is given in proof, assume the current one
        if not proof.id:
            private_key_amount = self.keyset.private_keys[proof.amount]
        else:
            logger.trace(
                f"Validating proof with keyset {self.keysets.keysets[proof.id].id}."
            )
            # use the appropriate active keyset for this proof.id
            private_key_amount = self.keysets.keysets[proof.id].private_keys[
                proof.amount
            ]

        C = PublicKey(bytes.fromhex(proof.C), raw=True)
        return b_dhke.verify(private_key_amount, C, proof.secret)

    def _verify_script(self, idx: int, proof: Proof) -> bool:
        """
        Verify bitcoin script in proof.script commited to by <address> in proof.secret.
        proof.secret format: P2SH:<address>:<secret>
        """
        # if no script is given
        if (
            proof.script is None
            or proof.script.script is None
            or proof.script.signature is None
        ):
            if len(proof.secret.split("P2SH:")) == 2:
                # secret indicates a script but no script is present
                return False
            else:
                # secret indicates no script, so treat script as valid
                return True
        # execute and verify P2SH
        txin_p2sh_address, valid = verify_script(
            proof.script.script, proof.script.signature
        )
        if valid:
            # check if secret commits to script address
            # format: P2SH:<address>:<secret>
            assert len(proof.secret.split(":")) == 3, "secret format wrong."
            assert proof.secret.split(":")[1] == str(
                txin_p2sh_address
            ), f"secret does not contain correct P2SH address: {proof.secret.split(':')[1]} is not {txin_p2sh_address}."
        return valid

    def _verify_outputs(
        self, total: int, amount: int, outputs: List[BlindedMessage]
    ) -> bool:
        """Verifies the expected split was correctly computed"""
        frst_amt, scnd_amt = total - amount, amount  # we have two amounts to split to
        frst_outputs = amount_split(frst_amt)
        scnd_outputs = amount_split(scnd_amt)
        expected = frst_outputs + scnd_outputs
        given = [o.amount for o in outputs]
        return given == expected

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

    def _verify_split_amount(self, amount: int) -> None:
        """Split amount like output amount can't be negative or too big."""
        try:
            self._verify_amount(amount)
        except:
            # For better error message
            raise Exception("invalid split amount: " + str(amount))

    def _verify_amount(self, amount: int) -> int:
        """Any amount used should be a positive integer not larger than 2^MAX_ORDER."""
        valid = (
            isinstance(amount, int) and amount > 0 and amount < 2**settings.max_order
        )
        if not valid:
            raise Exception("invalid amount: " + str(amount))
        return amount

    def _verify_equation_balanced(
        self, proofs: List[Proof], outs: List[BlindedSignature]
    ) -> None:
        """Verify that Σoutputs - Σinputs = 0."""
        sum_inputs = sum(self._verify_amount(p.amount) for p in proofs)
        sum_outputs = sum(self._verify_amount(p.amount) for p in outs)
        assert sum_outputs - sum_inputs == 0

    async def _request_lightning_invoice(self, amount: int,  description_hash: Optional[bytes] = None):
        """Generate a Lightning invoice using the funding source backend.

        Args:
            amount (int): Amount of invoice (in Satoshis)

        Raises:
            Exception: Error with funding source.

        Returns:
            Tuple[str, str]: Bolt11 invoice and payment hash (for lookup)
        """
        error, balance = await self.lightning.status()
        if error:
            raise Exception(f"Lightning wallet not responding: {error}")
        (
            ok,
            checking_id,
            payment_request,
            error_message,
        ) = await self.lightning.create_invoice(amount, "cashu deposit", description_hash)
        return payment_request, checking_id

    async def _check_lightning_invoice(self, amount: int, hash: str) -> Literal[True]:
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
        invoice: Union[Invoice, None] = await self.crud.get_lightning_invoice(
            hash=hash, db=self.db
        )
        if invoice is None:
            raise Exception("invoice not found.")
        if invoice.issued:
            raise Exception("tokens already issued for this invoice.")
        assert invoice.payment_hash, "invoice has no payment hash."

        # set this invoice as issued
        await self.crud.update_lightning_invoice(hash=hash, issued=True, db=self.db)

        try:
            if amount > invoice.amount:
                raise Exception(
                    f"requested amount too high: {amount}. Invoice amount: {invoice.amount}"
                )

            status = await self.lightning.get_invoice_status(invoice.payment_hash)
            if status.paid:
                return status.paid
            else:
                raise Exception("Lightning invoice not paid yet.")
        except Exception as e:
            # unset issued
            await self.crud.update_lightning_invoice(
                hash=hash, issued=False, db=self.db
            )
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
        error, _ = await self.lightning.status()
        if error:
            raise Exception(f"Lightning wallet not responding: {error}")
        (
            ok,
            checking_id,
            fee_msat,
            preimage,
            error_message,
        ) = await self.lightning.pay_invoice(invoice, fee_limit_msat=fee_limit_msat)
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
        for p in proofs:
            await self.crud.invalidate_proof(proof=p, db=self.db)

    async def _set_proofs_pending(self, proofs: List[Proof]):
        """If none of the proofs is in the pending table (_validate_proofs_pending), adds proofs to
        the list of pending proofs or removes them. Used as a mutex for proofs.

        Args:
            proofs (List[Proof]): Proofs to add to pending table.

        Raises:
            Exception: At least one proof already in pending table.
        """
        # first we check whether these proofs are pending aready
        await self._validate_proofs_pending(proofs)
        for p in proofs:
            try:
                await self.crud.set_proof_pending(proof=p, db=self.db)
            except:
                raise Exception("proofs already pending.")

    async def _unset_proofs_pending(self, proofs: List[Proof]):
        """Deletes proofs from pending table.

        Args:
            proofs (List[Proof]): Proofs to delete.
        """
        # we try: except: this block in order to avoid that any errors here
        # could block the _invalidate_proofs() call that happens afterwards.
        try:
            for p in proofs:
                await self.crud.unset_proof_pending(proof=p, db=self.db)
        except Exception as e:
            print(e)
            pass

    async def _validate_proofs_pending(self, proofs: List[Proof]):
        """Checks if any of the provided proofs is in the pending proofs table.

        Args:
            proofs (List[Proof]): Proofs to check.

        Raises:
            Exception: At least one of the proofs is in the pending table.
        """
        proofs_pending = await self.crud.get_proofs_pending(db=self.db)
        for p in proofs:
            for pp in proofs_pending:
                if p.secret == pp.secret:
                    raise Exception("proofs are pending.")

    async def _verify_proofs(self, proofs: List[Proof]):
        """Checks a series of criteria for the verification of proofs.

        Args:
            proofs (List[Proof]): List of proofs to check.

        Raises:
            Exception: Scripts did not validate.
            Exception: Criteria for provided secrets not met.
            Exception: Duplicate proofs provided.
            Exception: BDHKE verification failed.
        """
        # Verify scripts
        if not all([self._verify_script(i, p) for i, p in enumerate(proofs)]):
            raise Exception("script validation failed.")
        # Verify secret criteria
        if not all([self._verify_secret_criteria(p) for p in proofs]):
            raise Exception("secrets do not match criteria.")
        # verify that only unique proofs were used
        if not self._verify_no_duplicate_proofs(proofs):
            raise Exception("duplicate proofs.")
        # Verify proofs
        if not all([self._verify_proof_bdhke(p) for p in proofs]):
            raise Exception("could not verify proofs.")

    async def _generate_change_promises(
        self,
        total_provided: int,
        invoice_amount: int,
        ln_fee_msat: int,
        outputs: List[BlindedMessage],
        keyset: Optional[MintKeyset] = None,
    ):
        """Generates a set of new promises (blinded signatures) from a set of blank outputs
        (outputs with no or ignored amount) by looking at the difference between the Lightning
        fee reserve provided by the wallet and the actual Lightning fee paid by the mint.

        If there is a positive difference, produces maximum `n_return_outputs` new outputs
        with values close or equal to the fee difference. We can't be sure that we hit the
        fee perfectly because we can only work with a limited set of blanket outputs and
        their values are limited to 2^n.

        Args:
            total_provided (int): Amount of the proofs provided by the wallet.
            invoice_amount (int): Amount of the invoice to be paid.
            ln_fee_msat (int): Actually paid Lightning network fees.
            outputs (List[BlindedMessage]): Outputs to sign for returning the overpaid fees.

        Raises:
            Exception: Output validation failed.

        Returns:
            List[BlindedSignature]: Signatures on the outputs.
        """
        # we make sure that the fee is positive
        ln_fee_msat = abs(ln_fee_msat)
        # maximum number of change outputs (must be in consensus with wallet)
        n_return_outputs = 4
        ln_fee_sat = math.ceil(ln_fee_msat / 1000)
        user_paid_fee_sat = total_provided - invoice_amount
        logger.debug(
            f"Lightning fee was: {ln_fee_sat}. User paid: {user_paid_fee_sat}. Returning difference."
        )
        if user_paid_fee_sat - ln_fee_sat > 0 and outputs is not None:
            # we will only accept at maximum n_return_outputs outputs
            assert len(outputs) <= n_return_outputs, Exception(
                "too many change outputs provided"
            )

            return_amounts = amount_split(user_paid_fee_sat - ln_fee_sat)
            # we only need as many outputs as we have change to return
            outputs = outputs[: len(return_amounts)]
            # we sort the return_amounts in descending order so we only
            # take the largest values in the next step
            return_amounts_sorted = sorted(return_amounts, reverse=True)
            # we need to imprint these amounts into the blanket outputs
            for i in range(len(outputs)):
                outputs[i].amount = return_amounts_sorted[i]
            if not self._verify_no_duplicate_outputs(outputs):
                raise Exception("duplicate promises.")
            return_promises = await self._generate_promises(outputs, keyset)
            return return_promises
        else:
            return []

    # Public methods
    def get_keyset(self, keyset_id: Optional[str] = None):
        """Returns a dictionary of hex public keys of a specific keyset for each supported amount"""
        if keyset_id and keyset_id not in self.keysets.keysets:
            raise Exception("keyset does not exist")
        keyset = self.keysets.keysets[keyset_id] if keyset_id else self.keyset
        assert keyset.public_keys, Exception("no public keys for this keyset")
        return {a: p.serialize().hex() for a, p in keyset.public_keys.items()}

    async def request_mint(self, amount: int, description_hash: Optional[bytes] = None):
        """Returns Lightning invoice and stores it in the db.

        Args:
            amount (int): Amount of the mint request in Satoshis.

        Raises:
            Exception: Invoice creation failed.

        Returns:
            Tuple[str, str]: Bolt11 invoice and a hash (for looking it up later)
        """
        payment_request, payment_hash = await self._request_lightning_invoice(amount, description_hash)
        assert payment_request and payment_hash, Exception(
            "could not fetch invoice from Lightning backend"
        )

        invoice = Invoice(
            amount=amount,
            hash=random_hash(),
            pr=payment_request,
            payment_hash=payment_hash,  # what we got from the backend
            issued=False,
        )

        await self.crud.store_lightning_invoice(invoice=invoice, db=self.db)
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
            Exception: Lightning is turned on but no payment hash is provided.
            e: Something went wrong with the invoice check.
            Exception: Amount too large.

        Returns:
            List[BlindedSignature]: Signatures on the outputs.
        """
        amounts = [b.amount for b in B_s]
        amount = sum(amounts)
        # check if lightning invoice was paid
        if settings.lightning:
            if not hash:
                raise Exception("no hash provided.")
            try:
                paid = await self._check_lightning_invoice(amount, hash)
            except Exception as e:
                raise e

        for amount in amounts:
            if amount not in [2**i for i in range(settings.max_order)]:
                raise Exception(
                    f"Can only mint amounts with 2^n up to {2**settings.max_order}."
                )

        promises = await self._generate_promises(B_s, keyset)
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

        # validate and set proofs as pending
        await self._set_proofs_pending(proofs)

        try:
            await self._verify_proofs(proofs)

            total_provided = sum_proofs(proofs)
            invoice_obj = bolt11.decode(invoice)
            invoice_amount = math.ceil(invoice_obj.amount_msat / 1000)
            fees_msat = await self.check_fees(invoice)
            assert total_provided >= invoice_amount + fees_msat / 1000, Exception(
                "provided proofs not enough for Lightning payment."
            )

            # promises to return for overpaid fees
            return_promises: List[BlindedSignature] = []

            if settings.lightning:
                status, preimage, fee_msat = await self._pay_lightning_invoice(
                    invoice, fees_msat
                )
            else:
                status, preimage, fee_msat = True, "preimage", 0

            if status == True:
                await self._invalidate_proofs(proofs)

                # prepare change to compensate wallet for overpaid fees
                assert fee_msat is not None, Exception("fees not valid")
                if outputs:
                    return_promises = await self._generate_change_promises(
                        total_provided=total_provided,
                        invoice_amount=invoice_amount,
                        ln_fee_msat=fee_msat,
                        outputs=outputs,
                    )
            else:
                raise Exception("Lightning payment unsuccessful.")

        except Exception as e:
            raise e
        finally:
            # delete proofs from pending list
            await self._unset_proofs_pending(proofs)

        return status, preimage, return_promises

    async def check_spendable(self, proofs: List[Proof]):
        """Checks if provided proofs are valid and have not been spent yet.
        Used by wallets to check if their proofs have been redeemed by a receiver.

        Returns a list in the same order as the provided proofs. Wallet must match the list
        to the proofs they have provided in order to figure out which proof is still spendable
        and which isn't.

        Args:
            proofs (List[Proof]): List of proofs to check.

        Returns:
            List[bool]: List of which proof is still spendable (True if still spendable, else False)
        """
        return [self._check_spendable(p) for p in proofs]

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
            paid = await self.lightning.get_invoice_status(decoded_invoice.payment_hash)
            internal = paid.paid == False
        else:
            amount = 0
            internal = True
        fees_msat = fee_reserve(amount * 1000, internal)
        fee_sat = math.ceil(fees_msat / 1000)
        return fee_sat

    async def split(
        self,
        proofs: List[Proof],
        amount: int,
        outputs: List[BlindedMessage],
        keyset: Optional[MintKeyset] = None,
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

        # set proofs as pending
        await self._set_proofs_pending(proofs)

        total = sum_proofs(proofs)

        try:
            # verify that amount is kosher
            self._verify_split_amount(amount)
            # verify overspending attempt
            if amount > total:
                raise Exception("split amount is higher than the total sum.")

            await self._verify_proofs(proofs)

            # verify that only unique outputs were used
            if not self._verify_no_duplicate_outputs(outputs):
                raise Exception("duplicate promises.")
            # verify that outputs have the correct amount
            if not self._verify_outputs(total, amount, outputs):
                raise Exception("split of promises is not as expected.")
        except Exception as e:
            raise e
        finally:
            # delete proofs from pending list
            await self._unset_proofs_pending(proofs)

        # Mark proofs as used and prepare new promises
        await self._invalidate_proofs(proofs)

        # split outputs according to amount
        outs_fst = amount_split(total - amount)
        B_fst = [od for od in outputs[: len(outs_fst)]]
        B_snd = [od for od in outputs[len(outs_fst) :]]

        # generate promises
        prom_fst, prom_snd = await self._generate_promises(
            B_fst, keyset
        ), await self._generate_promises(B_snd, keyset)

        # verify amounts in produced proofs
        self._verify_equation_balanced(proofs, prom_fst + prom_snd)
        return prom_fst, prom_snd
