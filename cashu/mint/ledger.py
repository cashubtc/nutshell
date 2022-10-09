"""
Implementation of https://gist.github.com/phyro/935badc682057f418842c72961cf096c
"""

import math
from typing import Dict, List, Set

from loguru import logger

import cashu.core.b_dhke as b_dhke
import cashu.core.bolt11 as bolt11
from cashu.core.base import (
    BlindedMessage,
    BlindedSignature,
    Invoice,
    MintKeyset,
    MintKeysets,
    Proof,
)
from cashu.core.crypto import derive_keys, derive_keyset_id, derive_pubkeys
from cashu.core.db import Database
from cashu.core.helpers import fee_reserve
from cashu.core.script import verify_script
from cashu.core.secp import PublicKey
from cashu.core.settings import LIGHTNING, MAX_ORDER
from cashu.core.split import amount_split
from cashu.lightning import WALLET
from cashu.mint.crud import (
    get_keyset,
    get_lightning_invoice,
    get_proofs_used,
    invalidate_proof,
    store_keyset,
    store_lightning_invoice,
    store_promise,
    update_lightning_invoice,
)


class Ledger:
    def __init__(self, secret_key: str, db: str, derivation_path=""):
        self.proofs_used: Set[str] = set()
        self.master_key = secret_key
        self.derivation_path = derivation_path
        self.db: Database = Database("mint", db)

    async def load_used_proofs(self):
        self.proofs_used = set(await get_proofs_used(db=self.db))

    async def init_keysets(self):
        """Loads all past keysets and stores the active one if not already in db"""
        # generate current keyset from seed and current derivation path
        self.keyset = MintKeyset(
            seed=self.master_key, derivation_path=self.derivation_path
        )
        # check if current keyset is stored in db and store if not
        current_keyset_local: List[MintKeyset] = await get_keyset(
            id=self.keyset.id, db=self.db
        )
        if not len(current_keyset_local):
            logger.debug(f"Storing keyset {self.keyset.id}")
            await store_keyset(keyset=self.keyset, db=self.db)

        # load all past keysets from db
        # this needs two steps because the types of tmp_keysets and the argument of MintKeysets() are different
        tmp_keysets: List[MintKeyset] = await get_keyset(db=self.db)
        self.keysets = MintKeysets(tmp_keysets)
        logger.debug(f"Keysets {self.keysets.keysets}")
        # generate all derived keys from stored derivation paths of past keysets
        for _, v in self.keysets.keysets.items():
            v.generate_keys(self.master_key)

        if len(self.keysets.keysets):
            logger.debug(f"Loaded {len(self.keysets.keysets)} keysets from db.")

    async def _generate_promises(self, amounts: List[int], B_s: List[str]):
        """Generates promises that sum to the given amount."""
        return [
            await self._generate_promise(amount, PublicKey(bytes.fromhex(B_), raw=True))
            for (amount, B_) in zip(amounts, B_s)
        ]

    async def _generate_promise(self, amount: int, B_: PublicKey):
        """Generates a promise for given amount and returns a pair (amount, C')."""
        secret_key = self.keyset.private_keys[amount]  # Get the correct key
        C_ = b_dhke.step2_bob(B_, secret_key)
        await store_promise(
            amount, B_=B_.serialize().hex(), C_=C_.serialize().hex(), db=self.db
        )
        return BlindedSignature(amount=amount, C_=C_.serialize().hex())

    def _check_spendable(self, proof: Proof):
        """Checks whether the proof was already spent."""
        return not proof.secret in self.proofs_used

    def _verify_secret_or_script(self, proof: Proof):
        if proof.secret and proof.script:
            raise Exception("secret and script present at the same time.")
        return True

    def _verify_secret_criteria(self, proof: Proof):
        if proof.secret is None or proof.secret == "":
            raise Exception("no secret in proof.")
        return True

    def _verify_proof(self, proof: Proof):
        """Verifies that the proof of promise was issued by this ledger."""
        if not self._check_spendable(proof):
            raise Exception(f"tokens already spent. Secret: {proof.secret}")
        # if no keyset id is given in proof, assume the current one
        if not proof.id:
            secret_key = self.keyset.private_keys[proof.amount]
        else:
            # use the appropriate active keyset for this proof.id
            secret_key = self.keysets.keysets[proof.id].private_keys[proof.amount]

        C = PublicKey(bytes.fromhex(proof.C), raw=True)
        return b_dhke.verify(secret_key, C, proof.secret)

    def _verify_script(self, idx: int, proof: Proof):
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

    def _verify_outputs(self, total: int, amount: int, outputs: List[BlindedMessage]):
        """Verifies the expected split was correctly computed"""
        frst_amt, scnd_amt = total - amount, amount  # we have two amounts to split to
        frst_outputs = amount_split(frst_amt)
        scnd_outputs = amount_split(scnd_amt)
        expected = frst_outputs + scnd_outputs
        given = [o.amount for o in outputs]
        return given == expected

    def _verify_no_duplicates(self, proofs: List[Proof], outputs: List[BlindedMessage]):
        secrets = [p.secret for p in proofs]
        if len(secrets) != len(list(set(secrets))):
            return False
        B_s = [od.B_ for od in outputs]
        if len(B_s) != len(list(set(B_s))):
            return False
        return True

    def _verify_split_amount(self, amount: int):
        """Split amount like output amount can't be negative or too big."""
        try:
            self._verify_amount(amount)
        except:
            # For better error message
            raise Exception("invalid split amount: " + str(amount))

    def _verify_amount(self, amount: int):
        """Any amount used should be a positive integer not larger than 2^MAX_ORDER."""
        valid = isinstance(amount, int) and amount > 0 and amount < 2**MAX_ORDER
        if not valid:
            raise Exception("invalid amount: " + str(amount))
        return amount

    def _verify_equation_balanced(
        self, proofs: List[Proof], outs: List[BlindedSignature]
    ):
        """Verify that Σoutputs - Σinputs = 0."""
        sum_inputs = sum(self._verify_amount(p.amount) for p in proofs)
        sum_outputs = sum(self._verify_amount(p.amount) for p in outs)
        assert sum_outputs - sum_inputs == 0

    def _get_output_split(self, amount: int):
        """Given an amount returns a list of amounts returned e.g. 13 is [1, 4, 8]."""
        self._verify_amount(amount)
        bits_amt = bin(amount)[::-1][:-2]
        rv = []
        for (pos, bit) in enumerate(bits_amt):
            if bit == "1":
                rv.append(2**pos)
        return rv

    async def _request_lightning_invoice(self, amount: int):
        """Returns an invoice from the Lightning backend."""
        error, balance = await WALLET.status()
        if error:
            raise Exception(f"Lightning wallet not responding: {error}")
        ok, checking_id, payment_request, error_message = await WALLET.create_invoice(
            amount, "cashu deposit"
        )
        return payment_request, checking_id

    async def _check_lightning_invoice(self, amounts, payment_hash: str):
        """Checks with the Lightning backend whether an invoice with this payment_hash was paid."""
        invoice: Invoice = await get_lightning_invoice(payment_hash, db=self.db)
        if invoice.issued:
            raise Exception("tokens already issued for this invoice.")
        total_requested = sum([amount for amount in amounts])
        if total_requested > invoice.amount:
            raise Exception(
                f"Requested amount too high: {total_requested}. Invoice amount: {invoice.amount}"
            )
        status = await WALLET.get_invoice_status(payment_hash)
        if status.paid:
            await update_lightning_invoice(payment_hash, issued=True, db=self.db)
        return status.paid

    async def _pay_lightning_invoice(self, invoice: str, fees_msat: int):
        """Returns an invoice from the Lightning backend."""
        error, _ = await WALLET.status()
        if error:
            raise Exception(f"Lightning wallet not responding: {error}")
        ok, checking_id, fee_msat, preimage, error_message = await WALLET.pay_invoice(
            invoice, fee_limit_msat=fees_msat
        )
        return ok, preimage

    async def _invalidate_proofs(self, proofs: List[Proof]):
        """Adds secrets of proofs to the list of knwon secrets and stores them in the db."""
        # Mark proofs as used and prepare new promises
        proof_msgs = set([p.secret for p in proofs])
        self.proofs_used |= proof_msgs
        # store in db
        for p in proofs:
            await invalidate_proof(p, db=self.db)

    def _serialize_pubkeys(self):
        """Returns public keys for possible amounts."""
        return {a: p.serialize().hex() for a, p in self.keyset.public_keys.items()}

    # Public methods
    def get_keyset(self):
        return self._serialize_pubkeys()

    async def request_mint(self, amount):
        """Returns Lightning invoice and stores it in the db."""
        payment_request, checking_id = await self._request_lightning_invoice(amount)
        invoice = Invoice(
            amount=amount, pr=payment_request, hash=checking_id, issued=False
        )
        if not payment_request or not checking_id:
            raise Exception(f"Could not create Lightning invoice.")
        await store_lightning_invoice(invoice, db=self.db)
        return payment_request, checking_id

    async def mint(self, B_s: List[PublicKey], amounts: List[int], payment_hash=None):
        """Mints a promise for coins for B_."""
        # check if lightning invoice was paid
        if LIGHTNING:
            try:
                paid = await self._check_lightning_invoice(amounts, payment_hash)
            except Exception as e:
                raise Exception("could not check invoice: " + str(e))
            if not paid:
                raise Exception("Lightning invoice not paid yet.")

        for amount in amounts:
            if amount not in [2**i for i in range(MAX_ORDER)]:
                raise Exception(f"Can only mint amounts up to {2**MAX_ORDER}.")

        promises = [
            await self._generate_promise(amount, B_) for B_, amount in zip(B_s, amounts)
        ]
        return promises

    async def melt(self, proofs: List[Proof], invoice: str):
        """Invalidates proofs and pays a Lightning invoice."""
        # Verify proofs
        if not all([self._verify_proof(p) for p in proofs]):
            raise Exception("could not verify proofs.")

        total_provided = sum([p["amount"] for p in proofs])
        invoice_obj = bolt11.decode(invoice)
        amount = math.ceil(invoice_obj.amount_msat / 1000)
        fees_msat = await self.check_fees(invoice)
        assert total_provided >= amount + fees_msat / 1000, Exception(
            "provided proofs not enough for Lightning payment."
        )

        status, preimage = await self._pay_lightning_invoice(invoice, fees_msat)
        if status == True:
            await self._invalidate_proofs(proofs)
        return status, preimage

    async def check_spendable(self, proofs: List[Proof]):
        """Checks if all provided proofs are valid and still spendable (i.e. have not been spent)."""
        return {i: self._check_spendable(p) for i, p in enumerate(proofs)}

    async def check_fees(self, pr: str):
        """Returns the fees (in msat) required to pay this pr."""
        decoded_invoice = bolt11.decode(pr)
        amount = math.ceil(decoded_invoice.amount_msat / 1000)
        # hack: check if it's internal, if it exists, it will return paid = False,
        # if id does not exist (not internal), it returns paid = None
        paid = await WALLET.get_invoice_status(decoded_invoice.payment_hash)
        internal = paid.paid == False
        fees_msat = fee_reserve(amount * 1000, internal)
        return fees_msat

    async def split(
        self, proofs: List[Proof], amount: int, outputs: List[BlindedMessage]
    ):
        """Consumes proofs and prepares new promises based on the amount split."""
        total = sum([p.amount for p in proofs])

        # verify that amount is kosher
        self._verify_split_amount(amount)
        # verify overspending attempt
        if amount > total:
            raise Exception("split amount is higher than the total sum.")

        # Verify scripts
        if not all([self._verify_script(i, p) for i, p in enumerate(proofs)]):
            raise Exception("script verification failed.")
        # Verify secret criteria
        if not all([self._verify_secret_criteria(p) for p in proofs]):
            raise Exception("secrets do not match criteria.")
        # verify that only unique proofs and outputs were used
        if not self._verify_no_duplicates(proofs, outputs):
            raise Exception("duplicate proofs or promises.")
        # verify that outputs have the correct amount
        if not self._verify_outputs(total, amount, outputs):
            raise Exception("split of promises is not as expected.")
        # Verify proofs
        if not all([self._verify_proof(p) for p in proofs]):
            raise Exception("could not verify proofs.")

        # Mark proofs as used and prepare new promises
        await self._invalidate_proofs(proofs)

        outs_fst = amount_split(total - amount)
        outs_snd = amount_split(amount)
        B_fst = [od.B_ for od in outputs[: len(outs_fst)]]
        B_snd = [od.B_ for od in outputs[len(outs_fst) :]]
        prom_fst, prom_snd = await self._generate_promises(
            outs_fst, B_fst
        ), await self._generate_promises(outs_snd, B_snd)
        # verify amounts in produced proofs
        self._verify_equation_balanced(proofs, prom_fst + prom_snd)
        return prom_fst, prom_snd
