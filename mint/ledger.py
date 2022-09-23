"""
Implementation of https://gist.github.com/phyro/935badc682057f418842c72961cf096c
"""

import hashlib
from typing import List, Set

import core.b_dhke as b_dhke
from core.base import BlindedMessage, BlindedSignature, Invoice, Proof
from core.db import Database
from core.helpers import fee_reserve
from core.secp import PrivateKey, PublicKey
from core.settings import LIGHTNING, MAX_ORDER
from core.split import amount_split
from lightning import WALLET
from mint.crud import (
    get_lightning_invoice,
    get_proofs_used,
    invalidate_proof,
    store_lightning_invoice,
    store_promise,
    update_lightning_invoice,
)


class Ledger:
    def __init__(self, secret_key: str, db: str):
        self.proofs_used: Set[str] = set()

        self.master_key: str = secret_key
        self.keys: List[PrivateKey] = self._derive_keys(self.master_key)
        self.pub_keys: List[PublicKey] = self._derive_pubkeys(self.keys)
        self.db: Database = Database("mint", db)

    async def load_used_proofs(self):
        self.proofs_used = set(await get_proofs_used(db=self.db))

    @staticmethod
    def _derive_keys(master_key: str):
        """Deterministic derivation of keys for 2^n values."""
        return {
            2
            ** i: PrivateKey(
                hashlib.sha256((str(master_key) + str(i)).encode("utf-8"))
                .hexdigest()
                .encode("utf-8")[:32],
                raw=True,
            )
            for i in range(MAX_ORDER)
        }

    @staticmethod
    def _derive_pubkeys(keys: List[PrivateKey]):
        return {amt: keys[amt].pubkey for amt in [2**i for i in range(MAX_ORDER)]}

    async def _generate_promises(self, amounts: List[int], B_s: List[str]):
        """Generates promises that sum to the given amount."""
        return [
            await self._generate_promise(amount, PublicKey(bytes.fromhex(B_), raw=True))
            for (amount, B_) in zip(amounts, B_s)
        ]

    async def _generate_promise(self, amount: int, B_: PublicKey):
        """Generates a promise for given amount and returns a pair (amount, C')."""
        secret_key = self.keys[amount]  # Get the correct key
        C_ = b_dhke.step2_bob(B_, secret_key)
        await store_promise(
            amount, B_=B_.serialize().hex(), C_=C_.serialize().hex(), db=self.db
        )
        return BlindedSignature(amount=amount, C_=C_.serialize().hex())

    def _check_spendable(self, proof: Proof):
        """Checks whether the proof was already spent."""
        return not proof.secret in self.proofs_used

    def _verify_proof(self, proof: Proof):
        """Verifies that the proof of promise was issued by this ledger."""
        if not self._check_spendable(proof):
            raise Exception(f"tokens already spent. Secret: {proof.secret}")
        secret_key = self.keys[proof.amount]  # Get the correct key to check against
        C = PublicKey(bytes.fromhex(proof.C), raw=True)
        return b_dhke.verify(secret_key, C, proof.secret)

    def _verify_outputs(
        self, total: int, amount: int, output_data: List[BlindedMessage]
    ):
        """Verifies the expected split was correctly computed"""
        fst_amt, snd_amt = total - amount, amount  # we have two amounts to split to
        fst_outputs = amount_split(fst_amt)
        snd_outputs = amount_split(snd_amt)
        expected = fst_outputs + snd_outputs
        given = [o.amount for o in output_data]
        return given == expected

    def _verify_no_duplicates(
        self, proofs: List[Proof], output_data: List[BlindedMessage]
    ):
        secrets = [p.secret for p in proofs]
        if len(secrets) != len(list(set(secrets))):
            return False
        B_s = [od.B_ for od in output_data]
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
        self, proofs: List[Proof], outs: List[BlindedMessage]
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

    async def _check_lightning_invoice(self, payment_hash: str):
        """Checks with the Lightning backend whether an invoice with this payment_hash was paid."""
        invoice: Invoice = await get_lightning_invoice(payment_hash, db=self.db)
        if invoice.issued:
            raise Exception("tokens already issued for this invoice")
        status = await WALLET.get_invoice_status(payment_hash)
        if status.paid:
            await update_lightning_invoice(payment_hash, issued=True, db=self.db)
        return status.paid

    async def _pay_lightning_invoice(self, invoice: str, amount: int):
        """Returns an invoice from the Lightning backend."""
        error, balance = await WALLET.status()
        if error:
            raise Exception(f"Lightning wallet not responding: {error}")
        ok, checking_id, fee_msat, preimage, error_message = await WALLET.pay_invoice(
            invoice, fee_limit_msat=fee_reserve(amount * 1000)
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

    # Public methods
    def get_pubkeys(self):
        """Returns public keys for possible amounts."""
        return {a: p.serialize().hex() for a, p in self.pub_keys.items()}

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
        if LIGHTNING and (
            payment_hash and not await self._check_lightning_invoice(payment_hash)
        ):
            raise Exception("Lightning invoice not paid yet.")

        for amount in amounts:
            if amount not in [2**i for i in range(MAX_ORDER)]:
                raise Exception(f"Can only mint amounts up to {2**MAX_ORDER}.")

        promises = [
            await self._generate_promise(amount, B_) for B_, amount in zip(B_s, amounts)
        ]
        return promises

    async def melt(self, proofs: List[Proof], amount: int, invoice: str):
        """Invalidates proofs and pays a Lightning invoice."""
        # if not LIGHTNING:
        total = sum([p["amount"] for p in proofs])
        # check that lightning fees are included
        assert total + fee_reserve(amount * 1000) >= amount, Exception(
            "provided proofs not enough for Lightning payment."
        )

        status, preimage = await self._pay_lightning_invoice(invoice, amount)
        if status == True:
            await self._invalidate_proofs(proofs)
        return status, preimage

    async def check_spendable(self, proofs: List[Proof]):
        """Checks if all provided proofs are valid and still spendable (i.e. have not been spent)."""
        return {i: self._check_spendable(p) for i, p in enumerate(proofs)}

    async def split(
        self, proofs: List[Proof], amount: int, output_data: List[BlindedMessage]
    ):
        """Consumes proofs and prepares new promises based on the amount split."""
        self._verify_split_amount(amount)
        # Verify proofs are valid
        if not all([self._verify_proof(p) for p in proofs]):
            return False

        total = sum([p.amount for p in proofs])

        if not self._verify_no_duplicates(proofs, output_data):
            raise Exception("duplicate proofs or promises")
        if amount > total:
            raise Exception("split amount is higher than the total sum")
        if not self._verify_outputs(total, amount, output_data):
            raise Exception("split of promises is not as expected")

        # Mark proofs as used and prepare new promises
        await self._invalidate_proofs(proofs)

        outs_fst = amount_split(total - amount)
        outs_snd = amount_split(amount)
        B_fst = [od.B_ for od in output_data[: len(outs_fst)]]
        B_snd = [od.B_ for od in output_data[len(outs_fst) :]]
        prom_fst, prom_snd = await self._generate_promises(
            outs_fst, B_fst
        ), await self._generate_promises(outs_snd, B_snd)
        self._verify_equation_balanced(proofs, prom_fst + prom_snd)
        return prom_fst, prom_snd
