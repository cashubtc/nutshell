"""
Implementation of https://gist.github.com/phyro/935badc682057f418842c72961cf096c
"""

import hashlib

from ecc.curve import secp256k1, Point
from ecc.key import gen_keypair

import core.b_dhke as b_dhke
from core.db import Database
from core.split import amount_split
from core.settings import MAX_ORDER
from mint.crud import store_promise, invalidate_proof, get_proofs_used


class Ledger:
    def __init__(self, secret_key: str, db: str):
        self.master_key = secret_key
        self.proofs_used = set()
        self.keys = self._derive_keys(self.master_key)
        self.db = Database("mint", db)

    async def load_used_proofs(self):
        self.proofs_used = set(await get_proofs_used(db=self.db))

    @staticmethod
    def _derive_keys(master_key):
        """Deterministic derivation of keys for 2^n values."""
        return {
            2
            ** i: int(
                hashlib.sha256((str(master_key) + str(i)).encode("utf-8"))
                .hexdigest()
                .encode("utf-8"),
                16,
            )
            for i in range(MAX_ORDER)
        }

    async def _generate_promises(self, amounts, B_s):
        """Generates promises that sum to the given amount."""
        return [
            await self._generate_promise(amount, Point(B_["x"], B_["y"], secp256k1))
            for (amount, B_) in zip(amounts, B_s)
        ]

    async def _generate_promise(self, amount, B_):
        """Generates a promise for given amount and returns a pair (amount, C')."""
        secret_key = self.keys[amount]  # Get the correct key
        C_ = b_dhke.step2_alice(B_, secret_key)
        await store_promise(amount, B_x=B_.x, B_y=B_.y, C_x=C_.x, C_y=C_.y, db=self.db)
        return {"amount": amount, "C'": C_}

    def _verify_proof(self, proof):
        """Verifies that the proof of promise was issued by this ledger."""
        if proof["secret"] in self.proofs_used:
            raise Exception(f"Already spent. Secret: {proof['secret']}")
        secret_key = self.keys[proof["amount"]]  # Get the correct key to check against
        C = Point(proof["C"]["x"], proof["C"]["y"], secp256k1)
        return b_dhke.verify(secret_key, C, proof["secret"])

    def _verify_outputs(self, total, amount, output_data):
        """Verifies the expected split was correctly computed"""
        fst_amt, snd_amt = total - amount, amount  # we have two amounts to split to
        fst_outputs = amount_split(fst_amt)
        snd_outputs = amount_split(snd_amt)
        expected = fst_outputs + snd_outputs
        given = [o["amount"] for o in output_data]
        return given == expected

    def _verify_no_duplicates(self, proofs, output_data):
        secrets = [p["secret"] for p in proofs]
        if len(secrets) != len(list(set(secrets))):
            return False
        B_xs = [od["B'"]["x"] for od in output_data]
        if len(B_xs) != len(list(set(B_xs))):
            return False
        return True

    def _verify_split_amount(self, amount):
        """Split amount like output amount can't be negative or too big."""
        try:
            self._verify_amount(amount)
        except:
            # For better error message
            raise Exception("Invalid split amount: " + str(amount))

    def _verify_amount(self, amount):
        """Any amount used should be a positive integer not larger than 2^MAX_ORDER."""
        valid = isinstance(amount, int) and amount > 0 and amount < 2**MAX_ORDER
        if not valid:
            raise Exception("Invalid amount: " + str(amount))
        return amount

    def _verify_equation_balanced(self, proofs, outs):
        """Verify that Σoutputs - Σinputs = 0."""
        sum_inputs = sum(self._verify_amount(p["amount"]) for p in proofs)
        sum_outputs = sum(self._verify_amount(p["amount"]) for p in outs)
        assert sum_outputs - sum_inputs == 0

    def _get_output_split(self, amount):
        """Given an amount returns a list of amounts returned e.g. 13 is [1, 4, 8]."""
        self._verify_amount(amount)
        bits_amt = bin(amount)[::-1][:-2]
        rv = []
        for (pos, bit) in enumerate(bits_amt):
            if bit == "1":
                rv.append(2**pos)
        return rv

    # Public methods

    def get_pubkeys(self):
        """Returns public keys for possible amounts."""
        return {
            amt: self.keys[amt] * secp256k1.G
            for amt in [2**i for i in range(MAX_ORDER)]
        }

    async def mint(self, B_, amount):
        """Mints a promise for coins for B_."""
        if amount not in [2**i for i in range(MAX_ORDER)]:
            raise Exception(f"Can only mint amounts up to {2**MAX_ORDER}.")
        split = amount_split(amount)
        return [await self._generate_promise(a, B_) for a in split]

    async def split(self, proofs, amount, output_data):
        """Consumes proofs and prepares new promises based on the amount split."""
        self._verify_split_amount(amount)
        # Verify proofs are valid
        if not all([self._verify_proof(p) for p in proofs]):
            return False

        total = sum([p["amount"] for p in proofs])

        if not self._verify_no_duplicates(proofs, output_data):
            raise Exception("duplicate proofs or promises")
        if amount > total:
            raise Exception("split amount is higher than the total sum")
        if not self._verify_outputs(total, amount, output_data):
            raise Exception("split of promises is not as expected")

        # Perform split
        proof_msgs = set([p["secret"] for p in proofs])
        # Mark proofs as used and prepare new promises
        self.proofs_used |= proof_msgs

        # store in db
        for p in proofs:
            await invalidate_proof(p, db=self.db)

        outs_fst = amount_split(total - amount)
        outs_snd = amount_split(amount)
        B_fst = [od["B'"] for od in output_data[: len(outs_fst)]]
        B_snd = [od["B'"] for od in output_data[len(outs_fst) :]]
        prom_fst, prom_snd = await self._generate_promises(
            outs_fst, B_fst
        ), await self._generate_promises(outs_snd, B_snd)
        self._verify_equation_balanced(proofs, prom_fst + prom_snd)
        return prom_fst, prom_snd
