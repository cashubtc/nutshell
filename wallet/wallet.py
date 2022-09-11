import random
import asyncio

import requests
from ecc.curve import secp256k1, Point
from typing import List
from wallet.models import Proof

import core.b_dhke as b_dhke
from core.db import Database
from core.split import amount_split

from wallet.crud import store_proof, invalidate_proof, get_proofs


class LedgerAPI:
    def __init__(self, url):
        self.url = url
        self.keys = self._get_keys(url)

    @staticmethod
    def _get_keys(url):
        resp = requests.get(url + "/keys").json()
        return {
            int(amt): Point(val["x"], val["y"], secp256k1) for amt, val in resp.items()
        }

    @staticmethod
    def _get_output_split(amount):
        """Given an amount returns a list of amounts returned e.g. 13 is [1, 4, 8]."""
        bits_amt = bin(amount)[::-1][:-2]
        rv = []
        for (pos, bit) in enumerate(bits_amt):
            if bit == "1":
                rv.append(2**pos)
        return rv

    def _construct_proofs(self, promises, secrets):
        """Returns proofs of promise from promises."""
        proofs = []
        for promise, (r, secret) in zip(promises, secrets):
            C_ = Point(promise["C'"]["x"], promise["C'"]["y"], secp256k1)
            C = b_dhke.step3_bob(C_, r, self.keys[promise["amount"]])
            proofs.append(
                {
                    "amount": promise["amount"],
                    "C": {
                        "x": C.x,
                        "y": C.y,
                    },
                    "secret": secret,
                }
            )
        return proofs

    def mint(self, amount):
        """Mints new coins and returns a proof of promise."""
        secret = str(random.getrandbits(128))
        B_, r = b_dhke.step1_bob(secret)
        promises = requests.post(
            self.url + "/mint",
            params={"amount": amount},
            json={"x": str(B_.x), "y": str(B_.y)},
        ).json()
        if "error" in promises:
            print("Error: {}".format(promises["error"]))
            return []
        return self._construct_proofs(promises, [(r, secret)])

    def split(self, proofs, amount):
        """Consume proofs and create new promises based on amount split."""
        total = sum([p["amount"] for p in proofs])
        fst_amt, snd_amt = total - amount, amount
        fst_outputs = amount_split(fst_amt)
        snd_outputs = amount_split(snd_amt)

        secrets = []
        output_data = []
        for output_amt in fst_outputs + snd_outputs:
            secret = str(random.getrandbits(128))
            B_, r = b_dhke.step1_bob(secret)
            secrets.append((r, secret))
            output_data.append(
                {
                    "amount": output_amt,
                    "B'": {
                        "x": B_.x,
                        "y": B_.y,
                    },
                }
            )
        promises = requests.post(
            self.url + "/split",
            json={"proofs": proofs, "amount": amount, "output_data": output_data},
        ).json()
        if "error" in promises:
            print("Error: {}".format(promises["error"]))
            return [], []

        # Obtain proofs from promises
        fst_proofs = self._construct_proofs(
            promises["fst"], secrets[: len(promises["fst"])]
        )
        snd_proofs = self._construct_proofs(
            promises["snd"], secrets[len(promises["fst"]) :]
        )

        return fst_proofs, snd_proofs


class Wallet(LedgerAPI):
    """Minimal wallet wrapper."""

    def __init__(self, url: str, db: str):
        super().__init__(url)
        self.db = Database("wallet", db)
        self.proofs: List[Proof] = []

    async def load_proofs(self):
        self.proofs = await get_proofs(db=self.db)

    async def _store_proofs(self, proofs):
        for proof in proofs:
            await store_proof(proof, db=self.db)

    async def mint(self, amount):
        split = amount_split(amount)
        new_proofs = []
        for amount in split:
            proofs = super().mint(amount)
            if proofs == []:
                return []
            new_proofs += proofs
            await self._store_proofs(proofs)
        self.proofs += new_proofs
        return new_proofs

    async def redeem(self, proofs):
        return await self.split(proofs, sum(p["amount"] for p in proofs))

    async def split(self, proofs, amount):
        fst_proofs, snd_proofs = super().split(proofs, amount)
        if len(fst_proofs) == 0 and len(snd_proofs) == 0:
            return [], []
        used_secrets = [p["secret"] for p in proofs]
        self.proofs = list(
            filter(lambda p: p["secret"] not in used_secrets, self.proofs)
        )
        self.proofs += fst_proofs + snd_proofs
        # store in db
        for proof in proofs:
            await invalidate_proof(proof, db=self.db)
        await self._store_proofs(fst_proofs + snd_proofs)
        return fst_proofs, snd_proofs

    async def invalidate(self, proofs):
        # first we make sure that the server has invalidated these proofs
        fst_proofs, snd_proofs = await self.split(
            proofs, sum(p["amount"] for p in proofs)
        )
        assert fst_proofs == []
        assert snd_proofs == []

        # TODO: check with server if they were redeemed already
        for proof in proofs:
            await invalidate_proof(proof, db=self.db)
        invalidate_secrets = [p["secret"] for p in proofs]
        self.proofs = list(
            filter(lambda p: p["secret"] not in invalidate_secrets, self.proofs)
        )

    @property
    def balance(self):
        return sum(p["amount"] for p in self.proofs)

    def status(self):
        print("Balance: {}".format(self.balance))

    def proof_amounts(self):
        return [p["amount"] for p in sorted(self.proofs, key=lambda p: p["amount"])]
