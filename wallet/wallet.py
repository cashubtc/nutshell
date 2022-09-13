import random
import asyncio

import requests
from ecc.curve import secp256k1, Point
from typing import List
from core.base import Proof, BasePoint

import core.b_dhke as b_dhke
from core.db import Database
from core.split import amount_split

from wallet.crud import store_proof, invalidate_proof, get_proofs

from core.base import MintPayload, MintPayloads, SplitPayload


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
            c_point = BasePoint(x=C.x, y=C.y)
            proof = Proof(amount=promise["amount"], C=c_point, secret=secret)
            proofs.append(proof.dict())
        return proofs

    def mint(self, amounts):
        """Mints new coins and returns a proof of promise."""
        payloads: MintPayloads = MintPayloads()
        secrets = []
        rs = []
        for i, amount in enumerate(amounts):
            secret = str(random.getrandbits(128))
            secrets.append(secret)
            B_, r = b_dhke.step1_bob(secret)
            rs.append(r)
            blinded_point = BasePoint(x=str(B_.x), y=str(B_.y))
            payload: MintPayload = MintPayload(amount=amount, B_=blinded_point)
            payloads.payloads.append(payload)

        promises = requests.post(
            self.url + "/mint",
            json=payloads.dict(),
        ).json()
        if "detail" in promises:
            raise Exception("Error: {}".format(promises["detail"]))
        return self._construct_proofs(promises, [(r, s) for r, s in zip(rs, secrets)])

    def split(self, proofs, amount):
        """Consume proofs and create new promises based on amount split."""
        total = sum([p["amount"] for p in proofs])
        fst_amt, snd_amt = total - amount, amount
        fst_outputs = amount_split(fst_amt)
        snd_outputs = amount_split(snd_amt)

        secrets = []
        # output_data = []
        payloads: MintPayloads = MintPayloads()
        for output_amt in fst_outputs + snd_outputs:
            secret = str(random.getrandbits(128))
            B_, r = b_dhke.step1_bob(secret)
            secrets.append((r, secret))
            blinded_point = BasePoint(x=str(B_.x), y=str(B_.y))
            payload: MintPayload = MintPayload(amount=output_amt, B_=blinded_point)
            payloads.payloads.append(payload)
            # output_data.append(
            #     {
            #         "amount": output_amt,
            #         "B'": {
            #             "x": B_.x,
            #             "y": B_.y,
            #         },
            #     }
            # )
        split_payload = SplitPayload(proofs=proofs, amount=amount, output_data=payloads)
        promises = requests.post(
            self.url + "/split",
            json=split_payload.dict(),
        ).json()
        if "error" in promises:
            raise Exception("Error: {}".format(promises["error"]))

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

    def __init__(self, url: str, db: str, name: str = "no_name"):
        super().__init__(url)
        self.db = Database("wallet", db)
        self.proofs: List[Proof] = []
        self.name = name

    async def load_proofs(self):
        self.proofs = await get_proofs(db=self.db)

    async def _store_proofs(self, proofs):
        for proof in proofs:
            await store_proof(proof, db=self.db)

    async def mint(self, amount):
        split = amount_split(amount)
        proofs = super().mint(split)
        if proofs == []:
            raise Exception("received no proofs")
        await self._store_proofs(proofs)
        self.proofs += proofs
        return proofs

    async def redeem(self, proofs):
        return await self.split(proofs, sum(p["amount"] for p in proofs))

    async def split(self, proofs, amount):
        fst_proofs, snd_proofs = super().split(proofs, amount)
        if len(fst_proofs) == 0 and len(snd_proofs) == 0:
            raise Exception("received no splits")
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
        try:
            await self.split(proofs, sum(p["amount"] for p in proofs))
        except Exception as exc:
            assert exc.args[0].startswith("Error: Already spent."), Exception(
                "invalidating unspent tokens"
            )

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
        print(f"{self.name} balance: {self.balance}")

    def proof_amounts(self):
        return [p["amount"] for p in sorted(self.proofs, key=lambda p: p["amount"])]
