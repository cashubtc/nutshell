import base64
import json
import random
import secrets as scrts
import uuid
from typing import List

import requests

import core.b_dhke as b_dhke
from core.base import (
    BlindedMessage,
    BlindedSignature,
    CheckPayload,
    MeltPayload,
    MintPayloads,
    Proof,
    SplitPayload,
)
from core.db import Database
from core.secp import PublicKey
from core.settings import DEBUG
from core.split import amount_split
from wallet.crud import get_proofs, invalidate_proof, store_proof, update_proof_reserved


class LedgerAPI:
    def __init__(self, url):
        self.url = url
        self.keys = self._get_keys(url)

    @staticmethod
    def _get_keys(url):
        resp = requests.get(url + "/keys").json()
        return {
            int(amt): PublicKey(bytes.fromhex(val), raw=True)
            for amt, val in resp.items()
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

    def _construct_proofs(self, promises: List[BlindedSignature], secrets: List[str]):
        """Returns proofs of promise from promises."""
        proofs = []
        for promise, (r, secret) in zip(promises, secrets):
            C_ = PublicKey(bytes.fromhex(promise.C_), raw=True)
            C = b_dhke.step3_alice(C_, r, self.keys[promise.amount])
            proof = Proof(amount=promise.amount, C=C.serialize().hex(), secret=secret)
            proofs.append(proof)
        return proofs

    def _generate_secret(self, randombits=128):
        """Returns base64 encoded random string."""
        return scrts.token_urlsafe(randombits // 8)

    def request_mint(self, amount):
        """Requests a mint from the server and returns Lightning invoice."""
        r = requests.get(self.url + "/mint", params={"amount": amount})
        return r.json()

    def mint(self, amounts, payment_hash=None):
        """Mints new coins and returns a proof of promise."""
        payloads: MintPayloads = MintPayloads()
        secrets = []
        rs = []
        for amount in amounts:
            secret = self._generate_secret()
            secrets.append(secret)
            B_, r = b_dhke.step1_alice(secret)
            rs.append(r)
            payload: BlindedMessage = BlindedMessage(
                amount=amount, B_=B_.serialize().hex()
            )
            payloads.blinded_messages.append(payload)
        promises_list = requests.post(
            self.url + "/mint",
            json=payloads.dict(),
            params={"payment_hash": payment_hash},
        ).json()
        if "error" in promises_list:
            raise Exception("Error: {}".format(promises_list["error"]))
        promises = [BlindedSignature.from_dict(p) for p in promises_list]
        return self._construct_proofs(promises, [(r, s) for r, s in zip(rs, secrets)])

    def split(self, proofs, amount):
        """Consume proofs and create new promises based on amount split."""
        total = sum([p["amount"] for p in proofs])
        fst_amt, snd_amt = total - amount, amount
        fst_outputs = amount_split(fst_amt)
        snd_outputs = amount_split(snd_amt)

        secrets = []
        payloads: MintPayloads = MintPayloads()
        for output_amt in fst_outputs + snd_outputs:
            secret = self._generate_secret()
            B_, r = b_dhke.step1_alice(secret)
            secrets.append((r, secret))
            payload: BlindedMessage = BlindedMessage(
                amount=output_amt, B_=B_.serialize().hex()
            )
            payloads.blinded_messages.append(payload)
        split_payload = SplitPayload(proofs=proofs, amount=amount, output_data=payloads)
        promises_dict = requests.post(
            self.url + "/split",
            json=split_payload.dict(),
        ).json()
        if "error" in promises_dict:
            raise Exception("Error: {}".format(promises_dict["error"]))
        promises_fst = [BlindedSignature.from_dict(p) for p in promises_dict["fst"]]
        promises_snd = [BlindedSignature.from_dict(p) for p in promises_dict["snd"]]
        # Obtain proofs from promises
        fst_proofs = self._construct_proofs(promises_fst, secrets[: len(promises_fst)])
        snd_proofs = self._construct_proofs(promises_snd, secrets[len(promises_fst) :])

        return fst_proofs, snd_proofs

    async def check_spendable(self, proofs: List[Proof]):
        payload = CheckPayload(proofs=proofs)
        return_dict = requests.post(
            self.url + "/check",
            json=payload.dict(),
        ).json()

        return return_dict

    async def pay_lightning(self, proofs: List[Proof], amount: int, invoice: str):
        payload = MeltPayload(proofs=proofs, amount=amount, invoice=invoice)
        return_dict = requests.post(
            self.url + "/melt",
            json=payload.dict(),
        ).json()
        return return_dict


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

    async def request_mint(self, amount):
        return super().request_mint(amount)

    async def mint(self, amount: int, payment_hash: str = None):
        split = amount_split(amount)
        proofs = super().mint(split, payment_hash)
        if proofs == []:
            raise Exception("received no proofs.")
        await self._store_proofs(proofs)
        self.proofs += proofs
        return proofs

    async def redeem(self, proofs: List[Proof]):
        return await self.split(proofs, sum(p["amount"] for p in proofs))

    async def split(self, proofs: List[Proof], amount: int):
        assert len(proofs) > 0, ValueError("no proofs provided.")
        fst_proofs, snd_proofs = super().split(proofs, amount)
        if len(fst_proofs) == 0 and len(snd_proofs) == 0:
            raise Exception("received no splits.")
        used_secrets = [p["secret"] for p in proofs]
        self.proofs = list(
            filter(lambda p: p["secret"] not in used_secrets, self.proofs)
        )
        self.proofs += fst_proofs + snd_proofs
        await self._store_proofs(fst_proofs + snd_proofs)
        for proof in proofs:
            await invalidate_proof(proof, db=self.db)
        return fst_proofs, snd_proofs

    async def pay_lightning(self, proofs: List[Proof], amount: int, invoice: str):
        """Pays a lightning invoice"""
        status = await super().pay_lightning(proofs, amount, invoice)
        if status["paid"] == True:
            await self.invalidate(proofs)
        else:
            raise Exception("could not pay invoice.")
        return status["paid"]

    @staticmethod
    async def serialize_proofs(proofs: List[Proof]):
        proofs_serialized = [p.to_dict() for p in proofs]
        token = base64.urlsafe_b64encode(
            json.dumps(proofs_serialized).encode()
        ).decode()
        return token

    async def split_to_send(self, proofs: List[Proof], amount):
        """Like self.split but only considers non-reserved tokens."""
        if len([p for p in proofs if not p.reserved]) <= 0:
            raise Exception("balance too low.")
        return await self.split([p for p in proofs if not p.reserved], amount)

    async def set_reserved(self, proofs: List[Proof], reserved: bool):
        """Mark a proof as reserved to avoid reuse or delete marking."""
        uuid_str = str(uuid.uuid1())
        for proof in proofs:
            proof.reserved = True
            await update_proof_reserved(
                proof, reserved=reserved, send_id=uuid_str, db=self.db
            )

    async def check_spendable(self, proofs):
        return await super().check_spendable(proofs)

    async def invalidate(self, proofs):
        """Invalidates all spendable tokens supplied in proofs."""
        spendables = await self.check_spendable(proofs)
        invalidated_proofs = []
        for idx, spendable in spendables.items():
            if not spendable:
                invalidated_proofs.append(proofs[int(idx)])
                await invalidate_proof(proofs[int(idx)], db=self.db)
        invalidate_secrets = [p["secret"] for p in invalidated_proofs]
        self.proofs = list(
            filter(lambda p: p["secret"] not in invalidate_secrets, self.proofs)
        )

    @property
    def balance(self):
        return sum(p["amount"] for p in self.proofs)

    @property
    def available_balance(self):
        return sum(p["amount"] for p in self.proofs if not p.reserved)

    def status(self):
        print(
            f"Balance: {self.balance} sat (Available: {self.available_balance} sat in {len([p for p in self.proofs if not p.reserved])} tokens)"
        )

    def proof_amounts(self):
        return [p["amount"] for p in sorted(self.proofs, key=lambda p: p["amount"])]
