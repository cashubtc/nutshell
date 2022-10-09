import base64
import json
import secrets as scrts
import uuid
from itertools import groupby
from typing import Dict, List

import requests
from loguru import logger

import cashu.core.b_dhke as b_dhke
from cashu.core.base import (
    BlindedMessage,
    BlindedSignature,
    CheckFeesRequest,
    CheckRequest,
    MeltRequest,
    MintRequest,
    P2SHScript,
    Proof,
    SplitRequest,
    WalletKeyset,
)
from cashu.core.db import Database
from cashu.core.script import (
    step0_carol_checksig_redeemscrip,
    step0_carol_privkey,
    step1_carol_create_p2sh_address,
    step2_carol_sign_tx,
)
from cashu.core.secp import PublicKey
from cashu.core.settings import DEBUG
from cashu.core.split import amount_split
from cashu.wallet.crud import (
    get_keyset,
    get_proofs,
    invalidate_proof,
    secret_used,
    store_keyset,
    store_p2sh,
    store_proof,
    update_proof_reserved,
)


class LedgerAPI:
    keys: Dict[int, str]
    keyset: str

    def __init__(self, url):
        self.url = url

    async def _get_keys(self, url):
        resp = requests.get(url + "/keys").json()
        keys = resp
        assert len(keys), Exception("did not receive any keys")
        keyset_keys = {
            int(amt): PublicKey(bytes.fromhex(val), raw=True)
            for amt, val in keys.items()
        }
        keyset = WalletKeyset(pubkeys=keyset_keys, mint_url=url)
        return keyset

    async def _get_keysets(self, url):
        keysets = requests.get(url + "/keysets").json()
        assert len(keysets), Exception("did not receive any keysets")
        return keysets

    @staticmethod
    def _get_output_split(amount):
        """Given an amount returns a list of amounts returned e.g. 13 is [1, 4, 8]."""
        bits_amt = bin(amount)[::-1][:-2]
        rv = []
        for (pos, bit) in enumerate(bits_amt):
            if bit == "1":
                rv.append(2**pos)
        return rv

    def _construct_proofs(
        self, promises: List[BlindedSignature], secrets: List[str], rs: List[str]
    ):
        """Returns proofs of promise from promises. Wants secrets and blinding factors rs."""
        proofs = []
        for promise, secret, r in zip(promises, secrets, rs):
            C_ = PublicKey(bytes.fromhex(promise.C_), raw=True)
            C = b_dhke.step3_alice(C_, r, self.keys[promise.amount])
            proof = Proof(
                id=self.keyset_id,
                amount=promise.amount,
                C=C.serialize().hex(),
                secret=secret,
            )
            proofs.append(proof)
        return proofs

    @staticmethod
    def _generate_secret(randombits=128):
        """Returns base64 encoded random string."""
        return scrts.token_urlsafe(randombits // 8)

    async def _load_mint(self):
        """
        Loads the current keys and the active keyset of the map.
        """
        assert len(
            self.url
        ), "Ledger not initialized correctly: mint URL not specified yet. "
        # get current keyset
        keyset = await self._get_keys(self.url)
        logger.debug(f"Current mint keyset: {keyset.id}")
        # get all active keysets
        keysets = await self._get_keysets(self.url)
        logger.debug(f"Mint keysets: {keysets}")

        # check if current keyset is in db
        keyset_local: WalletKeyset = await get_keyset(keyset.id, db=self.db)
        if keyset_local is None:
            await store_keyset(keyset=keyset, db=self.db)

        # store current keyset
        assert len(keyset.public_keys) > 0, "did not receive keys from mint."
        self.keys = keyset.public_keys
        self.keyset_id = keyset.id

        # store active keysets
        self.keysets = keysets["keysets"]

    def request_mint(self, amount):
        """Requests a mint from the server and returns Lightning invoice."""
        r = requests.get(self.url + "/mint", params={"amount": amount})
        r.raise_for_status()
        return r.json()

    @staticmethod
    def _construct_outputs(amounts: List[int], secrets: List[str]):
        """Takes a list of amounts and secrets and returns outputs.
        Outputs are blinded messages `payloads` and blinding factors `rs`"""
        assert len(amounts) == len(
            secrets
        ), f"len(amounts)={len(amounts)} not equal to len(secrets)={len(secrets)}"
        payloads: MintRequest = MintRequest()
        rs = []
        for secret, amount in zip(secrets, amounts):
            B_, r = b_dhke.step1_alice(secret)
            rs.append(r)
            payload: BlindedMessage = BlindedMessage(
                amount=amount, B_=B_.serialize().hex()
            )
            payloads.blinded_messages.append(payload)
        return payloads, rs

    async def _check_used_secrets(self, secrets):
        for s in secrets:
            if await secret_used(s, db=self.db):
                raise Exception(f"secret already used: {s}")

    def generate_secrets(self, secret, n):
        """`secret` is the base string that will be tweaked n times"""
        if len(secret.split("P2SH:")) == 2:
            return [f"{secret}:{self._generate_secret()}" for i in range(n)]
        return [f"{i}:{secret}" for i in range(n)]

    async def mint(self, amounts, payment_hash=None):
        """Mints new coins and returns a proof of promise."""
        secrets = [self._generate_secret() for s in range(len(amounts))]
        await self._check_used_secrets(secrets)
        payloads, rs = self._construct_outputs(amounts, secrets)

        resp = requests.post(
            self.url + "/mint",
            json=payloads.dict(),
            params={"payment_hash": payment_hash},
        )
        resp.raise_for_status()
        try:
            promises_list = resp.json()
        except:
            raise Exception("Unkown mint error.")
        if "error" in promises_list:
            raise Exception("Error: {}".format(promises_list["error"]))

        promises = [BlindedSignature.from_dict(p) for p in promises_list]
        return self._construct_proofs(promises, secrets, rs)

    async def split(self, proofs, amount, scnd_secret: str = None):
        """Consume proofs and create new promises based on amount split.
        If scnd_secret is None, random secrets will be generated for the tokens to keep (frst_outputs)
        and the promises to send (scnd_outputs).

        If scnd_secret is provided, the wallet will create blinded secrets with those to attach a
        predefined spending condition to the tokens they want to send."""

        total = sum([p["amount"] for p in proofs])
        frst_amt, scnd_amt = total - amount, amount
        frst_outputs = amount_split(frst_amt)
        scnd_outputs = amount_split(scnd_amt)

        amounts = frst_outputs + scnd_outputs
        if scnd_secret is None:
            secrets = [self._generate_secret() for _ in range(len(amounts))]
        else:
            scnd_secrets = self.generate_secrets(scnd_secret, len(scnd_outputs))
            logger.debug(f"Creating proofs with custom secrets: {scnd_secrets}")
            assert len(scnd_secrets) == len(
                scnd_outputs
            ), "number of scnd_secrets does not match number of ouptus."
            # append predefined secrets (to send) to random secrets (to keep)
            secrets = [
                self._generate_secret() for s in range(len(frst_outputs))
            ] + scnd_secrets

        assert len(secrets) == len(
            amounts
        ), "number of secrets does not match number of outputs"
        await self._check_used_secrets(secrets)
        payloads, rs = self._construct_outputs(amounts, secrets)
        split_payload = SplitRequest(proofs=proofs, amount=amount, outputs=payloads)

        def _splitrequest_include_fields(proofs):
            """strips away fields from the model that aren't necessary for the /split"""
            proofs_include = {"id", "amount", "secret", "C", "script"}
            return {
                "amount": ...,
                "outputs": ...,
                "proofs": {i: proofs_include for i in range(len(proofs))},
            }

        resp = requests.post(
            self.url + "/split",
            json=split_payload.dict(include=_splitrequest_include_fields(proofs)),
        )
        resp.raise_for_status()
        try:
            promises_dict = resp.json()
        except:
            raise Exception("Unkown mint error.")
        if "error" in promises_dict:
            raise Exception("Mint Error: {}".format(promises_dict["error"]))
        promises_fst = [BlindedSignature.from_dict(p) for p in promises_dict["fst"]]
        promises_snd = [BlindedSignature.from_dict(p) for p in promises_dict["snd"]]
        # Construct proofs from promises (i.e., unblind signatures)
        frst_proofs = self._construct_proofs(
            promises_fst, secrets[: len(promises_fst)], rs[: len(promises_fst)]
        )
        scnd_proofs = self._construct_proofs(
            promises_snd, secrets[len(promises_fst) :], rs[len(promises_fst) :]
        )

        return frst_proofs, scnd_proofs

    async def check_spendable(self, proofs: List[Proof]):
        payload = CheckRequest(proofs=proofs)
        resp = requests.post(
            self.url + "/check",
            json=payload.dict(),
        )
        resp.raise_for_status()
        return_dict = resp.json()

        return return_dict

    async def check_fees(self, payment_request: str):
        """Checks whether the Lightning payment is internal."""
        payload = CheckFeesRequest(pr=payment_request)
        resp = requests.post(
            self.url + "/checkfees",
            json=payload.dict(),
        )
        resp.raise_for_status()

        return_dict = resp.json()
        return return_dict

    async def pay_lightning(self, proofs: List[Proof], invoice: str):
        payload = MeltRequest(proofs=proofs, invoice=invoice)

        def _meltequest_include_fields(proofs):
            """strips away fields from the model that aren't necessary for the /melt"""
            proofs_include = {"id", "amount", "secret", "C", "script"}
            return {
                "amount": ...,
                "invoice": ...,
                "proofs": {i: proofs_include for i in range(len(proofs))},
            }

        resp = requests.post(
            self.url + "/melt",
            json=payload.dict(include=_meltequest_include_fields(proofs)),
        )
        resp.raise_for_status()

        return_dict = resp.json()
        return return_dict


class Wallet(LedgerAPI):
    """Minimal wallet wrapper."""

    def __init__(self, url: str, db: str, name: str = "no_name"):
        super().__init__(url)
        self.db = Database("wallet", db)
        self.proofs: List[Proof] = []
        self.name = name

    async def load_mint(self):
        await super()._load_mint()

    async def load_proofs(self):
        self.proofs = await get_proofs(db=self.db)

    async def _store_proofs(self, proofs):
        for proof in proofs:
            await store_proof(proof, db=self.db)

    @staticmethod
    def _sum_proofs(proofs: List[Proof], available_only=False):
        if available_only:
            return sum([p.amount for p in proofs if not p.reserved])
        return sum([p.amount for p in proofs])

    @staticmethod
    def _get_proofs_per_keyset(proofs: List[Proof]):
        return {key: list(group) for key, group in groupby(proofs, lambda p: p.id)}

    async def request_mint(self, amount):
        return super().request_mint(amount)

    async def mint(self, amount: int, payment_hash: str = None):
        split = amount_split(amount)
        proofs = await super().mint(split, payment_hash)
        if proofs == []:
            raise Exception("received no proofs.")
        await self._store_proofs(proofs)
        self.proofs += proofs
        return proofs

    async def redeem(
        self,
        proofs: List[Proof],
        scnd_script: str = None,
        scnd_siganture: str = None,
    ):
        if scnd_script and scnd_siganture:
            logger.debug(f"Unlock script: {scnd_script}")
            # attach unlock scripts to proofs
            for p in proofs:
                p.script = P2SHScript(script=scnd_script, signature=scnd_siganture)
        return await self.split(proofs, sum(p["amount"] for p in proofs))

    async def split(
        self,
        proofs: List[Proof],
        amount: int,
        scnd_secret: str = None,
    ):
        assert len(proofs) > 0, ValueError("no proofs provided.")
        frst_proofs, scnd_proofs = await super().split(proofs, amount, scnd_secret)
        if len(frst_proofs) == 0 and len(scnd_proofs) == 0:
            raise Exception("received no splits.")
        used_secrets = [p["secret"] for p in proofs]
        self.proofs = list(
            filter(lambda p: p["secret"] not in used_secrets, self.proofs)
        )
        self.proofs += frst_proofs + scnd_proofs
        await self._store_proofs(frst_proofs + scnd_proofs)
        for proof in proofs:
            await invalidate_proof(proof, db=self.db)
        return frst_proofs, scnd_proofs

    async def pay_lightning(self, proofs: List[Proof], invoice: str):
        """Pays a lightning invoice"""
        status = await super().pay_lightning(proofs, invoice)
        if status["paid"] == True:
            await self.invalidate(proofs)
        else:
            raise Exception("could not pay invoice.")
        return status["paid"]

    @staticmethod
    async def serialize_proofs(proofs: List[Proof], hide_secrets=False):
        if hide_secrets:
            proofs_serialized = [p.to_dict_no_secret() for p in proofs]
        else:
            proofs_serialized = [p.to_dict() for p in proofs]
        token = base64.urlsafe_b64encode(
            json.dumps(proofs_serialized).encode()
        ).decode()
        return token

    async def _get_spendable_proofs(self, proofs: List[Proof]):
        """
        Selects proofs that can be used with the current mint.
        Chooses:
        1) Proofs that are not marked as reserved
        2) Proofs that have a keyset id that is in self.keysets (active keysets of mint) - !!! optional for backwards compatibility with legacy clients
        """
        proofs = [
            p for p in proofs if p.id in self.keysets or not p.id
        ]  # "or not p.id" is for backwards compatibility with proofs without a keyset id
        proofs = [p for p in proofs if not p.reserved]
        return proofs

    async def split_to_send(self, proofs: List[Proof], amount, scnd_secret: str = None):
        """Like self.split but only considers non-reserved tokens."""
        if scnd_secret:
            logger.debug(f"Spending conditions: {scnd_secret}")
        spendable_proofs = await self._get_spendable_proofs(proofs)
        if sum([p.amount for p in spendable_proofs]) < amount:
            raise Exception("balance too low.")
        return await self.split(
            [p for p in spendable_proofs if not p.reserved], amount, scnd_secret
        )

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

    async def create_p2sh_lock(self):
        alice_privkey = step0_carol_privkey()
        txin_redeemScript = step0_carol_checksig_redeemscrip(alice_privkey.pub)
        txin_p2sh_address = step1_carol_create_p2sh_address(txin_redeemScript)
        txin_signature = step2_carol_sign_tx(txin_redeemScript, alice_privkey).scriptSig
        txin_redeemScript_b64 = base64.urlsafe_b64encode(txin_redeemScript).decode()
        txin_signature_b64 = base64.urlsafe_b64encode(txin_signature).decode()
        p2shScript = P2SHScript(
            script=txin_redeemScript_b64,
            signature=txin_signature_b64,
            address=str(txin_p2sh_address),
        )
        await store_p2sh(p2shScript, db=self.db)
        return p2shScript

    @property
    def balance(self):
        return sum(p["amount"] for p in self.proofs)

    @property
    def available_balance(self):
        return sum(p["amount"] for p in self.proofs if not p.reserved)

    def status(self):
        print(
            f"Balance: {self.balance} sat (available: {self.available_balance} sat in {len([p for p in self.proofs if not p.reserved])} tokens)"
        )

    def balance_per_keyset(self):
        return {
            key: {
                "balance": self._sum_proofs(proofs),
                "available": self._sum_proofs(proofs, available_only=True),
            }
            for key, proofs in self._get_proofs_per_keyset(self.proofs).items()
        }

    def proof_amounts(self):
        return [p["amount"] for p in sorted(self.proofs, key=lambda p: p["amount"])]
