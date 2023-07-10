import asyncio
import base64
import json
import math
import secrets as scrts
import time
import uuid
from datetime import datetime, timedelta
from itertools import groupby
from typing import Dict, List, Optional, Tuple, Union

import requests
from loguru import logger

from ..core import bolt11 as bolt11
from ..core.base import (
    BlindedMessage,
    BlindedSignature,
    CheckFeesRequest,
    CheckSpendableRequest,
    CheckSpendableResponse,
    GetInfoResponse,
    GetMeltResponse,
    GetMintResponse,
    Invoice,
    KeysetsResponse,
    P2SHScript,
    PostMeltRequest,
    PostMintRequest,
    PostMintResponse,
    PostMintResponseLegacy,
    PostSplitRequest,
    Proof,
    Secret,
    SecretKind,
    Tags,
    TokenV2,
    TokenV2Mint,
    TokenV3,
    TokenV3Token,
    WalletKeyset,
)
from ..core.bolt11 import Invoice as InvoiceBolt11
from ..core.crypto import b_dhke
from ..core.crypto.secp import PrivateKey, PublicKey
from ..core.db import Database
from ..core.helpers import calculate_number_of_blank_outputs, sum_proofs
from ..core.p2pk import sign_p2pk_sign
from ..core.script import (
    step0_carol_checksig_redeemscrip,
    step0_carol_privkey,
    step1_carol_create_p2sh_address,
    step2_carol_sign_tx,
)
from ..core.settings import settings
from ..core.split import amount_split
from ..nostr.nostr.client.client import NostrClient
from ..tor.tor import TorProxy
from ..wallet.crud import (
    get_keyset,
    get_proofs,
    get_unused_locks,
    invalidate_proof,
    secret_used,
    store_keyset,
    store_lightning_invoice,
    store_p2sh,
    store_proof,
    update_lightning_invoice,
    update_proof_reserved,
)


def async_set_requests(func):
    """
    Decorator that wraps around any async class method of LedgerAPI that makes
    API calls. Sets some HTTP headers and starts a Tor instance if none is
    already running and  and sets local proxy to use it.
    """

    async def wrapper(self, *args, **kwargs):
        self.s.headers.update({"Client-version": settings.version})
        if settings.debug:
            self.s.verify = False

        # set proxy
        proxy_url: Union[str, None] = None
        if settings.tor and TorProxy().check_platform():
            self.tor = TorProxy(timeout=True)
            self.tor.run_daemon(verbose=True)
            proxy_url = f"socks5://localhost:9050"
        elif settings.socks_proxy:
            proxy_url = f"socks5://{settings.socks_proxy}"
        elif settings.http_proxy:
            proxy_url = settings.http_proxy
        if proxy_url:
            self.s.proxies.update({"http": proxy_url})
            self.s.proxies.update({"https": proxy_url})

        self.s.headers.update({"User-Agent": scrts.token_urlsafe(8)})
        return await func(self, *args, **kwargs)

    return wrapper


class LedgerAPI:
    keys: WalletKeyset  # holds current keys of mint
    keyset_id: str  # holds id of current keyset
    public_keys: Dict[int, PublicKey]  # holds public keys of
    mint_info: GetInfoResponse  # holds info about mint
    tor: TorProxy
    db: Database
    s: requests.Session

    def __init__(self, url):
        self.url = url
        self.s = requests.Session()

    @async_set_requests
    async def _init_s(self):
        """Dummy function that can be called from outside to use LedgerAPI.s"""
        return

    def _construct_proofs(
        self, promises: List[BlindedSignature], secrets: List[str], rs: List[PrivateKey]
    ) -> List[Proof]:
        """Returns proofs of promise from promises. Wants secrets and blinding factors rs."""
        logger.trace(f"Constructing proofs.")
        proofs: List[Proof] = []
        for promise, secret, r in zip(promises, secrets, rs):
            logger.trace(f"Creating proof with keyset {self.keyset_id} = {promise.id}")
            assert (
                self.keyset_id == promise.id
            ), "our keyset id does not match promise id."

            C_ = PublicKey(bytes.fromhex(promise.C_), raw=True)
            C = b_dhke.step3_alice(C_, r, self.public_keys[promise.amount])

            proof = Proof(
                id=promise.id,
                amount=promise.amount,
                C=C.serialize().hex(),
                secret=secret,
            )
            proofs.append(proof)
        logger.trace(f"Constructed {len(proofs)} proofs.")
        return proofs

    @staticmethod
    def raise_on_error(resp_dict) -> None:
        if "error" in resp_dict:
            raise Exception("Mint Error: {}".format(resp_dict["error"]))

    @staticmethod
    def _generate_secret(randombits=128):
        """Returns base64 encoded random string."""
        return scrts.token_urlsafe(randombits // 8)

    async def _load_mint_keys(self, keyset_id: str = "") -> WalletKeyset:
        assert len(
            self.url
        ), "Ledger not initialized correctly: mint URL not specified yet. "

        if keyset_id:
            # get requested keyset
            keyset = await self._get_keys_of_keyset(self.url, keyset_id)
        else:
            # get current keyset
            keyset = await self._get_keys(self.url)

        assert keyset.public_keys
        assert keyset.id
        assert len(keyset.public_keys) > 0, "did not receive keys from mint."

        # check if current keyset is in db
        keyset_local: Optional[WalletKeyset] = await get_keyset(keyset.id, db=self.db)
        # if not, store it
        if keyset_local is None:
            logger.debug(f"Storing new mint keyset: {keyset.id}")
            await store_keyset(keyset=keyset, db=self.db)

        self.keys = keyset
        assert self.keys.public_keys
        self.public_keys = self.keys.public_keys
        assert self.keys.id
        self.keyset_id = self.keys.id
        logger.debug(f"Current mint keyset: {self.keys.id}")
        return self.keys

    async def _load_mint_keysets(self) -> List[str]:
        # get all active keysets of this mint
        mint_keysets = []
        try:
            mint_keysets = await self._get_keyset_ids(self.url)
        except:
            assert self.keys.id, "could not get keysets from mint, and do not have keys"
            pass
        self.keysets = mint_keysets or [self.keys.id]
        logger.debug(f"Mint keysets: {self.keysets}")
        return self.keysets

    async def _load_mint_info(self) -> GetInfoResponse:
        """Loads the mint info from the mint."""
        self.mint_info = await self._get_info(self.url)
        logger.debug(f"Mint info: {self.mint_info}")
        return self.mint_info

    async def _load_mint(self, keyset_id: str = "") -> None:
        """
        Loads the public keys of the mint. Either gets the keys for the specified
        `keyset_id` or gets the keys of the active keyset from the mint.
        Gets the active keyset ids of the mint and stores in `self.keysets`.
        """
        await self._load_mint_keys(keyset_id)
        await self._load_mint_keysets()
        await self._load_mint_info()

        if keyset_id:
            assert keyset_id in self.keysets, f"keyset {keyset_id} not active on mint"

    @staticmethod
    def _construct_outputs(
        amounts: List[int], secrets: List[str]
    ) -> Tuple[List[BlindedMessage], List[PrivateKey]]:
        """Takes a list of amounts and secrets and returns outputs.
        Outputs are blinded messages `outputs` and blinding factors `rs`

        Args:
            amounts (List[int]): List of amounts
            secrets (List[str]): List of secrets

        Returns:
            Tuple[List[BlindedMessage], List[PrivateKey]]: Tuple of blinded messages and blinding factors

        Raises:
            Exception: If len(amounts) != len(secrets)
        """
        logger.trace(f"Constructing outputs.")
        assert len(amounts) == len(
            secrets
        ), f"len(amounts)={len(amounts)} not equal to len(secrets)={len(secrets)}"
        outputs: List[BlindedMessage] = []
        rs: List[PrivateKey] = []
        for secret, amount in zip(secrets, amounts):
            B_, r = b_dhke.step1_alice(secret)
            rs.append(r)
            output: BlindedMessage = BlindedMessage(
                amount=amount, B_=B_.serialize().hex()
            )
            outputs.append(output)
        logger.trace(f"Constructed {len(outputs)} outputs.")
        return outputs, rs

    async def _check_used_secrets(self, secrets) -> None:
        """Checks if any of the secrets have already been used

        Args:
            secrets (List[str]): List of secrets to check

        Raises:
            Exception: If any of the secrets have already been used
        """
        logger.trace("Checking secrets.")
        for s in secrets:
            if await secret_used(s, db=self.db):
                raise Exception(f"secret already used: {s}")
        logger.trace("Secret check complete.")

    """
    ENDPOINTS
    """

    @async_set_requests
    async def _get_keys(self, url: str) -> WalletKeyset:
        """API that gets the current keys of the mint

        Args:
            url (str): Mint URL

        Returns:
            WalletKeyset: Current mint keyset

        Raises:
            Exception: If no keys are received from the mint
        """
        resp = self.s.get(
            url + "/keys",
        )
        resp.raise_for_status()
        keys: dict = resp.json()
        assert len(keys), Exception("did not receive any keys")
        keyset_keys = {
            int(amt): PublicKey(bytes.fromhex(val), raw=True)
            for amt, val in keys.items()
        }
        keyset = WalletKeyset(public_keys=keyset_keys, mint_url=url)
        return keyset

    @async_set_requests
    async def _get_keys_of_keyset(self, url: str, keyset_id: str) -> WalletKeyset:
        """API that gets the keys of a specific keyset from the mint.


        Args:
            url (str): Mint URL
            keyset_id (str): base64 keyset ID, needs to be urlsafe-encoded before sending to mint (done in this method)

        Returns:
            WalletKeyset: Keyset with ID keyset_id

        Raises:
            Exception: If no keys are received from the mint
        """
        keyset_id_urlsafe = keyset_id.replace("+", "-").replace("/", "_")
        resp = self.s.get(
            url + f"/keys/{keyset_id_urlsafe}",
        )
        resp.raise_for_status()
        keys = resp.json()
        self.raise_on_error(keys)
        assert len(keys), Exception("did not receive any keys")
        keyset_keys = {
            int(amt): PublicKey(bytes.fromhex(val), raw=True)
            for amt, val in keys.items()
        }
        keyset = WalletKeyset(id=keyset_id, public_keys=keyset_keys, mint_url=url)
        return keyset

    @async_set_requests
    async def _get_keyset_ids(self, url: str) -> List[str]:
        """API that gets a list of all active keysets of the mint.

        Args:
            url (str): Mint URL

        Returns:
            KeysetsResponse (List[str]): List of all active keyset IDs of the mint

        Raises:
            Exception: If no keysets are received from the mint
        """
        resp = self.s.get(
            url + "/keysets",
        )
        resp.raise_for_status()
        keysets_dict = resp.json()
        keysets = KeysetsResponse.parse_obj(keysets_dict)
        assert len(keysets.keysets), Exception("did not receive any keysets")
        return keysets.keysets

    @async_set_requests
    async def _get_info(self, url: str) -> GetInfoResponse:
        """API that gets the mint info.

        Args:
            url (str): Mint URL

        Returns:
            GetInfoResponse: Current mint info

        Raises:
            Exception: If the mint info request fails
        """
        resp = self.s.get(
            url + "/info",
        )
        resp.raise_for_status()
        data: dict = resp.json()
        mint_info: GetInfoResponse = GetInfoResponse.parse_obj(data)
        return mint_info

    @async_set_requests
    async def request_mint(self, amount) -> Invoice:
        """Requests a mint from the server and returns Lightning invoice.

        Args:
            amount (int): Amount of tokens to mint

        Returns:
            Invoice: Lightning invoice

        Raises:
            Exception: If the mint request fails
        """
        logger.trace("Requesting mint: GET /mint")
        resp = self.s.get(self.url + "/mint", params={"amount": amount})
        resp.raise_for_status()
        return_dict = resp.json()
        self.raise_on_error(return_dict)
        mint_response = GetMintResponse.parse_obj(return_dict)
        return Invoice(amount=amount, pr=mint_response.pr, hash=mint_response.hash)

    @async_set_requests
    async def mint(self, amounts, hash=None) -> List[Proof]:
        """Mints new coins and returns a proof of promise.

        Args:
            amounts (List[int]): Amounts of tokens to mint
            hash (str, optional): Hash of the paid invoice. Defaults to None.

        Returns:
            list[Proof]: List of proofs.

        Raises:
            Exception: If the minting fails
        """
        secrets = [self._generate_secret() for s in range(len(amounts))]
        await self._check_used_secrets(secrets)
        outputs, rs = self._construct_outputs(amounts, secrets)
        outputs_payload = PostMintRequest(outputs=outputs)
        logger.trace("Checking Lightning invoice. POST /mint")
        resp = self.s.post(
            self.url + "/mint",
            json=outputs_payload.dict(),
            params={
                "hash": hash,
                "payment_hash": hash,  # backwards compatibility pre 0.12.0
            },
        )
        resp.raise_for_status()
        reponse_dict = resp.json()
        self.raise_on_error(reponse_dict)
        logger.trace("Lightning invoice checked. POST /mint")
        try:
            # backwards compatibility: parse promises < 0.8.0 with no "promises" field
            promises = PostMintResponseLegacy.parse_obj(reponse_dict).__root__
        except:
            promises = PostMintResponse.parse_obj(reponse_dict).promises

        return self._construct_proofs(promises, secrets, rs)

    @async_set_requests
    async def split(
        self,
        proofs: List[Proof],
        outputs: List[BlindedMessage],
        secrets: List[str],
        rs: List[PrivateKey],
        amount: int,
        secret_lock: Optional[Secret] = None,
    ) -> Tuple[List[BlindedSignature], List[BlindedSignature]]:
        """Consume proofs and create new promises based on amount split.

        If secret_lock is None, random secrets will be generated for the tokens to keep (frst_outputs)
        and the promises to send (scnd_outputs).

        If secret_lock is provided, the wallet will create blinded secrets with those to attach a
        predefined spending condition to the tokens they want to send."""
        logger.debug("Calling split. POST /split")
        split_payload = PostSplitRequest(proofs=proofs, amount=amount, outputs=outputs)

        # construct payload
        def _splitrequest_include_fields(proofs):
            """strips away fields from the model that aren't necessary for the /split"""
            proofs_include = {"id", "amount", "secret", "C", "p2shscript", "p2pksig"}
            return {
                "amount": ...,
                "outputs": ...,
                "proofs": {i: proofs_include for i in range(len(proofs))},
            }

        resp = self.s.post(
            self.url + "/split",
            json=split_payload.dict(include=_splitrequest_include_fields(proofs)),  # type: ignore
        )
        resp.raise_for_status()
        promises_dict = resp.json()
        self.raise_on_error(promises_dict)

        promises_fst = [BlindedSignature(**p) for p in promises_dict["fst"]]
        promises_snd = [BlindedSignature(**p) for p in promises_dict["snd"]]

        if len(promises_fst) == 0 and len(promises_snd) == 0:
            raise Exception("received no splits.")

        return promises_fst, promises_snd

    @async_set_requests
    async def check_proof_state(self, proofs: List[Proof]):
        """
        Cheks whether the secrets in proofs are already spent or not and returns a list of booleans.
        """
        payload = CheckSpendableRequest(proofs=proofs)

        def _check_proof_state_include_fields(proofs):
            """strips away fields from the model that aren't necessary for the /split"""
            return {
                "proofs": {i: {"secret"} for i in range(len(proofs))},
            }

        resp = self.s.post(
            self.url + "/check",
            json=payload.dict(include=_check_proof_state_include_fields(proofs)),  # type: ignore
        )
        resp.raise_for_status()
        return_dict = resp.json()
        self.raise_on_error(return_dict)
        states = CheckSpendableResponse.parse_obj(return_dict)
        return states

    @async_set_requests
    async def check_fees(self, payment_request: str):
        """Checks whether the Lightning payment is internal."""
        payload = CheckFeesRequest(pr=payment_request)
        resp = self.s.post(
            self.url + "/checkfees",
            json=payload.dict(),
        )
        resp.raise_for_status()
        return_dict = resp.json()
        self.raise_on_error(return_dict)
        return return_dict

    @async_set_requests
    async def pay_lightning(
        self, proofs: List[Proof], invoice: str, outputs: Optional[List[BlindedMessage]]
    ):
        """
        Accepts proofs and a lightning invoice to pay in exchange.
        """

        payload = PostMeltRequest(proofs=proofs, pr=invoice, outputs=outputs)

        def _meltrequest_include_fields(proofs):
            """strips away fields from the model that aren't necessary for the /melt"""
            proofs_include = {"id", "amount", "secret", "C", "script"}
            return {
                "proofs": {i: proofs_include for i in range(len(proofs))},
                "pr": ...,
                "outputs": ...,
            }

        resp = self.s.post(
            self.url + "/melt",
            json=payload.dict(include=_meltrequest_include_fields(proofs)),  # type: ignore
        )
        resp.raise_for_status()
        return_dict = resp.json()
        self.raise_on_error(return_dict)
        return GetMeltResponse.parse_obj(return_dict)


class Wallet(LedgerAPI):
    """Minimal wallet wrapper."""

    private_key: Optional[PrivateKey] = None

    def __init__(self, url: str, db: str, name: str = "no_name"):
        super().__init__(url)
        self.db = Database("wallet", db)
        self.proofs: List[Proof] = []
        self.name = name
        logger.debug(f"Wallet initalized with mint URL {url}")

        # temporarily, we use the NostrClient to generate keys
        try:
            nostr_pk = NostrClient(
                private_key=settings.nostr_private_key, connect=False
            ).private_key
            self.private_key = (
                PrivateKey(bytes.fromhex(nostr_pk.hex()), raw=True) or None
            )
        except Exception as e:
            pass

    # ---------- API ----------

    async def load_mint(self, keyset_id: str = ""):
        """Load a mint's keys with a given keyset_id if specified or else
        loads the active keyset of the mint into self.keys.
        Also loads all keyset ids into self.keysets.

        Args:
            keyset_id (str, optional): _description_. Defaults to "".
        """
        await super()._load_mint(keyset_id)

    async def load_proofs(self, reload: bool = False):
        """Load all proofs from the database."""

        if self.proofs and not reload:
            logger.debug("Proofs already loaded.")
            return
        self.proofs = await get_proofs(db=self.db)

    async def request_mint(self, amount):
        invoice = await super().request_mint(amount)
        invoice.time_created = int(time.time())
        await store_lightning_invoice(db=self.db, invoice=invoice)
        return invoice

    async def mint(
        self,
        amount: int,
        split: Optional[List[int]] = None,
        hash: Optional[str] = None,
    ):
        """Mint tokens of a specific amount after an invoice has been paid.

        Args:
            amount (int): Total amount of tokens to be minted
            split (Optional[List[str]], optional): List of desired amount splits to be minted. Total must sum to `amount`.
            hash (Optional[str], optional): Hash for looking up the paid Lightning invoice. Defaults to None (for testing with LIGHTNING=False).

        Raises:
            Exception: Raises exception if `amounts` does not sum to `amount` or has unsupported value.
            Exception: Raises exception if no proofs have been provided

        Returns:
            List[Proof]: Newly minted proofs.
        """
        # specific split
        if split:
            logger.trace(f"Mint with split: {split}")
            assert sum(split) == amount, "split must sum to amount"
            allowed_amounts = [2**i for i in range(settings.max_order)]
            for a in split:
                if a not in allowed_amounts:
                    raise Exception(
                        f"Can only mint amounts with 2^n up to {2**settings.max_order}."
                    )

        # if no split was specified, we use the canonical split
        amounts = split or amount_split(amount)
        proofs = await super().mint(amounts, hash)
        if proofs == []:
            raise Exception("received no proofs.")
        await self._store_proofs(proofs)
        if hash:
            await update_lightning_invoice(
                db=self.db, hash=hash, paid=True, time_paid=int(time.time())
            )
        self.proofs += proofs
        return proofs

    async def add_witnesses_to_proofs(self, proofs: List[Proof]):
        """Adds witnesses to proofs for P2SH or P2PK redemption."""

        p2sh_script, p2sh_signature = None, None
        p2pk_signatures = None

        # iterate through proofs and produce witnesses for each

        # first we check whether all tokens have serialized secrets as their secret
        try:
            for p in proofs:
                Secret.deserialize(p.secret)
        except:
            # if not, we do not add witnesses (treat as regular token secret)
            return proofs
        # P2SH scripts
        if all([Secret.deserialize(p.secret).kind == SecretKind.P2SH for p in proofs]):
            # Quirk: we use a single P2SH script and signature pair for all tokens in proofs
            address = Secret.deserialize(proofs[0].secret).data
            p2shscripts = await get_unused_locks(address, db=self.db)
            assert len(p2shscripts) == 1, Exception("lock not found.")
            p2sh_script, p2sh_signature = (
                p2shscripts[0].script,
                p2shscripts[0].signature,
            )
            logger.debug(f"Unlock script: {p2sh_script} signature: {p2sh_signature}")

            # attach unlock scripts to proofs
            for p in proofs:
                p.p2shscript = P2SHScript(script=p2sh_script, signature=p2sh_signature)

        # P2PK signatures
        elif all(
            [Secret.deserialize(p.secret).kind == SecretKind.P2PK for p in proofs]
        ):
            p2pk_signatures = await self.sign_p2pk_proofs(proofs)
            logger.debug(f"Unlock signature: {p2pk_signatures}")

            # attach unlock signatures to proofs
            assert len(proofs) == len(p2pk_signatures), "wrong number of signatures"
            for p, s in zip(proofs, p2pk_signatures):
                p.p2pksig = s

        return proofs

    async def redeem(
        self,
        proofs: List[Proof],
    ):
        return await self.split(proofs, sum_proofs(proofs))

    async def split(
        self,
        proofs: List[Proof],
        amount: int,
        secret_lock: Optional[Secret] = None,
    ):
        assert len(proofs) > 0, ValueError("no proofs provided.")

        # potentially add witnesses to unlock provided proofs (if they indicate one)
        proofs = await self.add_witnesses_to_proofs(proofs)

        # create a suitable amount split based on the proofs provided
        total = sum_proofs(proofs)
        frst_amt, scnd_amt = total - amount, amount
        frst_outputs = amount_split(frst_amt)
        scnd_outputs = amount_split(scnd_amt)

        amounts = frst_outputs + scnd_outputs
        # generate secrets for new outputs
        if secret_lock is None:
            # generate all secrets randomly
            secrets = [self._generate_secret() for _ in range(len(amounts))]
        else:
            # use provided secret_lock to generate secrets
            secret_locks = [secret_lock.serialize() for i in range(len(scnd_outputs))]
            logger.debug(f"Creating proofs with custom secrets: {secret_locks}")
            assert len(secret_locks) == len(
                scnd_outputs
            ), "number of secret_locks does not match number of ouptus."
            # append custom locks (to send) to randomly generated secrets (to keep)
            secrets = [
                self._generate_secret() for s in range(len(frst_outputs))
            ] + secret_locks

        assert len(secrets) == len(
            amounts
        ), "number of secrets does not match number of outputs"
        # verify that we didn't accidentally reuse a secret
        await self._check_used_secrets(secrets)

        # construct outputs
        outputs, rs = self._construct_outputs(amounts, secrets)

        # Call /split API
        promises_fst, promises_snd = await super().split(
            proofs, outputs, secrets, rs, amount, secret_lock
        )

        # Construct proofs from returned promises (i.e., unblind the signatures)
        frst_proofs = self._construct_proofs(
            promises_fst, secrets[: len(promises_fst)], rs[: len(promises_fst)]
        )
        scnd_proofs = self._construct_proofs(
            promises_snd, secrets[len(promises_fst) :], rs[len(promises_fst) :]
        )

        # remove used proofs from wallet and add new ones
        used_secrets = [p.secret for p in proofs]
        self.proofs = list(filter(lambda p: p.secret not in used_secrets, self.proofs))
        # add new proofs to wallet
        self.proofs += frst_proofs + scnd_proofs
        # store new proofs in database
        await self._store_proofs(frst_proofs + scnd_proofs)
        # invalidate used proofs in database
        for proof in proofs:
            await invalidate_proof(proof, db=self.db)
        return frst_proofs, scnd_proofs

    async def pay_lightning(self, proofs: List[Proof], invoice: str, fee_reserve: int):
        """Pays a lightning invoice"""

        # Generate a number of blank outputs for any overpaid fees. As described in
        # NUT-08, the mint will imprint these outputs with a value depending on the
        # amount of fees we overpaid.
        n_return_outputs = calculate_number_of_blank_outputs(fee_reserve)
        secrets = [self._generate_secret() for _ in range(n_return_outputs)]
        outputs, rs = self._construct_outputs(n_return_outputs * [1], secrets)

        status = await super().pay_lightning(proofs, invoice, outputs)

        if status.paid == True:
            # the payment was successful
            await self.invalidate(proofs)
            invoice_obj = Invoice(
                amount=-sum_proofs(proofs),
                pr=invoice,
                preimage=status.preimage,
                paid=True,
                time_paid=time.time(),
                hash="",
            )
            # we have a unique constraint on the hash, so we generate a random one if it doesn't exist
            invoice_obj.hash = invoice_obj.hash or self._generate_secret()
            await store_lightning_invoice(db=self.db, invoice=invoice_obj)

            # handle change and produce proofs
            if status.change:
                change_proofs = self._construct_proofs(
                    status.change,
                    secrets[: len(status.change)],
                    rs[: len(status.change)],
                )
                logger.debug(f"Received change: {sum_proofs(change_proofs)} sat")
                await self._store_proofs(change_proofs)

        else:
            raise Exception("could not pay invoice.")
        return status.paid

    async def check_proof_state(self, proofs):
        return await super().check_proof_state(proofs)

    # ---------- TOKEN MECHANIS ----------

    async def _store_proofs(self, proofs):
        for proof in proofs:
            await store_proof(proof, db=self.db)

    @staticmethod
    def _get_proofs_per_keyset(proofs: List[Proof]):
        return {key: list(group) for key, group in groupby(proofs, lambda p: p.id)}

    async def _get_proofs_per_minturl(self, proofs: List[Proof]):
        ret = {}
        for id in set([p.id for p in proofs]):
            if id is None:
                continue
            keyset_crud = await get_keyset(id=id, db=self.db)
            assert keyset_crud is not None, "keyset not found"
            keyset: WalletKeyset = keyset_crud
            if keyset.mint_url not in ret:
                ret[keyset.mint_url] = [p for p in proofs if p.id == id]
            else:
                ret[keyset.mint_url].extend([p for p in proofs if p.id == id])
        return ret

    def _get_proofs_keysets(self, proofs: List[Proof]):
        """Extracts all keyset ids from a list of proofs.

        Args:
            proofs (List[Proof]): List of proofs to get the keyset id's of
        """
        keysets: List[str] = [proof.id for proof in proofs if proof.id]
        return keysets

    async def _get_keyset_urls(self, keysets: List[str]):
        """Retrieves the mint URLs for a list of keyset id's from the wallet's database.
        Returns a dictionary from URL to keyset ID

        Args:
            keysets (List[str]): List of keysets.
        """
        mint_urls: Dict[str, List[str]] = {}
        for ks in set(keysets):
            keyset_db = await get_keyset(id=ks, db=self.db)
            if keyset_db and keyset_db.mint_url:
                mint_urls[keyset_db.mint_url] = (
                    mint_urls[keyset_db.mint_url] + [ks]
                    if mint_urls.get(keyset_db.mint_url)
                    else [ks]
                )
        return mint_urls

    async def _make_token(self, proofs: List[Proof], include_mints=True):
        """
        Takes list of proofs and produces a TokenV3 by looking up
        the mint URLs by the keyset id from the database.
        """
        token = TokenV3()

        if include_mints:
            # we create a map from mint url to keyset id and then group
            # all proofs with their mint url to build a tokenv3

            # extract all keysets from proofs
            keysets = self._get_proofs_keysets(proofs)
            # get all mint URLs for all unique keysets from db
            mint_urls = await self._get_keyset_urls(keysets)

            # append all url-grouped proofs to token
            for url, ids in mint_urls.items():
                mint_proofs = [p for p in proofs if p.id in ids]
                token.token.append(TokenV3Token(mint=url, proofs=mint_proofs))
        else:
            token_proofs = TokenV3Token(proofs=proofs)
            token.token.append(token_proofs)
        return token

    async def serialize_proofs(
        self, proofs: List[Proof], include_mints=True, legacy=False
    ):
        """
        Produces sharable token with proofs and mint information.
        """

        if legacy:
            # V2 tokens
            token = await self._make_token_v2(proofs, include_mints)
            return await self._serialize_token_base64_tokenv2(token)

            # # deprecated code for V1 tokens
            # proofs_serialized = [p.to_dict() for p in proofs]
            # return base64.urlsafe_b64encode(
            #     json.dumps(proofs_serialized).encode()
            # ).decode()

        # V3 tokens
        token = await self._make_token(proofs, include_mints)
        return token.serialize()

    async def _make_token_v2(self, proofs: List[Proof], include_mints=True):
        """
        Takes list of proofs and produces a TokenV2 by looking up
        the keyset id and mint URLs from the database.
        """
        # build token
        token = TokenV2(proofs=proofs)
        # add mint information to the token, if requested
        if include_mints:
            # dummy object to hold information about the mint
            mints: Dict[str, TokenV2Mint] = {}
            # dummy object to hold all keyset id's we need to fetch from the db later
            keysets: List[str] = [proof.id for proof in proofs if proof.id]
            # iterate through unique keyset ids
            for id in set(keysets):
                # load the keyset from the db
                keyset_db = await get_keyset(id=id, db=self.db)
                if keyset_db and keyset_db.mint_url and keyset_db.id:
                    # we group all mints according to URL
                    if keyset_db.mint_url not in mints:
                        mints[keyset_db.mint_url] = TokenV2Mint(
                            url=keyset_db.mint_url,
                            ids=[keyset_db.id],
                        )
                    else:
                        # if a mint URL has multiple keysets, append to the already existing list
                        mints[keyset_db.mint_url].ids.append(keyset_db.id)
            if len(mints) > 0:
                # add mints grouped by url to the token
                token.mints = list(mints.values())
        return token

    async def _serialize_token_base64_tokenv2(self, token: TokenV2):
        """
        Takes a TokenV2 and serializes it in urlsafe_base64.
        """
        # encode the token as a base64 string
        token_base64 = base64.urlsafe_b64encode(
            json.dumps(token.to_dict()).encode()
        ).decode()
        return token_base64

    async def _select_proofs_to_send(self, proofs: List[Proof], amount_to_send: int):
        """
        Selects proofs that can be used with the current mint. Implements a simple coin selection algorithm.

        The algorithm has two objectives: Get rid of all tokens from old epochs and include additional proofs from
        the current epoch starting from the proofs with the largest amount.

        Rules:
        1) Proofs that are not marked as reserved
        2) Proofs that have a keyset id that is in self.keysets (all active keysets of mint)
        3) Include all proofs that have an older keyset than the current keyset of the mint (to get rid of old epochs).
        4) If the target amount is not reached, add proofs of the current keyset until it is.
        """
        send_proofs: List[Proof] = []

        # select proofs that are not reserved
        proofs = [p for p in proofs if not p.reserved]

        # select proofs that are in the active keysets of the mint
        proofs = [p for p in proofs if p.id in self.keysets or not p.id]

        # check that enough spendable proofs exist
        if sum_proofs(proofs) < amount_to_send:
            raise Exception("balance too low.")

        # add all proofs that have an older keyset than the current keyset of the mint
        proofs_old_epochs = [p for p in proofs if p.id != self.keys.id]
        send_proofs += proofs_old_epochs

        # coinselect based on amount only from the current keyset
        # start with the proofs with the largest amount and add them until the target amount is reached
        proofs_current_epoch = [p for p in proofs if p.id == self.keys.id]
        sorted_proofs_of_current_keyset = sorted(
            proofs_current_epoch, key=lambda p: p.amount
        )

        while sum_proofs(send_proofs) < amount_to_send:
            proof_to_add = sorted_proofs_of_current_keyset.pop()
            send_proofs.append(proof_to_add)
        return send_proofs

    async def set_reserved(self, proofs: List[Proof], reserved: bool):
        """Mark a proof as reserved to avoid reuse or delete marking."""
        uuid_str = str(uuid.uuid1())
        for proof in proofs:
            proof.reserved = True
            await update_proof_reserved(
                proof, reserved=reserved, send_id=uuid_str, db=self.db
            )

    async def invalidate(self, proofs: List[Proof], check_spendable=True):
        """Invalidates all unspendable tokens supplied in proofs.

        Args:
            proofs (List[Proof]): Which proofs to delete
            check_spendable (bool, optional): Asks the mint to check whether proofs are already spent before deleting them. Defaults to True.
        """
        invalidated_proofs: List[Proof] = []
        if check_spendable:
            proof_states = await self.check_proof_state(proofs)
            for i, spendable in enumerate(proof_states.spendable):
                if not spendable:
                    invalidated_proofs.append(proofs[i])
        else:
            invalidated_proofs = proofs

        for p in invalidated_proofs:
            await invalidate_proof(p, db=self.db)
        invalidate_secrets = [p.secret for p in invalidated_proofs]
        self.proofs = list(
            filter(lambda p: p.secret not in invalidate_secrets, self.proofs)
        )

    # ---------- TRANSACTION HELPERS ----------

    async def get_pay_amount_with_fees(self, invoice: str):
        """
        Decodes the amount from a Lightning invoice and returns the
        total amount (amount+fees) to be paid.
        """
        decoded_invoice: InvoiceBolt11 = bolt11.decode(invoice)
        # check if it's an internal payment
        fees = int((await self.check_fees(invoice))["fee"])
        logger.debug(f"Mint wants {fees} sat as fee reserve.")
        amount = math.ceil((decoded_invoice.amount_msat + fees * 1000) / 1000)  # 1% fee
        return amount, fees

    async def split_to_send(
        self,
        proofs: List[Proof],
        amount: int,
        secret_lock: Optional[Secret] = None,
        set_reserved: bool = False,
    ):
        """
        Splits proofs such that a certain amount can be sent.

        Args:
            proofs (List[Proof]): Proofs to split
            amount (int): Amount to split to
            secret_lock (Optional[str], optional): If set, a custom secret is used to lock new outputs. Defaults to None.
            set_reserved (bool, optional): If set, the proofs are marked as reserved. Should be set to False if a payment attempt
            is made with the split that could fail (like a Lightning payment). Should be set to True if the token to be sent is
            displayed to the user to be then sent to someone else. Defaults to False.
        """
        if secret_lock:
            logger.debug(f"Spending conditions: {secret_lock}")
        spendable_proofs = await self._select_proofs_to_send(proofs, amount)

        keep_proofs, send_proofs = await self.split(
            spendable_proofs, amount, secret_lock
        )
        if set_reserved:
            await self.set_reserved(send_proofs, reserved=True)
        return keep_proofs, send_proofs

    # ---------- P2SH and P2PK ----------

    async def create_p2sh_address_and_store(self) -> str:
        """Creates a P2SH lock script and stores the script and signature in the database."""
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
        assert p2shScript.address
        return p2shScript.address

    async def create_p2pk_pubkey(self):
        assert (
            self.private_key
        ), "No private key set in settings. Set NOSTR_PRIVATE_KEY in .env"
        public_key = self.private_key.pubkey
        # logger.debug(f"Private key: {self.private_key.bech32()}")
        assert public_key
        return public_key.serialize().hex()

    async def create_p2pk_lock(
        self,
        pubkey: str,
        timelock: Optional[int] = None,
        tags: Optional[Tags] = None,
    ):
        return Secret(
            kind=SecretKind.P2PK,
            data=pubkey,
            timelock=int((datetime.now() + timedelta(seconds=timelock)).timestamp())
            if timelock
            else None,
            tags=tags,
        )

    async def create_p2sh_lock(
        self,
        address: str,
        timelock: Optional[int] = None,
        tags: Optional[Tags] = None,
    ):
        return Secret(
            kind=SecretKind.P2SH,
            data=address,
            timelock=int((datetime.now() + timedelta(seconds=timelock)).timestamp())
            if timelock
            else None,
            tags=tags,
        )

    async def sign_p2pk_proofs(self, proofs: List[Proof]) -> List[str]:
        assert (
            self.private_key
        ), "No private key set in settings. Set NOSTR_PRIVATE_KEY in .env"
        private_key = self.private_key
        assert private_key.pubkey
        return [
            sign_p2pk_sign(
                message=proof.secret.encode("utf-8"),
                private_key=private_key,
            )
            for proof in proofs
        ]

    # ---------- BALANCE CHECKS ----------

    @property
    def balance(self):
        return sum_proofs(self.proofs)

    @property
    def available_balance(self):
        return sum_proofs([p for p in self.proofs if not p.reserved])

    @property
    def proof_amounts(self):
        """Returns a sorted list of amounts of all proofs"""
        return [p.amount for p in sorted(self.proofs, key=lambda p: p.amount)]

    def status(self):
        print(f"Balance: {self.available_balance} sat")

    def balance_per_keyset(self):
        return {
            key: {
                "balance": sum_proofs(proofs),
                "available": sum_proofs([p for p in proofs if not p.reserved]),
            }
            for key, proofs in self._get_proofs_per_keyset(self.proofs).items()
        }

    async def balance_per_minturl(self):
        balances = await self._get_proofs_per_minturl(self.proofs)
        balances_return = {
            key: {
                "balance": sum_proofs(proofs),
                "available": sum_proofs([p for p in proofs if not p.reserved]),
            }
            for key, proofs in balances.items()
        }
        return dict(sorted(balances_return.items(), key=lambda item: item[0]))  # type: ignore
