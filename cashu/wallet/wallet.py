import base64
import json
import math
import secrets as scrts
import time
import uuid
from itertools import groupby
from typing import Dict, List, Optional, Tuple, Union

import requests
from bip32 import BIP32
from loguru import logger
from requests import Response

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
    PostMeltRequest,
    PostMintRequest,
    PostMintResponse,
    PostRestoreResponse,
    PostSplitRequest,
    Proof,
    Secret,
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
from ..core.migrations import migrate_databases
from ..core.settings import settings
from ..core.split import amount_split
from ..tor.tor import TorProxy
from ..wallet.crud import (
    bump_secret_derivation,
    get_keyset,
    get_proofs,
    invalidate_proof,
    secret_used,
    set_secret_derivation,
    store_keyset,
    store_lightning_invoice,
    store_proof,
    update_lightning_invoice,
    update_proof_reserved,
)
from . import migrations
from .p2pk import WalletP2PK
from .secrets import WalletSecrets


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
            proxy_url = "socks5://localhost:9050"
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


class LedgerAPI(object):
    keys: WalletKeyset  # holds current keys of mint
    keyset_id: str  # holds id of current keyset
    public_keys: Dict[int, PublicKey]  # holds public keys of
    mint_info: GetInfoResponse  # holds info about mint
    tor: TorProxy
    s: requests.Session
    db: Database

    def __init__(self, url: str, db: Database):
        self.url = url
        self.s = requests.Session()
        self.db = db

    # async def generate_n_secrets(
    #     self, n: int = 1, skip_bump: bool = False
    # ) -> Tuple[List[str], List[PrivateKey], List[str]]:
    #     return await self.generate_n_secrets(n, skip_bump)

    # async def _generate_secret(self, skip_bump: bool = False) -> str:
    #     return await self._generate_secret(skip_bump)

    @async_set_requests
    async def _init_s(self):
        """Dummy function that can be called from outside to use LedgerAPI.s"""
        return

    def _construct_proofs(
        self,
        promises: List[BlindedSignature],
        secrets: List[str],
        rs: List[PrivateKey],
        derivation_paths: List[str],
    ) -> List[Proof]:
        """Constructs proofs from promises, secrets, rs and derivation paths.

        This method is called after the user has received blind signatures from
        the mint. The results are proofs that can be used as ecash.

        Args:
            promises (List[BlindedSignature]): blind signatures from mint
            secrets (List[str]): secrets that were previously used to create blind messages (that turned into promises)
            rs (List[PrivateKey]): blinding factors that were previously used to create blind messages (that turned into promises)
            derivation_paths (List[str]): derivation paths that were used to generate secrets and blinding factors

        Returns:
            List[Proof]: list of proofs that can be used as ecash
        """
        logger.trace("Constructing proofs.")
        proofs: List[Proof] = []
        for promise, secret, r, path in zip(promises, secrets, rs, derivation_paths):
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
                derivation_path=path,
            )
            proofs.append(proof)
            logger.trace(
                f"Created proof: {proof}, r: {r.serialize()} out of promise {promise}"
            )

        logger.trace(f"Constructed {len(proofs)} proofs.")
        return proofs

    @staticmethod
    def _construct_outputs(
        amounts: List[int], secrets: List[str], rs: List[PrivateKey] = []
    ) -> Tuple[List[BlindedMessage], List[PrivateKey]]:
        """Takes a list of amounts and secrets and returns outputs.
        Outputs are blinded messages `outputs` and blinding factors `rs`

        Args:
            amounts (List[int]): list of amounts
            secrets (List[str]): list of secrets
            rs (List[PrivateKey], optional): list of blinding factors. If not given, `rs` are generated in step1_alice. Defaults to [].

        Returns:
            List[BlindedMessage]: list of blinded messages that can be sent to the mint
            List[PrivateKey]: list of blinding factors that can be used to construct proofs after receiving blind signatures from the mint

        Raises:
            AssertionError: if len(amounts) != len(secrets)
        """
        assert len(amounts) == len(
            secrets
        ), f"len(amounts)={len(amounts)} not equal to len(secrets)={len(secrets)}"
        outputs: List[BlindedMessage] = []

        rs_ = [None] * len(amounts) if not rs else rs
        rs_return: List[PrivateKey] = []
        for secret, amount, r in zip(secrets, amounts, rs_):
            B_, r = b_dhke.step1_alice(secret, r or None)
            rs_return.append(r)
            output = BlindedMessage(amount=amount, B_=B_.serialize().hex())
            outputs.append(output)
            logger.trace(f"Constructing output: {output}, r: {r.serialize()}")

        return outputs, rs_return

    @staticmethod
    def raise_on_error(resp: Response) -> None:
        """Raises an exception if the response from the mint contains an error.

        Args:
            resp_dict (Response): Response dict (previously JSON) from mint

        Raises:
            Exception: if the response contains an error
        """
        resp_dict = resp.json()
        if "detail" in resp_dict:
            logger.trace(f"Error from mint: {resp_dict}")
            error_message = f"Mint Error: {resp_dict['detail']}"
            if "code" in resp_dict:
                error_message += f" (Code: {resp_dict['code']})"
            raise Exception(error_message)
        # raise for status if no error
        resp.raise_for_status()

    async def _load_mint_keys(self, keyset_id: str = "") -> WalletKeyset:
        """Loads keys from mint and stores them in the database.

        Args:
            keyset_id (str, optional): keyset id to load. If given, requests keys for this keyset
            from the mint. If not given, requests current keyset of the mint. Defaults to "".

        Raises:
            AssertionError: if mint URL is not set
            AssertionError: if no keys are received from the mint
        """
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
        """Loads the keyset IDs of the mint.

        Returns:
            List[str]: list of keyset IDs of the mint

        Raises:
            AssertionError: if no keysets are received from the mint
        """
        mint_keysets = []
        try:
            mint_keysets = await self._get_keyset_ids(self.url)
        except Exception:
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
        try:
            await self._load_mint_info()
        except Exception as e:
            logger.debug(f"Could not load mint info: {e}")
            pass

        if keyset_id:
            assert keyset_id in self.keysets, f"keyset {keyset_id} not active on mint"

    async def _check_used_secrets(self, secrets):
        """Checks if any of the secrets have already been used"""
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
        self.raise_on_error(resp)
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
        self.raise_on_error(resp)
        keys = resp.json()
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
        self.raise_on_error(resp)
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
        self.raise_on_error(resp)
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
        self.raise_on_error(resp)
        return_dict = resp.json()
        mint_response = GetMintResponse.parse_obj(return_dict)
        return Invoice(amount=amount, pr=mint_response.pr, hash=mint_response.hash)

    @async_set_requests
    async def mint(
        self, outputs: List[BlindedMessage], hash: Optional[str] = None
    ) -> List[BlindedSignature]:
        """Mints new coins and returns a proof of promise.

        Args:
            outputs (List[BlindedMessage]): Outputs to mint new tokens with
            hash (str, optional): Hash of the paid invoice. Defaults to None.

        Returns:
            list[Proof]: List of proofs.

        Raises:
            Exception: If the minting fails
        """
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
        self.raise_on_error(resp)
        reponse_dict = resp.json()
        logger.trace("Lightning invoice checked. POST /mint")
        promises = PostMintResponse.parse_obj(reponse_dict).promises
        return promises

    @async_set_requests
    async def split(
        self,
        proofs: List[Proof],
        outputs: List[BlindedMessage],
    ) -> List[BlindedSignature]:
        """Consume proofs and create new promises based on amount split."""
        logger.debug("Calling split. POST /split")
        split_payload = PostSplitRequest(proofs=proofs, outputs=outputs)

        # construct payload
        def _splitrequest_include_fields(proofs: List[Proof]):
            """strips away fields from the model that aren't necessary for the /split"""
            proofs_include = {"id", "amount", "secret", "C", "p2shscript", "p2pksigs"}
            return {
                "outputs": ...,
                "proofs": {i: proofs_include for i in range(len(proofs))},
            }

        resp = self.s.post(
            self.url + "/split",
            json=split_payload.dict(include=_splitrequest_include_fields(proofs)),  # type: ignore
        )
        self.raise_on_error(resp)
        promises_dict = resp.json()
        mint_response = PostMintResponse.parse_obj(promises_dict)
        promises = [BlindedSignature(**p.dict()) for p in mint_response.promises]

        if len(promises) == 0:
            raise Exception("received no splits.")

        return promises

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
        self.raise_on_error(resp)

        return_dict = resp.json()
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
        self.raise_on_error(resp)

        return_dict = resp.json()
        return return_dict

    @async_set_requests
    async def pay_lightning(
        self, proofs: List[Proof], invoice: str, outputs: Optional[List[BlindedMessage]]
    ):
        """
        Accepts proofs and a lightning invoice to pay in exchange.
        """

        payload = PostMeltRequest(proofs=proofs, pr=invoice, outputs=outputs)

        def _meltrequest_include_fields(proofs: List[Proof]):
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
        self.raise_on_error(resp)
        return_dict = resp.json()

        return GetMeltResponse.parse_obj(return_dict)

    @async_set_requests
    async def restore_promises(
        self, outputs: List[BlindedMessage]
    ) -> Tuple[List[BlindedMessage], List[BlindedSignature]]:
        """
        Asks the mint to restore promises corresponding to outputs.
        """
        payload = PostMintRequest(outputs=outputs)
        resp = self.s.post(self.url + "/restore", json=payload.dict())
        self.raise_on_error(resp)
        reponse_dict = resp.json()
        returnObj = PostRestoreResponse.parse_obj(reponse_dict)
        return returnObj.outputs, returnObj.promises


class Wallet(LedgerAPI, WalletP2PK, WalletSecrets):
    """Minimal wallet wrapper."""

    mnemonic: str  # holds mnemonic of the wallet
    seed: bytes  # holds private key of the wallet generated from the mnemonic
    # db: Database
    bip32: BIP32
    # private_key: Optional[PrivateKey] = None

    def __init__(
        self,
        url: str,
        db: str,
        name: str = "no_name",
    ):
        """A Cashu wallet.

        Args:
            url (str): URL of the mint.
            db (str): Path to the database directory.
            name (str, optional): Name of the wallet database file. Defaults to "no_name".
        """
        self.db = Database("wallet", db)
        self.proofs: List[Proof] = []
        self.name = name

        super().__init__(url=url, db=self.db)
        logger.debug(f"Wallet initalized with mint URL {url}")

    @classmethod
    async def with_db(
        cls,
        url: str,
        db: str,
        name: str = "no_name",
        skip_private_key: bool = False,
    ):
        """Initializes a wallet with a database and initializes the private key.

        Args:
            url (str): URL of the mint.
            db (str): Path to the database.
            name (str, optional): Name of the wallet. Defaults to "no_name".
            skip_private_key (bool, optional): If true, the private key is not initialized. Defaults to False.

        Returns:
            Wallet: Initialized wallet.
        """
        self = cls(url=url, db=db, name=name)
        await self._migrate_database()
        if not skip_private_key:
            await self._init_private_key()
        return self

    async def _migrate_database(self):
        try:
            await migrate_databases(self.db, migrations)
        except Exception as e:
            logger.error(f"Could not run migrations: {e}")

    # ---------- API ----------

    async def load_mint(self, keyset_id: str = ""):
        """Load a mint's keys with a given keyset_id if specified or else
        loads the active keyset of the mint into self.keys.
        Also loads all keyset ids into self.keysets.

        Args:
            keyset_id (str, optional): _description_. Defaults to "".
        """
        await super()._load_mint(keyset_id)

    async def load_proofs(self, reload: bool = False) -> None:
        """Load all proofs from the database."""

        if self.proofs and not reload:
            logger.debug("Proofs already loaded.")
            return
        self.proofs = await get_proofs(db=self.db)

    async def request_mint(self, amount: int) -> Invoice:
        """Request a Lightning invoice for minting tokens.

        Args:
            amount (int): Amount for Lightning invoice in satoshis

        Returns:
            Invoice: Lightning invoice
        """
        invoice = await super().request_mint(amount)
        invoice.time_created = int(time.time())
        await store_lightning_invoice(db=self.db, invoice=invoice)
        return invoice

    async def mint(
        self,
        amount: int,
        split: Optional[List[int]] = None,
        hash: Optional[str] = None,
    ) -> List[Proof]:
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

        # quirk: we skip bumping the secret counter in the database since we are
        # not sure if the minting will succeed. If it succeeds, we will bump it
        # in the next step.
        secrets, rs, derivation_paths = await self.generate_n_secrets(
            len(amounts), skip_bump=True
        )
        await self._check_used_secrets(secrets)
        outputs, rs = self._construct_outputs(amounts, secrets, rs)

        # will raise exception if mint is unsuccessful
        promises = await super().mint(outputs, hash)

        # success, bump secret counter in database
        await bump_secret_derivation(
            db=self.db, keyset_id=self.keyset_id, by=len(amounts)
        )
        proofs = self._construct_proofs(promises, secrets, rs, derivation_paths)

        if proofs == []:
            raise Exception("received no proofs.")
        await self._store_proofs(proofs)
        if hash:
            await update_lightning_invoice(
                db=self.db, hash=hash, paid=True, time_paid=int(time.time())
            )
        self.proofs += proofs
        return proofs

    async def redeem(
        self,
        proofs: List[Proof],
    ) -> Tuple[List[Proof], List[Proof]]:
        """Redeem proofs by sending them to yourself (by calling a split).)
        Calls `add_witnesses_to_proofs` which parses all proofs and checks whether their
        secrets corresponds to any locks that we have the unlock conditions for. If so,
        it adds the unlock conditions to the proofs.
        Args:
            proofs (List[Proof]): Proofs to be redeemed.
        """
        return await self.split(proofs, sum_proofs(proofs))

    async def split(
        self,
        proofs: List[Proof],
        amount: int,
        secret_lock: Optional[Secret] = None,
    ) -> Tuple[List[Proof], List[Proof]]:
        """If secret_lock is None, random secrets will be generated for the tokens to keep (frst_outputs)
        and the promises to send (scnd_outputs).

        If secret_lock is provided, the wallet will create blinded secrets with those to attach a
        predefined spending condition to the tokens they want to send.

        Args:
            proofs (List[Proof]): _description_
            amount (int): _description_
            secret_lock (Optional[Secret], optional): _description_. Defaults to None.

        Returns:
            _type_: _description_
        """
        assert len(proofs) > 0, "no proofs provided."
        assert sum_proofs(proofs) >= amount, "amount too large."
        assert amount > 0, "amount must be positive."

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
            secrets, rs, derivation_paths = await self.generate_n_secrets(len(amounts))
        else:
            # NOTE: we use random blinding factors for P2SH, we won't be able to
            # restore these tokens from a backup
            rs = []
            # generate secrets for receiver
            secret_locks = [secret_lock.serialize() for i in range(len(scnd_outputs))]
            logger.debug(f"Creating proofs with custom secrets: {secret_locks}")
            assert len(secret_locks) == len(
                scnd_outputs
            ), "number of secret_locks does not match number of ouptus."
            # append predefined secrets (to send) to random secrets (to keep)
            # generate sercets to keep
            secrets = [
                await self._generate_secret() for s in range(len(frst_outputs))
            ] + secret_locks
            # TODO: derive derivation paths from secrets
            derivation_paths = ["custom"] * len(secrets)

        assert len(secrets) == len(
            amounts
        ), "number of secrets does not match number of outputs"
        # verify that we didn't accidentally reuse a secret
        await self._check_used_secrets(secrets)

        # construct outputs
        outputs, rs = self._construct_outputs(amounts, secrets, rs)

        # potentially add witnesses to outputs based on what requirement the proofs indicate
        outputs = await self.add_witnesses_to_outputs(proofs, outputs)

        # Call /split API
        promises = await super().split(proofs, outputs)

        # Construct proofs from returned promises (i.e., unblind the signatures)
        new_proofs = self._construct_proofs(promises, secrets, rs, derivation_paths)

        # remove used proofs from wallet and add new ones
        used_secrets = [p.secret for p in proofs]
        self.proofs = list(filter(lambda p: p.secret not in used_secrets, self.proofs))
        # add new proofs to wallet
        self.proofs += new_proofs
        # store new proofs in database
        await self._store_proofs(new_proofs)
        # invalidate used proofs in database
        for proof in proofs:
            await invalidate_proof(proof, db=self.db)

        keep_proofs = new_proofs[: len(frst_outputs)]
        send_proofs = new_proofs[len(frst_outputs) :]
        return keep_proofs, send_proofs

    async def pay_lightning(
        self, proofs: List[Proof], invoice: str, fee_reserve_sat: int
    ) -> bool:
        """Pays a lightning invoice and returns the status of the payment.

        Args:
            proofs (List[Proof]): List of proofs to be spent.
            invoice (str): Lightning invoice to be paid.
            fee_reserve_sat (int): Amount of fees to be reserved for the payment.

        """

        # Generate a number of blank outputs for any overpaid fees. As described in
        # NUT-08, the mint will imprint these outputs with a value depending on the
        # amount of fees we overpaid.
        n_return_outputs = calculate_number_of_blank_outputs(fee_reserve_sat)
        secrets, rs, derivation_paths = await self.generate_n_secrets(n_return_outputs)
        outputs, rs = self._construct_outputs(n_return_outputs * [1], secrets, rs)

        status = await super().pay_lightning(proofs, invoice, outputs)

        if status.paid:
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
            invoice_obj.hash = invoice_obj.hash or await self._generate_secret()
            await store_lightning_invoice(db=self.db, invoice=invoice_obj)

            # handle change and produce proofs
            if status.change:
                change_proofs = self._construct_proofs(
                    status.change,
                    secrets[: len(status.change)],
                    rs[: len(status.change)],
                    derivation_paths[: len(status.change)],
                )
                logger.debug(f"Received change: {sum_proofs(change_proofs)} sat")
                await self._store_proofs(change_proofs)

        else:
            raise Exception("could not pay invoice.")
        return status.paid

    async def check_proof_state(self, proofs):
        return await super().check_proof_state(proofs)

    # ---------- TOKEN MECHANICS ----------

    async def _store_proofs(self, proofs):
        async with self.db.connect() as conn:
            for proof in proofs:
                await store_proof(proof, db=self.db, conn=conn)

    @staticmethod
    def _get_proofs_per_keyset(proofs: List[Proof]):
        return {key: list(group) for key, group in groupby(proofs, lambda p: p.id)}  # type: ignore

    async def _get_proofs_per_minturl(
        self, proofs: List[Proof]
    ) -> Dict[str, List[Proof]]:
        ret: Dict[str, List[Proof]] = {}
        for id in set([p.id for p in proofs]):
            if id is None:
                continue
            keyset_crud = await get_keyset(id=id, db=self.db)
            assert keyset_crud is not None, "keyset not found"
            keyset: WalletKeyset = keyset_crud
            assert keyset.mint_url
            if keyset.mint_url not in ret:
                ret[keyset.mint_url] = [p for p in proofs if p.id == id]
            else:
                ret[keyset.mint_url].extend([p for p in proofs if p.id == id])
        return ret

    def _get_proofs_keysets(self, proofs: List[Proof]) -> List[str]:
        """Extracts all keyset ids from a list of proofs.

        Args:
            proofs (List[Proof]): List of proofs to get the keyset id's of
        """
        keysets: List[str] = [proof.id for proof in proofs if proof.id]
        return keysets

    async def _get_keyset_urls(self, keysets: List[str]) -> Dict[str, List[str]]:
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

    async def _make_token(self, proofs: List[Proof], include_mints=True) -> TokenV3:
        """
        Takes list of proofs and produces a TokenV3 by looking up
        the mint URLs by the keyset id from the database.

        Args:
            proofs (List[Proof]): List of proofs to be included in the token
            include_mints (bool, optional): Whether to include the mint URLs in the token. Defaults to True.

        Returns:
            TokenV3: TokenV3 object
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
    ) -> str:
        """Produces sharable token with proofs and mint information.

        Args:
            proofs (List[Proof]): List of proofs to be included in the token
            include_mints (bool, optional): Whether to include the mint URLs in the token. Defaults to True.
            legacy (bool, optional): Whether to produce a legacy V2 token. Defaults to False.

        Returns:
            str: Serialized Cashu token
        """

        if legacy:
            # V2 tokens
            token_v2 = await self._make_token_v2(proofs, include_mints)
            return await self._serialize_token_base64_tokenv2(token_v2)

            # # deprecated code for V1 tokens
            # proofs_serialized = [p.to_dict() for p in proofs]
            # return base64.urlsafe_b64encode(
            #     json.dumps(proofs_serialized).encode()
            # ).decode()

        # V3 tokens
        token = await self._make_token(proofs, include_mints)
        return token.serialize()

    async def _make_token_v2(self, proofs: List[Proof], include_mints=True) -> TokenV2:
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

    async def _serialize_token_base64_tokenv2(self, token: TokenV2) -> str:
        """
        Takes a TokenV2 and serializes it in urlsafe_base64.
        """
        # encode the token as a base64 string
        token_base64 = base64.urlsafe_b64encode(
            json.dumps(token.to_dict()).encode()
        ).decode()
        return token_base64

    async def _select_proofs_to_send(
        self, proofs: List[Proof], amount_to_send: int
    ) -> List[Proof]:
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

        logger.debug(f"selected proof amounts: {[p.amount for p in send_proofs]}")
        return send_proofs

    async def set_reserved(self, proofs: List[Proof], reserved: bool) -> None:
        """Mark a proof as reserved or reset it in the wallet db to avoid reuse when it is sent.

        Args:
            proofs (List[Proof]): List of proofs to mark as reserved
            reserved (bool): Whether to mark the proofs as reserved or not
        """
        uuid_str = str(uuid.uuid1())
        for proof in proofs:
            proof.reserved = True
            await update_proof_reserved(
                proof, reserved=reserved, send_id=uuid_str, db=self.db
            )

    async def invalidate(
        self, proofs: List[Proof], check_spendable=True
    ) -> List[Proof]:
        """Invalidates all unspendable tokens supplied in proofs.

        Args:
            proofs (List[Proof]): Which proofs to delete
            check_spendable (bool, optional): Asks the mint to check whether proofs are already spent before deleting them. Defaults to True.

        Returns:
            List[Proof]: List of proofs that are still spendable.
        """
        invalidated_proofs: List[Proof] = []
        if check_spendable:
            proof_states = await self.check_proof_state(proofs)
            for i, spendable in enumerate(proof_states.spendable):
                if not spendable:
                    invalidated_proofs.append(proofs[i])
        else:
            invalidated_proofs = proofs

        if invalidated_proofs:
            logger.debug(
                f"Invalidating {len(invalidated_proofs)} proofs worth"
                f" {sum_proofs(invalidated_proofs)} sat."
            )

        async with self.db.connect() as conn:
            for p in invalidated_proofs:
                await invalidate_proof(p, db=self.db, conn=conn)

        invalidate_secrets = [p.secret for p in invalidated_proofs]
        self.proofs = list(
            filter(lambda p: p.secret not in invalidate_secrets, self.proofs)
        )
        return [p for p in proofs if p not in invalidated_proofs]

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

    async def restore_wallet_from_mnemonic(
        self, mnemonic: Optional[str], to: int = 2, batch: int = 25
    ) -> None:
        """Restores the wallet from a mnemonic

        Args:
            mnemonic (Optional[str]): The mnemonic to restore the wallet from. If None, the mnemonic is loaded from the db.
            to (int, optional): The number of consecutive empty reponses to stop restoring. Defaults to 2.
            batch (int, optional): The number of proofs to restore in one batch. Defaults to 25.
        """
        await self._init_private_key(mnemonic)
        await self.load_mint()
        print("Restoring tokens...")
        stop_counter = 0
        # we get the current secret counter and restore from there on
        spendable_proofs = []
        counter_before = await bump_secret_derivation(
            db=self.db, keyset_id=self.keyset_id, by=0
        )
        if counter_before != 0:
            print("This wallet has already been used. Restoring from it's last state.")
        i = counter_before
        n_last_restored_proofs = 0
        while stop_counter < to:
            print(f"Restoring token {i} to {i + batch}...")
            restored_proofs = await self.restore_promises_from_to(i, i + batch - 1)
            if len(restored_proofs) == 0:
                stop_counter += 1
            spendable_proofs = await self.invalidate(restored_proofs)
            if len(spendable_proofs):
                n_last_restored_proofs = len(spendable_proofs)
                print(f"Restored {sum_proofs(restored_proofs)} sat")
            i += batch

        # restore the secret counter to its previous value for the last round
        revert_counter_by = batch * to + n_last_restored_proofs
        logger.debug(f"Reverting secret counter by {revert_counter_by}")
        before = await bump_secret_derivation(
            db=self.db,
            keyset_id=self.keyset_id,
            by=-revert_counter_by,
        )
        logger.debug(
            f"Secret counter reverted from {before} to {before - revert_counter_by}"
        )
        if n_last_restored_proofs == 0:
            print("No tokens restored.")
            return

    async def restore_promises_from_to(
        self, from_counter: int, to_counter: int
    ) -> List[Proof]:
        """Restores promises from a given range of counters. This is for restoring a wallet from a mnemonic.

        Args:
            from_counter (int): Counter for the secret derivation to start from
            to_counter (int): Counter for the secret derivation to end at

        Returns:
            List[Proof]: List of restored proofs
        """
        # we regenerate the secrets and rs for the given range
        secrets, rs, derivation_paths = await self.generate_secrets_from_to(
            from_counter, to_counter
        )
        # we don't know the amount but luckily the mint will tell us so we use a dummy amount here
        amounts_dummy = [1] * len(secrets)
        # we generate outptus from deterministic secrets and rs
        regenerated_outputs, _ = self._construct_outputs(amounts_dummy, secrets, rs)
        # we ask the mint to reissue the promises
        proofs = await self.restore_promises(
            outputs=regenerated_outputs,
            secrets=secrets,
            rs=rs,
            derivation_paths=derivation_paths,
        )

        await set_secret_derivation(
            db=self.db, keyset_id=self.keyset_id, counter=to_counter + 1
        )
        return proofs

    async def restore_promises(
        self,
        outputs: List[BlindedMessage],
        secrets: List[str],
        rs: List[PrivateKey],
        derivation_paths: List[str],
    ) -> List[Proof]:
        """Restores proofs from a list of outputs, secrets, rs and derivation paths.

        Args:
            outputs (List[BlindedMessage]): Outputs for which we request promises
            secrets (List[str]): Secrets generated for the outputs
            rs (List[PrivateKey]): Random blinding factors generated for the outputs
            derivation_paths (List[str]): Derivation paths for the secrets

        Returns:
            List[Proof]: List of restored proofs
        """
        # restored_outputs is there so we can match the promises to the secrets and rs
        restored_outputs, restored_promises = await super().restore_promises(outputs)
        # now we need to filter out the secrets and rs that had a match
        matching_indices = [
            idx
            for idx, val in enumerate(outputs)
            if val.B_ in [o.B_ for o in restored_outputs]
        ]
        secrets = [secrets[i] for i in matching_indices]
        rs = [rs[i] for i in matching_indices]
        # now we can construct the proofs with the secrets and rs
        proofs = self._construct_proofs(
            restored_promises, secrets, rs, derivation_paths
        )
        logger.debug(f"Restored {len(restored_promises)} promises")
        await self._store_proofs(proofs)

        # append proofs to proofs in memory so the balance updates
        for proof in proofs:
            if proof.secret not in [p.secret for p in self.proofs]:
                self.proofs.append(proof)
        return proofs
