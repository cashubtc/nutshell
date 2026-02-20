import json
from posixpath import join
from typing import Any, Dict, List, Optional, Tuple, Union

import bolt11
import httpx
from httpx import Response
from loguru import logger
from pydantic import ValidationError

from ..core.base import (
    AuthProof,
    BlindedMessage,
    BlindedSignature,
    MeltQuoteState,
    Proof,
    ProofSpentState,
    ProofState,
    Unit,
    WalletKeyset,
)
from ..core.crypto.secp import PublicKey
from ..core.db import Database
from ..core.models import (
    GetInfoResponse,
    KeysetsResponse,
    KeysetsResponseKeyset,
    KeysResponse,
    PostAuthBlindMintRequest,
    PostAuthBlindMintResponse,
    PostCheckStateRequest,
    PostCheckStateResponse,
    PostMeltQuoteRequest,
    PostMeltQuoteResponse,
    PostMeltRequest,
    PostMeltRequestOptionMpp,
    PostMeltRequestOptions,
    PostMeltResponse_deprecated,
    PostMintQuoteRequest,
    PostMintQuoteResponse,
    PostMintRequest,
    PostMintResponse,
    PostRestoreResponse,
    PostSwapRequest,
    PostSwapResponse,
)
from ..core.settings import settings
from ..tor.tor import TorProxy
from .crud import (
    get_proofs,
    invalidate_proof,
)
from .protocols import SupportsAuth

GET = "GET"
POST = "POST"


def async_set_httpx_client(func):
    """
    Decorator that wraps around any async class method of LedgerAPI that makes
    API calls. Sets some HTTP headers and starts a Tor instance if none is
    already running and and sets local proxy to use it.
    """

    async def wrapper(self, *args, **kwargs):
        # set proxy
        proxies_dict = {}
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
            proxies_dict.update({"all://": proxy_url})

        headers_dict = {"Client-version": settings.version}

        self.httpx = httpx.AsyncClient(
            verify=not settings.debug,
            proxies=proxies_dict,  # type: ignore
            headers=headers_dict,
            base_url=self.url.rstrip("/"),
            timeout=None if settings.debug else 60,
        )
        return await func(self, *args, **kwargs)

    return wrapper


def async_ensure_mint_loaded(func):
    """Decorator that ensures that the mint is loaded before calling the wrapped
    function. If the mint is not loaded, it will be loaded first.
    """

    async def wrapper(self, *args, **kwargs):
        if not self.keysets:
            await self.load_mint()
        return await func(self, *args, **kwargs)

    return wrapper


class LedgerAPI(SupportsAuth):
    tor: TorProxy
    httpx: httpx.AsyncClient
    api_prefix = "v1"

    def __init__(self, url: str, db: Database):
        self.url = url
        self.db = db

    @async_set_httpx_client
    async def _init_s(self):
        """Dummy function that can be called from outside to use LedgerAPI.s"""
        return

    @staticmethod
    def raise_on_error_request(
        resp: Response,
    ) -> None:
        """Raises an exception if the response from the mint contains an error.

        Args:
            resp_dict (Response): Response dict (previously JSON) from mint

        Raises:
            Exception: if the response contains an error
        """
        try:
            resp_dict = resp.json()
        except json.JSONDecodeError:
            resp.raise_for_status()
            return
        if "detail" in resp_dict:
            logger.trace(f"Error from mint: {resp_dict}")
            error_message = f"Mint Error: {resp_dict['detail']}"
            if "code" in resp_dict:
                error_message += f" (Code: {resp_dict['code']})"
            raise Exception(error_message)
        resp.raise_for_status()

    def raise_on_unsupported_version(self, resp: Response, endpoint:str):
        """
        Helper that handles unsupported endpoints (pre-v1 mints).
        If mint returns 404 (endpoint not present), raise a clear exception.
        Otherwise delegate to raise_on_error_request for other status codes.
        """

        if resp.status_code == 404:
            raise Exception(f"The mint at {self.url} does not support endpoint {endpoint}.")
        
        #For other non-200 statuses, raise using existing logic
        self.raise_on_error_request(resp)

    async def _request(self, method: str, path: str, noprefix=False, **kwargs):
        if not noprefix:
            path = join(self.api_prefix, path)
        if self.mint_info and self.mint_info.requires_blind_auth_path(method, path):
            if not self.auth_db:
                raise Exception(
                    "Mint requires blind auth, but no auth database is set."
                )
            if not self.auth_keyset_id:
                raise Exception(
                    "Mint requires blind auth, but no auth keyset id is set."
                )
            proofs = await get_proofs(db=self.auth_db, id=self.auth_keyset_id)
            if not proofs:
                raise Exception(
                    "Mint requires blind auth, but no blind auth tokens were found."
                )
            # select one auth proof
            proof = proofs[0]
            auth_token = AuthProof.from_proof(proof).to_base64()
            kwargs.setdefault("headers", {}).update(
                {
                    "Blind-auth": f"{auth_token}",
                }
            )
            await invalidate_proof(proof=proof, db=self.auth_db)
        if self.mint_info and self.mint_info.requires_clear_auth_path(method, path):
            logger.debug(f"Using clear auth token for {path}")
            clear_auth_token = kwargs.pop("clear_auth_token")
            if not clear_auth_token:
                raise Exception(
                    "Mint requires clear auth, but no clear auth token is set."
                )
            kwargs.setdefault("headers", {}).update(
                {
                    "Clear-auth": f"{clear_auth_token}",
                }
            )

        # Verbose logging of requests when enabled
        if settings.wallet_verbose_requests:
            request_info = f"{method} {self.url.rstrip('/')}/{path}"
            if "json" in kwargs:
                request_info += f"\nPayload: {json.dumps(kwargs['json'], indent=2)}"
            print(f"Request: {request_info}")
            
        resp = await self.httpx.request(method, path, **kwargs)
        
        # Verbose logging of responses when enabled
        if settings.wallet_verbose_requests:
            response_info = f"Response: {resp.status_code}"
            try:
                json_response = resp.json()
                response_info += f"\n{json.dumps(json_response, indent=2)}"
            except json.JSONDecodeError:
                response_info += f"\n{resp.text}"
            print(response_info)
            
        return resp

    """
    ENDPOINTS
    """

    @async_set_httpx_client
    async def _get_keys(self) -> List[WalletKeyset]:
        """API that gets the current keys of the mint

        Args:
            url (str): Mint URL

        Returns:
            WalletKeyset: Current mint keyset

        Raises:
            Exception: If no keys are received from the mint
        """
        resp = await self._request(GET, "keys")

        #if mint doesn't support v1 keys endpoint, fail explicitly
        self.raise_on_unsupported_version(resp, "Get /v1/keys")

        keys_dict: dict = resp.json()
        assert len(keys_dict), Exception("did not receive any keys")
        keys = KeysResponse.model_validate(keys_dict)
        keysets_str = " ".join([f"{k.id} ({k.unit})" for k in keys.keysets])
        logger.debug(f"Received {len(keys.keysets)} keysets from mint: {keysets_str}.")
        ret = [
            WalletKeyset(
                id=keyset.id,
                unit=keyset.unit,
                public_keys={
                    int(amt): PublicKey(bytes.fromhex(val))
                    for amt, val in keyset.keys.items()
                },
                mint_url=self.url,
            )
            for keyset in keys.keysets
        ]
        return ret

    @async_set_httpx_client
    async def _get_keyset(self, keyset_id: str) -> WalletKeyset:
        """API that gets the keys of a specific keyset from the mint.


        Args:
            keyset_id (str): base64 keyset ID, needs to be urlsafe-encoded before sending to mint (done in this method)

        Returns:
            WalletKeyset: Keyset with ID keyset_id

        Raises:
            Exception: If no keys are received from the mint
        """
        keyset_id_urlsafe = keyset_id.replace("+", "-").replace("/", "_")
        resp = await self._request(GET, f"keys/{keyset_id_urlsafe}")

        #if mint doesn't support v1 keyset endpoint, fail explicitly
        self.raise_on_unsupported_version(resp, f"GET /v1/keys/{keyset_id_urlsafe}")

        keys_dict = resp.json()
        assert len(keys_dict), Exception("did not receive any keys")
        keys = KeysResponse.model_validate(keys_dict)
        this_keyset = keys.keysets[0]
        keyset_keys = {
            int(amt): PublicKey(bytes.fromhex(val))
            for amt, val in this_keyset.keys.items()
        }
        keyset = WalletKeyset(
            id=keyset_id,
            unit=this_keyset.unit,
            public_keys=keyset_keys,
            mint_url=self.url,
        )
        return keyset

    @async_set_httpx_client
    async def _get_keysets(self) -> List[KeysetsResponseKeyset]:
        """API that gets a list of all active keysets of the mint.

        Returns:
            KeysetsResponse (List[str]): List of all active keyset IDs of the mint

        Raises:
            Exception: If no keysets are received from the mint
        """
        resp = await self._request(GET, "keysets")
        self.raise_on_unsupported_version(resp, "Get /v1/keysets")

        keysets_dict = resp.json()
        keysets = KeysetsResponse.model_validate(keysets_dict).keysets
        if not keysets:
            raise Exception("did not receive any keysets")
        return keysets

    @async_set_httpx_client
    async def _get_info(self) -> GetInfoResponse:
        """API that gets the mint info.

        Returns:
            GetInfoResponse: Current mint info

        Raises:
            Exception: If the mint info request fails
        """
        resp = await self._request(GET, "/v1/info", noprefix=True)
        self.raise_on_unsupported_version(resp, "Get /v1/info")

        data: dict = resp.json()
        mint_info: GetInfoResponse = GetInfoResponse.model_validate(data)
        return mint_info

    @async_set_httpx_client
    @async_ensure_mint_loaded
    async def mint_quote(
        self,
        amount: int,
        unit: Unit,
        memo: Optional[str] = None,
        pubkey: Optional[str] = None,
    ) -> PostMintQuoteResponse:
        """Requests a mint quote from the server and returns a payment request.

        Args:
            amount (int): Amount of tokens to mint
            unit (Unit): Unit of the amount
            memo (Optional[str], optional): Memo to attach to Lightning invoice. Defaults to None.
            pubkey (Optional[str], optional): Public key from which to expect a signature in a subsequent mint request.
        Returns:
            PostMintQuoteResponse: Mint Quote Response

        Raises:
            Exception: If the mint request fails
        """
        logger.trace("Requesting mint: POST /v1/mint/bolt11")
        payload = PostMintQuoteRequest(
            unit=unit.name, amount=amount, description=memo, pubkey=pubkey
        )
        resp = await self._request(
            POST,
            "mint/quote/bolt11",
            json=payload.model_dump(),
        )

        #if mint doesn't support v1 endpoint, fail explicitly
        self.raise_on_unsupported_version(resp, "POST /v1/mint/quote/bolt11")

        return_dict = resp.json()
        return PostMintQuoteResponse.model_validate(return_dict)

    @async_set_httpx_client
    @async_ensure_mint_loaded
    async def get_mint_quote(self, quote: str) -> PostMintQuoteResponse:
        """Returns an existing mint quote from the server.

        Args:
            quote (str): Quote ID

        Returns:
            PostMintQuoteResponse: Mint Quote Response
        """
        resp = await self._request(GET, f"mint/quote/bolt11/{quote}")
        self.raise_on_unsupported_version(resp, f"GET /v1/mint/quote/bolt11/{quote}")
        return_dict = resp.json()
        return PostMintQuoteResponse.model_validate(return_dict)

    @async_set_httpx_client
    @async_ensure_mint_loaded
    async def mint(
        self, outputs: List[BlindedMessage], quote: str, signature: Optional[str] = None
    ) -> List[BlindedSignature]:
        """Mints new coins and returns a proof of promise.

        Args:
            outputs (List[BlindedMessage]): Outputs to mint new tokens with
            quote (str): Quote ID.
            signature (Optional[str], optional): NUT-19 signature of the request.

        Returns:
            list[Proof]: List of proofs.

        Raises:
            Exception: If the minting fails
        """
        outputs_payload = PostMintRequest(
            outputs=outputs, quote=quote, signature=signature
        )
        logger.trace("Checking Lightning invoice. POST /v1/mint/bolt11")

        def _mintrequest_include_fields(outputs: List[BlindedMessage]):
            """strips away fields from the model that aren't necessary for the /mint"""
            outputs_include = {"id", "amount", "B_"}
            res = {
                "quote": ...,
                "outputs": {i: outputs_include for i in range(len(outputs))},
            }
            if signature:
                res["signature"] = ...
            return res

        payload = outputs_payload.model_dump(include=_mintrequest_include_fields(outputs))  # type: ignore
        resp = await self._request(
            POST,
            "mint/bolt11",
            json=payload,  # type: ignore
        )
        
        # fail explicitly if mint doesn't support v1 mint endpoint
        self.raise_on_unsupported_version(resp, f"POST /v1/mint/{quote}")
        response_dict = resp.json()
        logger.trace(f"Lightning invoice checked. POST {self.api_prefix}/mint/bolt11")
        promises = PostMintResponse.model_validate(response_dict).signatures
        return promises

    @async_set_httpx_client
    @async_ensure_mint_loaded
    async def check_mint_quotes(
        self, quotes: List[str], method: str = "bolt11"
    ) -> Dict[str, str]:
        """Check the status of multiple mint quotes at once.
        
        Args:
            quotes: List of quote IDs to check
            method: Payment method (default: bolt11)
            
        Returns:
            Dict mapping quote IDs to their states
        """
        logger.trace(f"Checking mint quotes: {quotes}")
        payload = {"quote_ids": quotes, "method": method}
        resp = await self._request(
            POST,
            f"mint/quote/{method}/check",
            json=payload,
        )
        self.raise_on_unsupported_version(resp, "POST /v1/mint/quote/bolt11/check")
        return resp.json()

    @async_set_httpx_client
    @async_ensure_mint_loaded
    async def mint_batch(
        self,
        quotes: List[tuple[str, List[BlindedMessage]]],
        method: str = "bolt11",
        signature: Optional[str] = None,
    ) -> Dict[str, List[BlindedSignature]]:
        """Mint tokens for multiple quotes at once.
        
        Args:
            quotes: List of (quote_id, outputs) tuples
            method: Payment method (default: bolt11)
            signature: Optional NUT-19 signature
            
        Returns:
            Dict mapping quote IDs to lists of blinded signatures
        """
        payload: Dict[str, Any] = {"method": method, "quotes": {}}
        
        for quote_id, outputs in quotes:
            # Build outputs include fields
            outputs_include = {"id", "amount", "B_"}
            payload["quotes"][quote_id] = {
                "outputs": {i: outputs_include for i in range(len(outputs))}
            }
            if signature:
                payload["quotes"][quote_id]["signature"] = ...
        
        if signature:
            payload["signature"] = signature
            
        resp = await self._request(
            POST,
            f"mint/{method}/batch",
            json=payload,
        )
        self.raise_on_unsupported_version(resp, f"POST /v1/mint/{method}/batch")
        return resp.json()

    @async_set_httpx_client
    @async_ensure_mint_loaded
    async def melt_quote(
        self, payment_request: str, unit: Unit, amount_msat: Optional[int] = None
    ) -> PostMeltQuoteResponse:
        """Checks whether the Lightning payment is internal."""
        invoice_obj = bolt11.decode(payment_request)
        assert invoice_obj.amount_msat, "invoice must have amount"

        # add mpp amount for partial melts
        melt_options = None
        if amount_msat:
            melt_options = PostMeltRequestOptions(
                mpp=PostMeltRequestOptionMpp(amount=amount_msat)
            )

        payload = PostMeltQuoteRequest(
            unit=unit.name, request=payment_request, options=melt_options
        )

        resp = await self._request(
            POST,
            "melt/quote/bolt11",
            json=payload.model_dump(),
        )
        
        #if mint doesn't support v1 melt-quote endpoint, fail explicitly
        self.raise_on_unsupported_version(resp, "POST /v1/melt/quote")
        return_dict = resp.json()
        return PostMeltQuoteResponse.model_validate(return_dict)

    @async_set_httpx_client
    @async_ensure_mint_loaded
    async def get_melt_quote(self, quote: str) -> PostMeltQuoteResponse:
        """Returns an existing melt quote from the server.

        Args:
            quote (str): Quote ID

        Returns:
            PostMeltQuoteResponse: Melt Quote Response
        """
        resp = await self._request(GET, f"melt/quote/bolt11/{quote}")
        self.raise_on_error_request(resp)
        return_dict = resp.json()
        return PostMeltQuoteResponse.model_validate(return_dict)

    @async_set_httpx_client
    @async_ensure_mint_loaded
    async def melt(
        self,
        quote: str,
        proofs: List[Proof],
        outputs: Optional[List[BlindedMessage]],
    ) -> PostMeltQuoteResponse:
        """
        Accepts proofs and a lightning invoice to pay in exchange.
        """

        payload = PostMeltRequest(quote=quote, inputs=proofs, outputs=outputs)

        def _meltrequest_include_fields(
            proofs: List[Proof], outputs: List[BlindedMessage]
        ):
            """strips away fields from the model that aren't necessary for the /melt"""
            proofs_include = {"id", "amount", "secret", "C", "witness"}
            outputs_include = {"id", "amount", "B_"}
            return {
                "quote": ...,
                "inputs": {i: proofs_include for i in range(len(proofs))},
                "outputs": {i: outputs_include for i in range(len(outputs))},
            }

        resp = await self._request(
            POST,
            "melt/bolt11",
            json=payload.model_dump(include=_meltrequest_include_fields(proofs, outputs)),  # type: ignore
            timeout=None,
        )
        try:
            self.raise_on_error_request(resp)
            return_dict = resp.json()
            return PostMeltQuoteResponse.model_validate(return_dict)
        except Exception as e:
            # BEGIN backwards compatibility < 0.15.0
            # before 0.16.0, mints return PostMeltResponse_deprecated
            if isinstance(e, ValidationError):
                # BEGIN backwards compatibility < 0.16.0
                ret = PostMeltResponse_deprecated.model_validate(return_dict)
                # END backwards compatibility < 0.16.0
            else:
                raise e
            return PostMeltQuoteResponse(
                quote=quote,
                amount=0,
                unit="sat",
                request="lnbc0",
                fee_reserve=0,
                paid=ret.paid or False,
                state=(
                    MeltQuoteState.paid.value
                    if ret.paid
                    else MeltQuoteState.unpaid.value
                ),
                payment_preimage=ret.preimage,
                change=ret.change,
                expiry=None,
            )
            # END backwards compatibility < 0.15.0

    @async_set_httpx_client
    @async_ensure_mint_loaded
    async def split(
        self,
        proofs: List[Proof],
        outputs: List[BlindedMessage],
    ) -> List[BlindedSignature]:
        """Consume proofs and create new promises based on amount split."""
        logger.debug(f"Calling split. POST {self.api_prefix}/swap")
        split_payload = PostSwapRequest(inputs=proofs, outputs=outputs)

        # construct payload
        def _splitrequest_include_fields(proofs: List[Proof]):
            """strips away fields from the model that aren't necessary for /v1/swap"""
            proofs_include = {
                "id",
                "amount",
                "secret",
                "C",
                "witness",
            }
            return {
                "outputs": ...,
                "inputs": {i: proofs_include for i in range(len(proofs))},
            }

        resp = await self._request(
            POST,
            "swap",
            json=split_payload.model_dump(include=_splitrequest_include_fields(proofs)),  # type: ignore
        )
       
       #if mint doesn't support v1 swap endpoint, fail explicitly
        self.raise_on_unsupported_version(resp, "POST /v1/swap")
        promises_dict = resp.json()
        mint_response = PostSwapResponse.model_validate(promises_dict)
        promises = [BlindedSignature(**p.model_dump()) for p in mint_response.signatures]

        if len(promises) == 0:
            raise Exception("received no splits.")

        return promises

    @async_set_httpx_client
    @async_ensure_mint_loaded
    async def check_proof_state(self, proofs: List[Proof]) -> PostCheckStateResponse:
        """
        Checks whether the secrets in proofs are already spent or not and returns a list of booleans.
        """
        payload = PostCheckStateRequest(Ys=[p.Y for p in proofs])
        resp = await self._request(
            POST,
            "checkstate",
            json=payload.model_dump(),
        )
        
        #fail if endpoint missing
        self.raise_on_unsupported_version(resp, "POST /v1/checkstate")

        # BEGIN backwards compatibility < 0.16.0
        # payload has "secrets" instead of "Ys"
        if resp.status_code == 422:
            logger.warning(
                "Received HTTP Error 422. Attempting state check with < 0.16.0 compatibility."
            )
            payload_secrets = {"secrets": [p.secret for p in proofs]}
            resp_secrets = await self._request(POST, "checkstate", json=payload_secrets)
            self.raise_on_error_request(resp_secrets)
            states = [
                ProofState(Y=p.Y, state=ProofSpentState(s["state"]))
                for p, s in zip(proofs, resp_secrets.json()["states"])
            ]
            return PostCheckStateResponse(states=states)
        # END backwards compatibility < 0.16.0

        self.raise_on_error_request(resp)
        return PostCheckStateResponse.model_validate(resp.json())

    @async_set_httpx_client
    @async_ensure_mint_loaded
    async def restore_promises(
        self, outputs: List[BlindedMessage]
    ) -> Tuple[List[BlindedMessage], List[BlindedSignature]]:
        """
        Asks the mint to restore promises corresponding to outputs.
        """
        payload = PostMintRequest(quote="restore", outputs=outputs)
        resp = await self._request(POST, "restore", json=payload.model_dump())
        #fail if endpoint missing
        self.raise_on_unsupported_version(resp, "POST /v1/restore")
        response_dict = resp.json()
        returnObj = PostRestoreResponse.model_validate(response_dict)

        # BEGIN backwards compatibility < 0.15.1
        # if the mint returns promises, duplicate into signatures
        if returnObj.promises:
            returnObj.signatures = returnObj.promises
        # END backwards compatibility < 0.15.1

        return returnObj.outputs, returnObj.signatures

    @async_set_httpx_client
    async def blind_mint_blind_auth(
        self, clear_auth_token: str, outputs: List[BlindedMessage]
    ) -> List[BlindedSignature]:
        """
        Asks the mint to mint blind auth tokens. Needs to provide a clear auth token.
        """
        payload = PostAuthBlindMintRequest(outputs=outputs)
        resp = await self._request(
            POST,
            "mint",
            json=payload.model_dump(),
            clear_auth_token=clear_auth_token,
        )
        self.raise_on_error_request(resp)
        response_dict = resp.json()
        return PostAuthBlindMintResponse.model_validate(response_dict).signatures
