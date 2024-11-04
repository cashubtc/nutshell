import json
import uuid
from posixpath import join
from typing import List, Optional, Tuple, Union

import bolt11
import httpx
from httpx import Response
from loguru import logger
from pydantic import ValidationError

from cashu.wallet.crud import get_bolt11_melt_quote

from ..core.base import (
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
    CheckFeesResponse_deprecated,
    GetInfoResponse,
    KeysetsResponse,
    KeysetsResponseKeyset,
    KeysResponse,
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
from .wallet_deprecated import LedgerAPIDeprecated


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
            base_url=self.url,
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


class LedgerAPI(LedgerAPIDeprecated):
    tor: TorProxy
    db: Database  # we need the db for melt_deprecated
    httpx: httpx.AsyncClient

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
            # if we can't decode the response, raise for status
            resp.raise_for_status()
            return
        if "detail" in resp_dict:
            logger.trace(f"Error from mint: {resp_dict}")
            error_message = f"Mint Error: {resp_dict['detail']}"
            if "code" in resp_dict:
                error_message += f" (Code: {resp_dict['code']})"
            raise Exception(error_message)
        # raise for status if no error
        resp.raise_for_status()

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
        resp = await self.httpx.get(
            join(self.url, "/v1/keys"),
        )
        # BEGIN backwards compatibility < 0.15.0
        # assume the mint has not upgraded yet if we get a 404
        if resp.status_code == 404:
            ret = await self._get_keys_deprecated(self.url)
            return [ret]
        # END backwards compatibility < 0.15.0
        self.raise_on_error_request(resp)
        keys_dict: dict = resp.json()
        assert len(keys_dict), Exception("did not receive any keys")
        keys = KeysResponse.parse_obj(keys_dict)
        keysets_str = " ".join([f"{k.id} ({k.unit})" for k in keys.keysets])
        logger.debug(f"Received {len(keys.keysets)} keysets from mint: {keysets_str}.")
        ret = [
            WalletKeyset(
                id=keyset.id,
                unit=keyset.unit,
                public_keys={
                    int(amt): PublicKey(bytes.fromhex(val), raw=True)
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
        resp = await self.httpx.get(
            join(self.url, f"/v1/keys/{keyset_id_urlsafe}"),
        )
        # BEGIN backwards compatibility < 0.15.0
        # assume the mint has not upgraded yet if we get a 404
        if resp.status_code == 404:
            ret = await self._get_keyset_deprecated(self.url, keyset_id)
            return ret
        # END backwards compatibility < 0.15.0
        self.raise_on_error_request(resp)

        keys_dict = resp.json()
        assert len(keys_dict), Exception("did not receive any keys")
        keys = KeysResponse.parse_obj(keys_dict)
        this_keyset = keys.keysets[0]
        keyset_keys = {
            int(amt): PublicKey(bytes.fromhex(val), raw=True)
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
        resp = await self.httpx.get(
            join(self.url, "/v1/keysets"),
        )
        # BEGIN backwards compatibility < 0.15.0
        # assume the mint has not upgraded yet if we get a 404
        if resp.status_code == 404:
            ret = await self._get_keysets_deprecated(self.url)
            return ret
        # END backwards compatibility < 0.15.0
        self.raise_on_error_request(resp)

        keysets_dict = resp.json()
        keysets = KeysetsResponse.parse_obj(keysets_dict).keysets
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
        resp = await self.httpx.get(
            join(self.url, "/v1/info"),
        )
        # BEGIN backwards compatibility < 0.15.0
        # assume the mint has not upgraded yet if we get a 404
        if resp.status_code == 404:
            ret = await self._get_info_deprecated()
            return ret
        # END backwards compatibility < 0.15.0
        self.raise_on_error_request(resp)
        data: dict = resp.json()
        mint_info: GetInfoResponse = GetInfoResponse.parse_obj(data)
        return mint_info

    @async_set_httpx_client
    @async_ensure_mint_loaded
    async def mint_quote(
        self, amount: int, unit: Unit, memo: Optional[str] = None
    ) -> PostMintQuoteResponse:
        """Requests a mint quote from the server and returns a payment request.

        Args:
            amount (int): Amount of tokens to mint
            unit (Unit): Unit of the amount
            memo (Optional[str], optional): Memo to attach to Lightning invoice. Defaults to None.

        Returns:
            PostMintQuoteResponse: Mint Quote Response

        Raises:
            Exception: If the mint request fails
        """
        logger.trace("Requesting mint: POST /v1/mint/bolt11")
        payload = PostMintQuoteRequest(unit=unit.name, amount=amount, description=memo)
        resp = await self.httpx.post(
            join(self.url, "/v1/mint/quote/bolt11"), json=payload.dict()
        )
        # BEGIN backwards compatibility < 0.15.0
        # assume the mint has not upgraded yet if we get a 404
        if resp.status_code == 404:
            ret = await self.request_mint_deprecated(amount)
            return ret
        # END backwards compatibility < 0.15.0
        self.raise_on_error_request(resp)
        return_dict = resp.json()
        return PostMintQuoteResponse.parse_obj(return_dict)

    @async_set_httpx_client
    @async_ensure_mint_loaded
    async def get_mint_quote(self, quote: str) -> PostMintQuoteResponse:
        """Returns an existing mint quote from the server.

        Args:
            quote (str): Quote ID

        Returns:
            PostMintQuoteResponse: Mint Quote Response
        """
        resp = await self.httpx.get(
            join(self.url, f"/v1/mint/quote/bolt11/{quote}"),
        )
        self.raise_on_error_request(resp)
        return_dict = resp.json()
        return PostMintQuoteResponse.parse_obj(return_dict)

    @async_set_httpx_client
    @async_ensure_mint_loaded
    async def mint(
        self, outputs: List[BlindedMessage], quote: str
    ) -> List[BlindedSignature]:
        """Mints new coins and returns a proof of promise.

        Args:
            outputs (List[BlindedMessage]): Outputs to mint new tokens with
            quote (str): Quote ID.

        Returns:
            list[Proof]: List of proofs.

        Raises:
            Exception: If the minting fails
        """
        outputs_payload = PostMintRequest(outputs=outputs, quote=quote)
        logger.trace("Checking Lightning invoice. POST /v1/mint/bolt11")

        def _mintrequest_include_fields(outputs: List[BlindedMessage]):
            """strips away fields from the model that aren't necessary for the /mint"""
            outputs_include = {"id", "amount", "B_"}
            return {
                "quote": ...,
                "outputs": {i: outputs_include for i in range(len(outputs))},
            }

        payload = outputs_payload.dict(include=_mintrequest_include_fields(outputs))  # type: ignore
        resp = await self.httpx.post(
            join(self.url, "/v1/mint/bolt11"),
            json=payload,  # type: ignore
        )
        # BEGIN backwards compatibility < 0.15.0
        # assume the mint has not upgraded yet if we get a 404
        if resp.status_code == 404:
            ret = await self.mint_deprecated(outputs, quote)
            return ret
        # END backwards compatibility < 0.15.0
        self.raise_on_error_request(resp)
        response_dict = resp.json()
        logger.trace("Lightning invoice checked. POST /v1/mint/bolt11")
        promises = PostMintResponse.parse_obj(response_dict).signatures
        return promises

    @async_set_httpx_client
    @async_ensure_mint_loaded
    async def melt_quote(
        self, payment_request: str, unit: Unit, amount: Optional[int] = None
    ) -> PostMeltQuoteResponse:
        """Checks whether the Lightning payment is internal."""
        invoice_obj = bolt11.decode(payment_request)
        assert invoice_obj.amount_msat, "invoice must have amount"
        # add mpp amount for partial melts
        melt_options = None
        if amount:
            melt_options = PostMeltRequestOptions(
                mpp=PostMeltRequestOptionMpp(amount=amount)
            )

        payload = PostMeltQuoteRequest(
            unit=unit.name, request=payment_request, options=melt_options
        )

        resp = await self.httpx.post(
            join(self.url, "/v1/melt/quote/bolt11"),
            json=payload.dict(),
        )
        # BEGIN backwards compatibility < 0.15.0
        # assume the mint has not upgraded yet if we get a 404
        if resp.status_code == 404:
            ret: CheckFeesResponse_deprecated = await self.check_fees_deprecated(
                payment_request
            )
            quote_id = f"deprecated_{uuid.uuid4()}"
            return PostMeltQuoteResponse(
                quote=quote_id,
                amount=amount or invoice_obj.amount_msat // 1000,
                fee_reserve=ret.fee or 0,
                paid=False,
                state=MeltQuoteState.unpaid.value,
                expiry=invoice_obj.expiry,
            )
        # END backwards compatibility < 0.15.0
        self.raise_on_error_request(resp)
        return_dict = resp.json()
        return PostMeltQuoteResponse.parse_obj(return_dict)

    @async_set_httpx_client
    @async_ensure_mint_loaded
    async def get_melt_quote(self, quote: str) -> PostMeltQuoteResponse:
        """Returns an existing melt quote from the server.

        Args:
            quote (str): Quote ID

        Returns:
            PostMeltQuoteResponse: Melt Quote Response
        """
        resp = await self.httpx.get(
            join(self.url, f"/v1/melt/quote/bolt11/{quote}"),
        )
        self.raise_on_error_request(resp)
        return_dict = resp.json()
        return PostMeltQuoteResponse.parse_obj(return_dict)

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

        resp = await self.httpx.post(
            join(self.url, "/v1/melt/bolt11"),
            json=payload.dict(include=_meltrequest_include_fields(proofs, outputs)),  # type: ignore
            timeout=None,
        )
        try:
            self.raise_on_error_request(resp)
            return_dict = resp.json()
            return PostMeltQuoteResponse.parse_obj(return_dict)
        except Exception as e:
            # BEGIN backwards compatibility < 0.15.0
            # assume the mint has not upgraded yet if we get a 404
            if resp.status_code == 404:
                melt_quote = await get_bolt11_melt_quote(quote=quote, db=self.db)
                assert melt_quote, f"no melt_quote found for id {quote}"
                ret: PostMeltResponse_deprecated = await self.melt_deprecated(
                    proofs=proofs, outputs=outputs, invoice=melt_quote.request
                )
            elif isinstance(e, ValidationError):
                # BEGIN backwards compatibility < 0.16.0
                # before 0.16.0, mints return PostMeltResponse_deprecated
                ret = PostMeltResponse_deprecated.parse_obj(return_dict)
                # END backwards compatibility < 0.16.0
            else:
                raise e
            return PostMeltQuoteResponse(
                quote=quote,
                amount=0,
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
        logger.debug("Calling split. POST /v1/swap")
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

        resp = await self.httpx.post(
            join(self.url, "/v1/swap"),
            json=split_payload.dict(include=_splitrequest_include_fields(proofs)),  # type: ignore
        )
        # BEGIN backwards compatibility < 0.15.0
        # assume the mint has not upgraded yet if we get a 404
        if resp.status_code == 404:
            ret = await self.split_deprecated(proofs, outputs)
            return ret
        # END backwards compatibility < 0.15.0
        self.raise_on_error_request(resp)
        promises_dict = resp.json()
        mint_response = PostSwapResponse.parse_obj(promises_dict)
        promises = [BlindedSignature(**p.dict()) for p in mint_response.signatures]

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
        resp = await self.httpx.post(
            join(self.url, "/v1/checkstate"),
            json=payload.dict(),
        )
        # BEGIN backwards compatibility < 0.15.0
        # assume the mint has not upgraded yet if we get a 404
        if resp.status_code == 404:
            ret = await self.check_proof_state_deprecated(proofs)
            # convert CheckSpendableResponse_deprecated to CheckSpendableResponse
            states: List[ProofState] = []
            for spendable, pending, p in zip(ret.spendable, ret.pending, proofs):
                if spendable and not pending:
                    states.append(ProofState(Y=p.Y, state=ProofSpentState.unspent))
                elif spendable and pending:
                    states.append(ProofState(Y=p.Y, state=ProofSpentState.pending))
                else:
                    states.append(ProofState(Y=p.Y, state=ProofSpentState.spent))
            return PostCheckStateResponse(states=states)
        # END backwards compatibility < 0.15.0

        # BEGIN backwards compatibility < 0.16.0
        # payload has "secrets" instead of "Ys"
        if resp.status_code == 422:
            logger.warning(
                "Received HTTP Error 422. Attempting state check with < 0.16.0 compatibility."
            )
            payload_secrets = {"secrets": [p.secret for p in proofs]}
            resp_secrets = await self.httpx.post(
                join(self.url, "/v1/checkstate"),
                json=payload_secrets,
            )
            self.raise_on_error(resp_secrets)
            states = [
                ProofState(Y=p.Y, state=ProofSpentState(s["state"]))
                for p, s in zip(proofs, resp_secrets.json()["states"])
            ]
            return PostCheckStateResponse(states=states)
        # END backwards compatibility < 0.16.0

        self.raise_on_error_request(resp)
        return PostCheckStateResponse.parse_obj(resp.json())

    @async_set_httpx_client
    @async_ensure_mint_loaded
    async def restore_promises(
        self, outputs: List[BlindedMessage]
    ) -> Tuple[List[BlindedMessage], List[BlindedSignature]]:
        """
        Asks the mint to restore promises corresponding to outputs.
        """
        payload = PostMintRequest(quote="restore", outputs=outputs)
        resp = await self.httpx.post(join(self.url, "/v1/restore"), json=payload.dict())
        # BEGIN backwards compatibility < 0.15.0
        # assume the mint has not upgraded yet if we get a 404
        if resp.status_code == 404:
            ret = await self.restore_promises_deprecated(outputs)
            return ret
        # END backwards compatibility < 0.15.0
        self.raise_on_error_request(resp)
        response_dict = resp.json()
        returnObj = PostRestoreResponse.parse_obj(response_dict)

        # BEGIN backwards compatibility < 0.15.1
        # if the mint returns promises, duplicate into signatures
        if returnObj.promises:
            returnObj.signatures = returnObj.promises
        # END backwards compatibility < 0.15.1

        return returnObj.outputs, returnObj.signatures
