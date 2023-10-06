import secrets as scrts
from typing import Callable, Dict, List, Optional, Union

import requests
from loguru import logger
from requests import Response

from ..core import bolt11 as bolt11
from ..core.base import (
    KeysetsResponse_deprecated,
    WalletKeyset,
)
from ..core.crypto.secp import PublicKey
from ..core.settings import settings
from ..tor.tor import TorProxy
from .protocols import SupportsRequests


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


class LedgerAPIDeprecated(SupportsRequests):
    """Deprecated wallet class, will be removed in the future."""

    s: requests.Session

    @staticmethod
    def raise_on_error(
        resp: Response,
        call_404: Optional[Callable] = None,
        call_args: List = [],
        call_kwargs: Dict = {},
    ) -> None:
        """Raises an exception if the response from the mint contains an error.

        Args:
            resp_dict (Response): Response dict (previously JSON) from mint
            call_instead (Callable): Function to call instead of raising an exception

        Raises:
            Exception: if the response contains an error
        """
        resp_dict = resp.json()
        if "detail" in resp_dict:
            logger.trace(f"Error from mint: {resp_dict}")
            error_message = f"Mint Error: {resp_dict['detail']}"
            if "code" in resp_dict:
                error_message += f" (Code: {resp_dict['code']})"
            # BEGIN BACKWARDS COMPATIBILITY < 0.14.0
            # if the error is a 404, we assume that the mint is not upgraded yet
            if call_404 and resp.status_code == 404:
                return call_404(*call_args, **call_kwargs)
            # END BACKWARDS COMPATIBILITY < 0.14.0
            raise Exception(error_message)
        # raise for status if no error
        resp.raise_for_status()

    @async_set_requests
    async def _get_keys_deprecated(self, url: str) -> WalletKeyset:
        """API that gets the current keys of the mint

        Args:
            url (str): Mint URL

        Returns:
            WalletKeyset: Current mint keyset

        Raises:
            Exception: If no keys are received from the mint
        """
        logger.warning(f"Using deprecated API call: {url}/keys")
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
        keyset = WalletKeyset(
            public_keys=keyset_keys, mint_url=url, use_deprecated_id=True
        )
        return keyset

    @async_set_requests
    async def _get_keys_of_keyset_deprecated(
        self, url: str, keyset_id: str
    ) -> WalletKeyset:
        """API that gets the keys of a specific keyset from the mint.


        Args:
            url (str): Mint URL
            keyset_id (str): base64 keyset ID, needs to be urlsafe-encoded before sending to mint (done in this method)

        Returns:
            WalletKeyset: Keyset with ID keyset_id

        Raises:
            Exception: If no keys are received from the mint
        """
        logger.warning(f"Using deprecated API call: {url}/keys/{keyset_id}")
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
        keyset = WalletKeyset(
            id=keyset_id, public_keys=keyset_keys, mint_url=url, use_deprecated_id=True
        )
        return keyset

    @async_set_requests
    async def _get_keyset_ids_deprecated(self, url: str) -> List[str]:
        """API that gets a list of all active keysets of the mint.

        Args:
            url (str): Mint URL

        Returns:
            KeysetsResponse (List[str]): List of all active keyset IDs of the mint

        Raises:
            Exception: If no keysets are received from the mint
        """
        logger.warning(f"Using deprecated API call: {url}/keysets")
        resp = self.s.get(
            url + "/keysets",
        )
        self.raise_on_error(resp)
        keysets_dict = resp.json()
        keysets = KeysetsResponse_deprecated.parse_obj(keysets_dict)
        assert len(keysets.keysets), Exception("did not receive any keysets")
        return keysets.keysets
