import hashlib
import os
from typing import List

from loguru import logger

from ...core.base import Proof
from ...core.crypto.secp import PrivateKey
from ...core.db import Database
from ...core.settings import settings
from ..crud import get_mint_by_url, update_mint
from ..errors import BalanceTooLowError
from ..wallet import Wallet
from .openid_connect.openid_client import AuthorizationFlow, OpenIDClient


class WalletAuth(Wallet):
    oidc_discovery_url: str
    oidc_client: OpenIDClient
    wallet_db: Database
    auth_flow: AuthorizationFlow = AuthorizationFlow.AUTHORIZATION_CODE
    username: str | None
    password: str | None

    def __init__(
        self, url: str, db: str, name: str = "auth", unit: str = "auth", **kwargs
    ):
        """Authentication wallet.

        Args:
            url (str): Mint url.
            db (str): Auth wallet db location.
            wallet_db (str): Wallet db location.
            name (str, optional): Wallet name. Defaults to "auth".
            unit (str, optional): Wallet unit. Defaults to "auth".
            kwargs: Additional keyword arguments.
                client_id (str, optional): OpenID client id. Defaults to "cashu-client".
                client_secret (str, optional): OpenID client secret. Defaults to "".
                username (str, optional): OpenID username. When set, the username and
                    password flow will be used to authenticate. If a username is already
                    stored in the database, it will be used. Will be stored in the
                    database if not already stored.
                password (str, optional): OpenID password. Used if username is set. Will
                    be read from the database if already stored. Will be stored in the
                    database if not already stored.
        """
        super().__init__(url, db, name, unit)
        self.client_id = kwargs.get("client_id", "cashu-client")
        self.client_secret = kwargs.get("client_secret", "")
        self.username = kwargs.get("username")
        self.password = kwargs.get("password")

        if self.username:
            if self.password is None:
                raise Exception("Password must be set if username is set.")
            self.auth_flow = AuthorizationFlow.PASSWORD
        else:
            self.auth_flow = AuthorizationFlow.AUTHORIZATION_CODE

        self.access_token = kwargs.get("access_token")
        self.refresh_token = kwargs.get("refresh_token")

    # overload with_db
    @classmethod
    async def with_db(cls, *args, **kwargs) -> "WalletAuth":
        """Create a new wallet with a database."""

        dirty_url_parse = args[0]
        dirty_db_parse = args[1]
        dirty_wallet_name = args[2]
        wallet_db_name = kwargs.get("wallet_db")
        if not wallet_db_name:
            raise Exception("Wallet db location is required.")
        wallet_db = Database(dirty_wallet_name, dirty_db_parse)

        # the wallet db could not have been created yet
        try:
            mint_db = await get_mint_by_url(wallet_db, dirty_url_parse)
            if mint_db:
                kwargs.update(
                    {
                        "username": mint_db.username,
                        "password": mint_db.password,
                        "access_token": mint_db.access_token,
                        "refresh_token": mint_db.refresh_token,
                    }
                )
        except Exception:
            pass

        # run migrations etc
        kwargs.update(dict(skip_db_read=True))
        await super().with_db(*args, **kwargs)

        return cls(*args, **kwargs)

    async def init_wallet(self):
        # Load mint info from original api_prefix path first
        await self.load_mint_info()
        if not self.mint_info.requires_clear_auth():
            raise Exception("Mint does not require clear auth.")

        # Use the blind auth api_prefix for all following requests
        self.api_prefix = "/v1/auth/blind"
        await self.load_mint_keysets()
        await self.activate_keyset()
        await self.load_proofs()

        self.oidc_discovery_url = self.mint_info.oidc_discovery_url()
        # Initialize OpenIDClient
        self.oidc_client = OpenIDClient(
            discovery_url=self.oidc_discovery_url,
            client_id=self.client_id,
            client_secret=self.client_secret,
            auth_flow=self.auth_flow,
            username=self.username,
            password=self.password,
            access_token=self.access_token,
            refresh_token=self.refresh_token,
        )
        # Authenticate using OpenIDClient
        self.oidc_client.authenticate()

        # Store the access and refresh tokens in the database
        await self.store_clear_auth_token()

    async def store_clear_auth_token(self) -> None:
        """Store the access and refresh tokens in the database."""
        access_token = self.oidc_client.access_token
        refresh_token = self.oidc_client.refresh_token
        if not access_token or not refresh_token:
            raise Exception("Access or refresh token not available.")
        # Store the tokens in the database
        mint_db = await get_mint_by_url(self.db, self.url)
        if not mint_db:
            raise Exception("Mint not found.")
        if (
            mint_db.access_token != access_token
            or mint_db.refresh_token != refresh_token
        ):
            mint_db.access_token = access_token
            mint_db.refresh_token = refresh_token
            await update_mint(self.db, mint_db)

    async def spend_auth_token(self) -> str:
        try:
            auth_proofs, _ = await self.select_to_send(self.proofs, 1, offline=True)
        except BalanceTooLowError:
            logger.debug("Balance too low. Requesting new blind auth tokens.")
            await self.mint_blind_auth_proofs()
            auth_proofs, _ = await self.select_to_send(self.proofs, 1, offline=True)
        except Exception as e:
            raise e
        blind_auth_token = await self.serialize_proofs(auth_proofs)
        await self.invalidate(auth_proofs)
        return blind_auth_token

    async def mint_blind_auth_proofs(self) -> List[Proof]:
        # Ensure access token is valid
        if self.oidc_client.is_token_expired():
            self.oidc_client.refresh_access_token()
            await self.store_clear_auth_token()
        clear_auth_token = self.oidc_client.access_token
        if not clear_auth_token:
            raise Exception("No clear auth token available.")
        amounts = settings.mint_auth_max_blind_tokens * [1]
        secrets = [hashlib.sha256(os.urandom(32)).hexdigest() for _ in amounts]
        rs = [PrivateKey(privkey=os.urandom(32), raw=True) for _ in amounts]
        derivation_paths = ["" for _ in amounts]
        outputs, rs = self._construct_outputs(amounts, secrets, rs)

        promises = await self.blind_mint_blind_auth(clear_auth_token, outputs)

        new_proofs = await self._construct_proofs(
            promises, secrets, rs, derivation_paths
        )
        return new_proofs
