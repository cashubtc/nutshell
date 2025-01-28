import hashlib
import os
from typing import List, Optional

from loguru import logger

from cashu.core.helpers import sum_proofs
from cashu.core.mint_info import MintInfo

from ...core.base import Proof
from ...core.crypto.secp import PrivateKey
from ...core.db import Database
from ..crud import get_mint_by_url, update_mint
from ..wallet import Wallet
from .openid_connect.openid_client import AuthorizationFlow, OpenIDClient


class WalletAuth(Wallet):
    oidc_discovery_url: str
    oidc_client: OpenIDClient
    wallet_db: Database
    auth_flow: AuthorizationFlow
    username: str | None
    password: str | None
    # API prefix for all requests
    api_prefix = "/v1/auth/blind"

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
        logger.trace(f"client_id: {self.client_id}")
        self.client_secret = kwargs.get("client_secret", "")
        self.username = kwargs.get("username")
        self.password = kwargs.get("password")

        if self.username:
            if self.password is None:
                raise Exception("Password must be set if username is set.")
            self.auth_flow = AuthorizationFlow.PASSWORD
        else:
            self.auth_flow = AuthorizationFlow.AUTHORIZATION_CODE
            # self.auth_flow = AuthorizationFlow.DEVICE_CODE

        self.access_token = kwargs.get("access_token")
        self.refresh_token = kwargs.get("refresh_token")

    # overload with_db
    @classmethod
    async def with_db(cls, *args, **kwargs) -> "WalletAuth":
        """Create a new wallet with a database.
        Keyword arguments:
            url (str): Mint url.
            db (str): Wallet db location.
            name (str, optional): Wallet name. Defaults to "auth".
            username (str, optional): OpenID username. When set, the username and
                password flow will be used to authenticate. If a username is already
                stored in the database, it will be used. Will be stored in the
                database if not already stored.
            password (str, optional): OpenID password. Used if username is set. Will
                be read from the database if already stored. Will be stored in the
                database if not already stored.
            client_id (str, optional): OpenID client id. Defaults to "cashu-client".
            client_secret (str, optional): OpenID client secret. Defaults to "".
            access_token (str, optional): OpenID access token. Defaults to None.
            refresh_token (str, optional): OpenID refresh token. Defaults to None.
        Returns:
            WalletAuth: WalletAuth instance.
        """

        url: str = kwargs.get("url", "")
        db = kwargs.get("db", "")
        kwargs["name"] = kwargs.get("name", "auth")
        name = kwargs["name"]
        username = kwargs.get("username")
        password = kwargs.get("password")
        wallet_db = Database(name, db)

        # run migrations etc
        kwargs.update(dict(skip_db_read=True))
        await super().with_db(*args, **kwargs)

        # the wallet might not have been created yet
        # if it was though, we load the username, password,
        # access token and refresh token from the database
        try:
            mint_db = await get_mint_by_url(wallet_db, url)
            if mint_db:
                kwargs.update(
                    {
                        "username": username or mint_db.username,
                        "password": password or mint_db.password,
                        "access_token": mint_db.access_token,
                        "refresh_token": mint_db.refresh_token,
                    }
                )
        except Exception:
            pass

        return cls(*args, **kwargs)

    async def init_auth_wallet(
        self,
        mint_info: Optional[MintInfo] = None,
        mint_auth_proofs=True,
        force_auth=False,
    ) -> bool:
        """Initialize authentication wallet.

        Args:
            mint_info (MintInfo, optional): Mint information. If not provided, we load the
                info from the database or the mint directly. Defaults to None.
            mint_auth_proofs (bool, optional): Whether to mint auth proofs if necessary.
                Defaults to True.
            force_auth (bool, optional): Whether to force authentication. Defaults to False.

        Returns:
            bool: False if the mint does not require clear auth. True otherwise.
        """
        if mint_info:
            self.mint_info = mint_info
        await self.load_mint_info()
        if not self.mint_info.requires_clear_auth():
            return False

        # Use the blind auth api_prefix for all following requests
        await self.load_mint_keysets()
        await self.activate_keyset()
        await self.load_proofs()

        self.oidc_discovery_url = self.mint_info.oidc_discovery_url()
        self.client_id = self.mint_info.oidc_client_id()

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
        await self.oidc_client.initialize()
        await self.oidc_client.authenticate(force_authenticate=force_auth)

        await self.store_username_password()
        await self.store_clear_auth_token()

        if mint_auth_proofs:
            await self.mint_blind_auth_min_balance()

        return True

    async def mint_blind_auth_min_balance(self) -> None:
        """Mint auth tokens if balance is too low."""
        MIN_BALANCE = self.mint_info.bat_max_mint

        if self.available_balance < MIN_BALANCE:
            logger.debug(
                f"Balance too low. Minting {self.unit.str(MIN_BALANCE)} auth tokens."
            )
            try:
                await self.mint_blind_auth()
            except Exception as e:
                logger.error(f"Error minting auth proofs: {str(e)}")

    async def store_username_password(self) -> None:
        """Store the username and password in the database."""
        if self.username and self.password:
            mint_db = await get_mint_by_url(self.db, self.url)
            if not mint_db:
                raise Exception("Mint not found.")
            if mint_db.username != self.username or mint_db.password != self.password:
                mint_db.username = self.username
                mint_db.password = self.password
                await update_mint(self.db, mint_db)

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

    async def mint_blind_auth(self) -> List[Proof]:
        # Ensure access token is valid
        if self.oidc_client.is_token_expired():
            await self.oidc_client.refresh_access_token()
            await self.store_clear_auth_token()
        clear_auth_token = self.oidc_client.access_token
        if not clear_auth_token:
            raise Exception("No clear auth token available.")

        amounts = self.mint_info.bat_max_mint * [1]  # 1 AUTH tokens
        secrets = [hashlib.sha256(os.urandom(32)).hexdigest() for _ in amounts]
        rs = [PrivateKey(privkey=os.urandom(32), raw=True) for _ in amounts]
        derivation_paths = ["" for _ in amounts]
        outputs, rs = self._construct_outputs(amounts, secrets, rs)
        promises = await self.blind_mint_blind_auth(clear_auth_token, outputs)
        new_proofs = await self._construct_proofs(
            promises, secrets, rs, derivation_paths
        )
        logger.debug(
            f"Minted {self.unit.str(sum_proofs(new_proofs))} blind auth proofs."
        )
        return new_proofs
