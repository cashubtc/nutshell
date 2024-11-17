import datetime
from typing import Any, List, Optional

import httpx
import jwt
from loguru import logger

from ...core.base import AuthProof
from ...core.db import Database
from ...core.models import BlindedMessage, BlindedSignature
from ...core.settings import settings
from ..crud import LedgerCrudSqlite
from ..ledger import Ledger
from .base import User
from .crud import AuthLedgerCrud, AuthLedgerCrudSqlite


class AuthLedger(Ledger):
    auth_crud: AuthLedgerCrud
    jwks_url: str
    jwks_client: jwt.PyJWKClient
    signing_key: jwt.PyJWK

    def __init__(
        self,
        db: Database,
        seed: str,
        seed_decryption_key: Optional[str] = None,
        derivation_path="",
        amounts: Optional[List[int]] = None,
        crud=LedgerCrudSqlite(),
    ):
        super().__init__(
            db=db,
            seed=seed,
            backends=None,
            seed_decryption_key=seed_decryption_key,
            derivation_path=derivation_path,
            crud=crud,
            amounts=amounts,
        )

        if not settings.mint_auth_oicd_discovery_url:
            raise Exception("Missing OpenID Connect discovery URL.")
        self.oicd_discovery_url = settings.mint_auth_oicd_discovery_url
        logger.info(f"Initializing OpenID Connect: {self.oicd_discovery_url}")
        self.oicd_discovery_json = self._get_oicd_discovery_json()
        self.jwks_url = self.oicd_discovery_json["jwks_uri"]
        self.jwks_client = jwt.PyJWKClient(self.jwks_url)
        logger.info(f"Getting JWKS from: {self.jwks_url}")
        self.signing_key = self.fetch_es256_signing_key(self.jwks_url)
        self.auth_crud = AuthLedgerCrudSqlite()
        self.issuer: str = self.oicd_discovery_json["issuer"]
        logger.info(f"Initialized OpenID Connect: {self.issuer}")

    def fetch_es256_signing_key(self, jwks_url: str) -> jwt.PyJWK:
        """Fetch the ES256 signing key from the JWKS."""
        response = httpx.get(jwks_url)
        response.raise_for_status()
        jwks = response.json()
        for key in jwks["keys"]:
            if key.get("alg") == "ES256" and key.get("use") == "sig":
                return jwt.PyJWK.from_dict(key)
        raise Exception("No ES256 signing key found in JWKS. Make sure to enable it.")

    def _get_oicd_discovery_json(self) -> dict:
        resp = httpx.get(self.oicd_discovery_url)
        resp.raise_for_status()
        return resp.json()

    def _verify_oicd_issuer(self, clear_auth_token: str) -> None:
        """Verify the issuer of the clear-auth token.

        Args:
            clear_auth_token (str): _description_

        Raises:
            Exception: Invalid issuer.
        """
        try:
            decoded = jwt.decode(
                clear_auth_token,
                options={"verify_signature": False},
            )
            issuer = decoded["iss"]
            if issuer != self.issuer:
                raise Exception(f"Invalid issuer: {issuer}. Expected: {self.issuer}")
        except Exception as e:
            raise e

    def _verify_decode_jwt(self, clear_auth_token: str) -> Any:
        """Verify the clear-auth JWT token.

        Args:
            clear_auth_token (str): JWT token.

        Raises:
            jwt.ExpiredSignatureError: Token has expired.
            jwt.InvalidSignatureError: Invalid signature.
            jwt.InvalidTokenError: Invalid token.

        Returns:
            Any: Decoded JWT.
        """
        try:
            decoded = jwt.decode(
                clear_auth_token,
                self.signing_key.key,
                algorithms=["ES256"],
                verify=True,
                options={"verify_aud": False},
            )
            logger.trace(f"Decoded JWT: {decoded}")
        except jwt.ExpiredSignatureError as e:
            logger.error("Token has expired")
            raise e
        except jwt.InvalidSignatureError as e:
            logger.error("Invalid signature")
            raise e
        except jwt.InvalidTokenError as e:
            logger.error("Invalid token")
            raise e
        except Exception as e:
            raise e

        return decoded

    async def _get_user(self, decoded_token: Any) -> User:
        """Get the user from the decoded token. If the user does not exist, create a new one.

        Args:
            decoded_token (Any): decoded JWT from PyJWT.decode

        Returns:
            User: User object
        """
        user_id = decoded_token["sub"]
        user = await self.auth_crud.get_user(user_id=user_id, db=self.db)
        if not user:
            logger.info(f"Creating new user: {user_id}")
            user = User(id=user_id)
            await self.auth_crud.create_user(user=user, db=self.db)
        return user

    async def verify_clear_auth(self, clear_auth_token: str) -> User:
        """Verify the clear-auth JWT token and return the user.

        Checks:
            - Token not expired.
            - Token signature valid.
            - User exists.

        Args:
            auth_token (str): _description_

        Returns:
            User: _description_
        """
        self._verify_oicd_issuer(clear_auth_token)
        decoded = self._verify_decode_jwt(clear_auth_token)
        user = await self._get_user(decoded)
        logger.info(f"User authenticated: {user.id}")

        if (
            user.last_access
            and user.last_access
            > datetime.datetime.now()
            - datetime.timedelta(seconds=settings.mint_auth_rate_limit_seconds)
        ):
            raise Exception("Rate limit exceeded.")

        return user

    async def mint_blind_auth(
        self,
        *,
        outputs: List[BlindedMessage],
        user: User,
    ) -> List[BlindedSignature]:
        """Mints auth tokens. Returns a list of promises.

        Args:
            outputs (List[BlindedMessage]): Outputs to sign.
            user (User): Authenticated user.

        Raises:
            Exception: Invalid auth.
            Exception: Output verification failed.
            Exception: Output quota exceeded.

        Returns:
            List[BlindedSignature]: _description_
        """

        if len(outputs) > settings.mint_auth_max_blind_tokens:
            raise Exception(
                f"Too many outputs. You can only mint {settings.mint_auth_max_blind_tokens} tokens."
            )

        await self._verify_outputs(outputs)
        promises = await self._generate_promises(outputs)

        # update last_access timestamp of the user
        await self.auth_crud.update_user(user_id=user.id, db=self.db)

        return promises

    async def verify_blind_auth(self, *, blind_auth_token) -> None:
        """Melts the proofs of a blind auth token. Returns if successful, raises an exception otherwise.

        Args:
            proofs (List[Proof]): Proofs to melt (must be a list of length 1).

        Raises:
            Exception: Proof already spent or pending.
        """
        logger.trace(f"Blind auth token: {blind_auth_token}")
        try:
            proof = AuthProof.from_base64(blind_auth_token).to_proof()
            await self.db_write._verify_spent_proofs_and_set_pending([proof])
            await self._invalidate_proofs(proofs=[proof])
            await self.db_write._unset_proofs_pending([proof])
        except Exception as e:
            raise Exception(f"Blind auth error: {e}")