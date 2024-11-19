import argparse
import asyncio
import base64
import secrets
import webbrowser
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx
import jwt
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from loguru import logger


class AuthorizationFlow(Enum):
    AUTHORIZATION_CODE = "authorization_code"
    PASSWORD = "password"


class OpenIDClient:
    def __init__(
        self,
        discovery_url: str,
        client_id: str,
        client_secret: str = "",
        auth_flow: AuthorizationFlow = AuthorizationFlow.AUTHORIZATION_CODE,
        username: Optional[str] = None,
        password: Optional[str] = None,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        token_expiration_time: Optional[datetime] = None,
    ) -> None:
        self.discovery_url: str = discovery_url
        self.client_id: str = client_id
        self.client_secret: str = client_secret
        self.auth_flow: AuthorizationFlow = auth_flow
        self.username: Optional[str] = username
        self.password: Optional[str] = password
        self.access_token: Optional[str] = access_token
        self.refresh_token: Optional[str] = refresh_token
        self.token_expiration_time: Optional[datetime] = token_expiration_time

        self.redirect_uri: str = "http://localhost:33388"
        self.expected_state: str = secrets.token_urlsafe(16)
        self.token_response: Dict[str, Any] = {}
        self.token_event: asyncio.Event = asyncio.Event()
        self.token_endpoint: str = ""
        self.authorization_endpoint: str = ""
        self.introspection_endpoint: Optional[str] = None
        self.revocation_endpoint: Optional[str] = None
        self.templates: Jinja2Templates = Jinja2Templates(
            directory="cashu/wallet/auth/openid_connect/templates"
        )

        self.app: FastAPI = FastAPI()
        self.app.state.client = self  # Store self in app state

        # Set up the route handlers
        @self.app.get("/", response_class=HTMLResponse)
        async def read_root(request: Request) -> Any:
            return await self.read_root(request)

    async def initialize(self) -> None:
        """Initialize the client asynchronously."""
        await self.fetch_oidc_configuration()

    async def fetch_oidc_configuration(self) -> None:
        """Fetch OIDC configuration from the discovery URL."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.discovery_url)
                response.raise_for_status()
                oidc_config = response.json()
                self.authorization_endpoint = oidc_config.get("authorization_endpoint")
                self.token_endpoint = oidc_config.get("token_endpoint")
                self.introspection_endpoint = oidc_config.get("introspection_endpoint")
                self.revocation_endpoint = oidc_config.get("revocation_endpoint")
        except httpx.HTTPError as e:
            logger.error(f"Failed to get OpenID configuration: {e}")
            raise

    async def read_root(self, request: Request) -> HTMLResponse:
        """Endpoint to handle the redirect from the OpenID provider."""
        params = request.query_params
        if "error" in params:
            return self.templates.TemplateResponse(
                "error.html",
                {"request": request, "error": params["error"]},
            )
        elif "code" in params and "state" in params:
            code: str = params["code"]
            state: str = params["state"]
            if state != self.expected_state:
                raise HTTPException(status_code=400, detail="Invalid state parameter")
            # Exchange the code for tokens
            token_data: Dict[str, Any] = await self.exchange_code_for_token(code)
            self.update_token_data(token_data)
            # Render an HTML page with a green check mark and user info
            response = self.render_success_page(request, token_data)
            self.token_event.set()  # Signal that the token has been received
            return response
        else:
            return self.templates.TemplateResponse(
                "error.html",
                {"request": request, "error": "Missing 'code' or 'state' parameter"},
            )

    async def exchange_code_for_token(self, code: str) -> Dict[str, Any]:
        """Exchange the authorization code for tokens."""
        data: Dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
        }
        headers: Dict[str, str] = {}
        if self.client_secret:
            # Use HTTP Basic Auth if client_secret is provided
            basic_auth: str = f"{self.client_id}:{self.client_secret}"
            basic_auth_bytes: bytes = basic_auth.encode("ascii")
            basic_auth_b64: str = base64.b64encode(basic_auth_bytes).decode("ascii")
            headers["Authorization"] = f"Basic {basic_auth_b64}"
        else:
            # Include client_id in the POST body for public clients
            data["client_id"] = self.client_id
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    self.token_endpoint, data=data, headers=headers
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPError as e:
                logger.error(f"HTTP error occurred during token exchange: {e}")
                self.token_event.set()
                return {}

    async def run_server(self) -> None:
        """Run the FastAPI server."""
        config = uvicorn.Config(
            self.app, host="127.0.0.1", port=33388, log_level="error"
        )
        self.server = uvicorn.Server(config)
        await self.server.serve()

    async def shutdown_server(self) -> None:
        """Shut down the uvicorn server."""
        self.server.should_exit = True

    async def authenticate(self, force_authenticate: bool = False) -> None:
        """Start the authentication process."""
        need_authenticate = force_authenticate
        if self.access_token and self.refresh_token:
            # Tokens are provided, check if token is expired
            if self.is_token_expired():
                try:
                    await self.refresh_access_token()
                except httpx.HTTPError:
                    logger.debug("Failed to refresh token.")
                    need_authenticate = True
            else:
                logger.info("Using existing access token.")
        else:
            need_authenticate = True

        if need_authenticate:
            if self.auth_flow == AuthorizationFlow.AUTHORIZATION_CODE:
                await self.authenticate_with_authorization_code()
            elif self.auth_flow == AuthorizationFlow.PASSWORD:
                await self.authenticate_with_password()
            else:
                raise ValueError(f"Unknown authentication flow: {self.auth_flow}")

    def is_token_expired(self) -> bool:
        """Check if the access token is expired."""
        if not self.access_token:
            raise ValueError("Access token is not set.")
        decoded = jwt.decode(self.access_token, options={"verify_signature": False})
        exp = decoded.get("exp")
        if not exp:
            return False
        return datetime.now() >= datetime.fromtimestamp(exp) - timedelta(minutes=1)

    async def refresh_access_token(self) -> None:
        """Refresh the access token using the refresh token."""
        data = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
            "client_id": self.client_id,
        }
        if self.client_secret:
            data["client_secret"] = self.client_secret
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(self.token_endpoint, data=data)
                response.raise_for_status()
                token_data = response.json()
                self.update_token_data(token_data)
                logger.info("Token refreshed successfully.")
            except httpx.HTTPError as e:
                logger.error(f"Failed to refresh token: {e}")
                raise

    async def authenticate_with_authorization_code(self) -> None:
        """Authenticate using the authorization code flow."""
        # Build the authorization URL
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "openid profile email",
            "state": self.expected_state,
        }
        auth_url = f"{self.authorization_endpoint}?{urlencode(params)}"

        # Start the web server as an asyncio task
        server_task = asyncio.create_task(self.run_server())

        # Open the browser or print the URL for the user
        logger.info("Please open the following URL in your browser to authenticate:")
        logger.info(auth_url)
        webbrowser.open(auth_url)

        # Wait for the token response
        logger.info("Waiting for authentication...")
        await self.token_event.wait()

        # Use the retrieved tokens
        if self.token_response:
            logger.info("Authentication successful!")
            # logger.info("Token response:")
            # logger.info(self.token_response)
        else:
            logger.error("Authentication failed.")

        # Signal the server to shut down
        await self.shutdown_server()

        # Wait for the server task to finish
        await server_task

    def update_token_data(self, token_data: Dict[str, Any]) -> None:
        self.token_response.update(token_data)
        self.access_token = token_data.get("access_token")
        self.refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in")
        if expires_in:
            self.token_expiration_time = datetime.utcnow() + timedelta(
                seconds=int(expires_in)
            )
        refresh_expires_in = token_data.get("refresh_expires_in")
        if refresh_expires_in:
            logger.info(f"Refresh token expires in {refresh_expires_in} seconds.")
            self.refresh_token_expiration_time = datetime.utcnow() + timedelta(
                seconds=int(refresh_expires_in)
            )

    async def authenticate_with_password(self) -> None:
        """Authenticate using the resource owner password credentials flow."""
        if not self.username or not self.password:
            raise ValueError(
                "Username and password must be provided for password flow."
            )
        data = {
            "grant_type": "password",
            "client_id": self.client_id,
            "username": self.username,
            "password": self.password,
            "scope": "openid profile email",
        }
        if self.client_secret:
            data["client_secret"] = self.client_secret
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(self.token_endpoint, data=data)
                response.raise_for_status()
                token_data = response.json()
                self.update_token_data(token_data)
                logger.info("Authentication successful!")
                logger.info("Token response:")
                logger.info(self.token_response)
            except httpx.HTTPError as e:
                logger.error(f"Failed to obtain token: {e}")
                raise

    def render_success_page(
        self, request: Request, token_data: Dict[str, Any]
    ) -> HTMLResponse:
        """Render an HTML page with a green check mark and user information."""
        context = {"request": request, "token_data": token_data}
        return self.templates.TemplateResponse("success.html", context)


async def main() -> None:
    parser = argparse.ArgumentParser(description="OpenID Connect Authentication Client")
    parser.add_argument("discovery_url", help="OpenID Connect Discovery URL")
    parser.add_argument("client_id", help="Client ID")
    parser.add_argument("--client_secret", help="Client Secret", default="")
    parser.add_argument(
        "--auth_flow",
        choices=["authorization_code", "password"],
        default="authorization_code",
        help="Authentication flow to use",
    )
    parser.add_argument("--username", help="Username for password flow")
    parser.add_argument("--password", help="Password for password flow")
    parser.add_argument("--access_token", help="Stored access token")
    parser.add_argument("--refresh_token", help="Stored refresh token")
    args = parser.parse_args()

    client = OpenIDClient(
        discovery_url=args.discovery_url,
        client_id=args.client_id,
        client_secret=args.client_secret,
        auth_flow=AuthorizationFlow(args.auth_flow),
        username=args.username,
        password=args.password,
        access_token=args.access_token,
        refresh_token=args.refresh_token,
    )
    await client.initialize()
    await client.authenticate()


if __name__ == "__main__":
    asyncio.run(main())
