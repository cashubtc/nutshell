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
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"


class OpenIDClient:
    """OpenID Connect client for authentication."""

    oidc_config: Dict[str, Any]

    def __init__(
        self,
        discovery_url: str,
        client_id: str,
        client_secret: str = "",
        auth_flow: Optional[AuthorizationFlow] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        token_expiration_time: Optional[datetime] = None,
        device_code: Optional[str] = None,
    ) -> None:
        self.discovery_url: str = discovery_url
        self.client_id: str = client_id
        self.client_secret: str = client_secret
        self.auth_flow: Optional[AuthorizationFlow] = auth_flow
        self.username: Optional[str] = username
        self.password: Optional[str] = password
        self.access_token: Optional[str] = access_token
        self.refresh_token: Optional[str] = refresh_token
        self.token_expiration_time: Optional[datetime] = token_expiration_time
        self.device_code: Optional[str] = device_code

        self.redirect_uri: str = "http://localhost:33388/callback"
        self.expected_state: str = secrets.token_urlsafe(16)
        self.token_response: Dict[str, Any] = {}
        self.token_event: asyncio.Event = asyncio.Event()
        self.token_endpoint: str = ""
        self.authorization_endpoint: str = ""
        self.introspection_endpoint: Optional[str] = None
        self.revocation_endpoint: Optional[str] = None
        self.device_authorization_endpoint: Optional[str] = None
        self.templates: Jinja2Templates = Jinja2Templates(
            directory="cashu/wallet/auth/openid_connect/templates"
        )

        self.app: FastAPI = FastAPI()
        self.app.state.client = self  # Store self in app state

    async def initialize(self) -> None:
        """Initialize the client asynchronously."""
        await self.fetch_oidc_configuration()
        await self.determine_auth_flow()

    async def determine_auth_flow(self) -> AuthorizationFlow:
        """Determine the authentication flow to use from the oidc configuration.
        Supported flows are chosen in the following order:
        - device_code
        - authorization_code
        - password
        """
        if not hasattr(self, "oidc_config"):
            raise ValueError(
                "OIDC configuration not loaded. Call fetch_oidc_configuration first."
            )

        supported_flows = self.oidc_config.get("grant_types_supported", [])

        # if self.auth_flow is already set, check if it is supported
        if self.auth_flow:
            if self.auth_flow.value not in supported_flows:
                raise ValueError(
                    f"Authentication flow {self.auth_flow.value} not supported by the OIDC configuration."
                )
            return self.auth_flow

        if AuthorizationFlow.DEVICE_CODE.value in supported_flows:
            self.auth_flow = AuthorizationFlow.DEVICE_CODE
        elif AuthorizationFlow.AUTHORIZATION_CODE.value in supported_flows:
            self.auth_flow = AuthorizationFlow.AUTHORIZATION_CODE
        elif AuthorizationFlow.PASSWORD.value in supported_flows:
            self.auth_flow = AuthorizationFlow.PASSWORD
        else:
            raise ValueError(
                "No supported authentication flows found in the OIDC configuration."
            )

        logger.debug(f"Determined authentication flow: {self.auth_flow.value}")
        return self.auth_flow

    async def fetch_oidc_configuration(self) -> None:
        """Fetch OIDC configuration from the discovery URL."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.discovery_url)
                response.raise_for_status()
                self.oidc_config = response.json()
                self.authorization_endpoint = self.oidc_config.get(  # type: ignore
                    "authorization_endpoint"
                )
                self.token_endpoint = self.oidc_config.get("token_endpoint")  # type: ignore
                self.introspection_endpoint = self.oidc_config.get(
                    "introspection_endpoint"
                )
                self.revocation_endpoint = self.oidc_config.get("revocation_endpoint")
                self.device_authorization_endpoint = self.oidc_config.get(
                    "device_authorization_endpoint"
                )
        except httpx.HTTPError as e:
            logger.error(f"Failed to get OpenID configuration: {e}")
            raise

    async def handle_callback(self, request: Request) -> HTMLResponse:
        """Endpoint to handle the redirect from the OpenID provider."""
        params = request.query_params
        if "error" in params:
            error_str = params["error"]
            if "error_description" in params:
                error_str += f": {params['error_description']}"
            return self.templates.TemplateResponse(
                "error.html",
                {"request": request, "error": error_str},
            )
        elif "code" in params and "state" in params:
            code: str = params["code"]
            state: str = params["state"]
            if state != self.expected_state:
                raise HTTPException(status_code=400, detail="Invalid state parameter")
            token_data: Dict[str, Any] = await self.exchange_code_for_token(code)
            self.update_token_data(token_data)
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
            # We have a token and a refresh token, check if token is expired
            if self.is_token_expired():
                try:
                    await self.refresh_access_token()
                except httpx.HTTPError:
                    logger.debug("Failed to refresh token.")
                    need_authenticate = True
            else:
                logger.debug("Using existing access token.")
        else:
            need_authenticate = True

        if need_authenticate:
            if self.auth_flow == AuthorizationFlow.AUTHORIZATION_CODE:
                await self.authenticate_with_authorization_code()
            elif self.auth_flow == AuthorizationFlow.PASSWORD:
                await self.authenticate_with_password()
            elif self.auth_flow == AuthorizationFlow.DEVICE_CODE:
                await self.authenticate_with_device_code()
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
                logger.debug(f"Failed to refresh token: {e}")
                raise

    async def authenticate_with_authorization_code(self) -> None:
        """Authenticate using the authorization code flow."""

        # Set up the route handlers
        @self.app.get("/callback", response_class=HTMLResponse)
        async def handle_callback(request: Request) -> Any:
            print("CALLBACK")
            return await self.handle_callback(request)

        # Build the authorization URL
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "openid",
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
        if not self.access_token or not self.refresh_token:
            raise ValueError(
                "Access token or refresh token not found in token response."
            )
        expires_in = token_data.get("expires_in")
        if expires_in:
            self.token_expiration_time = datetime.utcnow() + timedelta(
                seconds=int(expires_in)
            )
        refresh_expires_in = token_data.get("refresh_expires_in")
        if refresh_expires_in:
            logger.debug(f"Refresh token expires in {refresh_expires_in} seconds.")
            self.refresh_token_expiration_time = datetime.utcnow() + timedelta(
                seconds=int(refresh_expires_in)
            )

    async def authenticate_with_password(self) -> None:
        """Authenticate using the resource owner password credentials flow."""
        if not self.username or not self.password:
            raise ValueError(
                'Username and password must be provided. To set a password use: "cashu auth -p"'
            )
        data = {
            "grant_type": "password",
            "client_id": self.client_id,
            "username": self.username,
            "password": self.password,
            "scope": "openid",
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
                # logger.info("Token response:")
                # logger.info(self.token_response)
            except httpx.HTTPError as e:
                logger.error(f"Failed to obtain token: {e}")
                raise

    def render_success_page(
        self, request: Request, token_data: Dict[str, Any]
    ) -> HTMLResponse:
        """Render an HTML page with a green check mark and user information."""
        context = {"request": request, "token_data": token_data}
        return self.templates.TemplateResponse("success.html", context)

    async def authenticate_with_device_code(self) -> None:
        """Authenticate using the device code flow."""
        if not self.device_authorization_endpoint:
            raise ValueError("Device authorization endpoint not available.")

        data = {
            "client_id": self.client_id,
            "scope": "openid",
        }
        if self.client_secret:
            data["client_secret"] = self.client_secret

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    self.device_authorization_endpoint, data=data
                )
                response.raise_for_status()
                device_data = response.json()
            except httpx.HTTPError as e:
                logger.error(f"Failed to obtain device code: {e}")
                raise

        # Extract device code data
        device_code = device_data.get("device_code")
        user_code = device_data.get("user_code")
        verification_uri = device_data.get("verification_uri")
        verification_uri_complete = device_data.get("verification_uri_complete")
        expires_in = device_data.get("expires_in")
        interval = device_data.get("interval", 5)  # Default interval is 5 seconds

        if not device_code or not verification_uri:
            raise ValueError("Invalid response from device authorization endpoint.")

        # Display instructions to the user and open the browser
        if verification_uri_complete:
            logger.info("Opening browser to complete authorization...")
            logger.info(verification_uri_complete)
            webbrowser.open(verification_uri_complete)
        else:
            logger.info("Please visit the following URL to authorize:")
            logger.info(verification_uri)
            logger.info(f"Enter the user code: {user_code}")
            # Construct the URL for the user to enter the code
            full_verification_uri = f"{verification_uri}?user_code={user_code}"
            webbrowser.open(full_verification_uri)

        # Start polling the token endpoint
        start_time = datetime.now()
        expires_at = start_time + timedelta(seconds=expires_in)
        token_data = None
        while datetime.now() < expires_at:
            await asyncio.sleep(interval)
            data = {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": self.client_id,
            }
            if self.client_secret:
                data["client_secret"] = self.client_secret
            async with httpx.AsyncClient() as client:
                try:
                    response = await client.post(self.token_endpoint, data=data)
                    if response.status_code == 200:
                        # Successful response
                        token_data = response.json()
                        self.update_token_data(token_data)
                        logger.info("Authentication successful!")
                        break
                    else:
                        error_data = response.json()
                        error = error_data.get("error")
                        if error == "authorization_pending":
                            # Continue polling
                            pass
                        elif error == "slow_down":
                            # Increase interval by 5 seconds
                            interval += 5
                        elif error == "access_denied":
                            logger.error("Access denied by user.")
                            break
                        elif error == "expired_token":
                            logger.error("Device code has expired.")
                            break
                        else:
                            logger.error(f"Error during polling: {error}")
                            break
                except httpx.HTTPError as e:
                    logger.error(f"HTTP error during token polling: {e}")
                    break
        else:
            logger.error("Device code has expired before authorization.")
            raise Exception("Device code expired")


async def main() -> None:
    parser = argparse.ArgumentParser(description="OpenID Connect Authentication Client")
    parser.add_argument("discovery_url", help="OpenID Connect Discovery URL")
    parser.add_argument("client_id", help="Client ID")
    parser.add_argument("--client_secret", help="Client Secret", default="")
    parser.add_argument(
        "--auth_flow",
        choices=["authorization_code", "password", "device_code"],
        default="authorization_code",
        help="Authentication flow to use",
    )
    parser.add_argument("--username", help="Username for password flow")
    parser.add_argument("--password", help="Password for password flow")
    parser.add_argument("--access_token", help="Stored access token")
    parser.add_argument("--refresh_token", help="Stored refresh token")
    parser.add_argument("--device_code", help="Device code for device flow")
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
        device_code=args.device_code,
    )
    await client.initialize()
    await client.authenticate()


if __name__ == "__main__":
    asyncio.run(main())
