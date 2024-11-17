import argparse
import base64
import logging
import secrets
import threading
import webbrowser
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates


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
        self.token_event: threading.Event = threading.Event()
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

        # Fetch OpenID configuration using the discovery URL
        self.fetch_oidc_configuration()

    def fetch_oidc_configuration(self) -> None:
        """Fetch OIDC configuration from the discovery URL."""
        try:
            response = httpx.get(self.discovery_url)
            response.raise_for_status()
            oidc_config = response.json()
            self.authorization_endpoint = oidc_config.get("authorization_endpoint")
            self.token_endpoint = oidc_config.get("token_endpoint")
            self.introspection_endpoint = oidc_config.get("introspection_endpoint")
            self.revocation_endpoint = oidc_config.get("revocation_endpoint")
        except httpx.HTTPError as e:
            logging.error(f"Failed to get OpenID configuration: {e}")
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
            self.token_response.update(token_data)
            self.access_token = token_data.get("access_token")
            self.refresh_token = token_data.get("refresh_token")
            expires_in = token_data.get("expires_in")
            if expires_in:
                self.token_expiration_time = datetime.utcnow() + timedelta(
                    seconds=int(expires_in)
                )
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
                logging.error(f"HTTP error occurred during token exchange: {e}")
                self.token_event.set()
                return {}

    def run_server(self) -> None:
        """Run the FastAPI server."""
        config = uvicorn.Config(
            self.app, host="127.0.0.1", port=33388, log_level="error"
        )
        server = uvicorn.Server(config)

        # Start a thread to monitor the token event and stop the server
        threading.Thread(
            target=self.wait_for_token, args=(server,), daemon=True
        ).start()
        server.run()

    def wait_for_token(self, server) -> None:
        """Wait for the token event to be set, then stop the server."""
        self.token_event.wait()
        # Signal the server to shut down
        server.should_exit = True

    def authenticate(self) -> None:
        """Start the authentication process."""
        if self.access_token and self.refresh_token:
            # Tokens are provided, check if token is expired
            if self.is_token_expired():
                self.refresh_access_token()
            else:
                logging.info("Using existing access token.")
        else:
            if self.auth_flow == AuthorizationFlow.AUTHORIZATION_CODE:
                self.authenticate_with_authorization_code()
            elif self.auth_flow == AuthorizationFlow.PASSWORD:
                self.authenticate_with_password()
            else:
                raise ValueError(f"Unknown authentication flow: {self.auth_flow}")

    def is_token_expired(self) -> bool:
        """Check if the access token is expired."""
        if not self.token_expiration_time:
            return True
        return datetime.utcnow() >= self.token_expiration_time

    def refresh_access_token(self) -> None:
        """Refresh the access token using the refresh token."""
        data = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
            "client_id": self.client_id,
        }
        if self.client_secret:
            data["client_secret"] = self.client_secret
        with httpx.Client() as client:
            try:
                response = client.post(self.token_endpoint, data=data)
                response.raise_for_status()
                token_data = response.json()
                self.access_token = token_data.get("access_token")
                self.refresh_token = token_data.get("refresh_token", self.refresh_token)
                expires_in = token_data.get("expires_in")
                if expires_in:
                    self.token_expiration_time = datetime.utcnow() + timedelta(
                        seconds=int(expires_in)
                    )
                logging.info("Token refreshed successfully.")
            except httpx.HTTPError as e:
                logging.error(f"Failed to refresh token: {e}")
                raise

    def authenticate_with_authorization_code(self) -> None:
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

        # Start the web server in a separate thread (non-daemon)
        server_thread = threading.Thread(target=self.run_server)
        server_thread.start()

        # Open the browser or print the URL for the user
        logging.info("Please open the following URL in your browser to authenticate:")
        logging.info(auth_url)
        webbrowser.open(auth_url)

        # Wait for the token response
        logging.info("Waiting for authentication...")
        self.token_event.wait()

        # Use the retrieved tokens
        if self.token_response:
            logging.info("Authentication successful!")
            logging.info("Token response:")
            logging.info(self.token_response)
        else:
            logging.error("Authentication failed.")

        # Wait for the server thread to finish
        server_thread.join()

    def authenticate_with_password(self) -> None:
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
        with httpx.Client() as client:
            try:
                response = client.post(self.token_endpoint, data=data)
                response.raise_for_status()
                token_data = response.json()
                self.token_response.update(token_data)
                self.access_token = token_data.get("access_token")
                self.refresh_token = token_data.get("refresh_token")
                expires_in = token_data.get("expires_in")
                if expires_in:
                    self.token_expiration_time = datetime.utcnow() + timedelta(
                        seconds=int(expires_in)
                    )
                logging.info("Authentication successful!")
                logging.info("Token response:")
                logging.info(self.token_response)
            except httpx.HTTPError as e:
                logging.error(f"Failed to obtain token: {e}")
                raise

    def render_success_page(
        self, request: Request, token_data: Dict[str, Any]
    ) -> HTMLResponse:
        """Render an HTML page with a green check mark and user information."""
        context = {"request": request, "token_data": token_data}
        return self.templates.TemplateResponse("success.html", context)


def main() -> None:
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

    logging.basicConfig(level=logging.INFO)

    client = OpenIDClient(
        discovery_url=args.discovery_url,
        client_id=args.client_id,
        client_secret=args.client_secret,
        auth_flow=args.auth_flow,
        username=args.username,
        password=args.password,
        access_token=args.access_token,
        refresh_token=args.refresh_token,
    )
    client.authenticate()


if __name__ == "__main__":
    main()
