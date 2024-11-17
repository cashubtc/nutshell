import argparse
import base64
import secrets
import threading
import webbrowser
from typing import Any, Dict
from urllib.parse import urlencode

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates


class OpenIDClient:
    def __init__(
        self, discovery_url: str, client_id: str, client_secret: str = ""
    ) -> None:
        self.discovery_url: str = discovery_url
        self.client_id: str = client_id
        self.client_secret: str = client_secret
        self.redirect_uri: str = "http://localhost:33388"
        self.expected_state: str = secrets.token_urlsafe(16)
        self.token_response: Dict[str, Any] = {}
        self.token_event: threading.Event = threading.Event()
        self.token_endpoint: str = ""
        self.authorization_endpoint: str = ""
        self.templates: Jinja2Templates = Jinja2Templates(
            directory="dev/openid_connect/templates"
        )

        self.app: FastAPI = FastAPI()
        self.app.state.client = self  # Store self in app state

        # Set up the route handlers
        @self.app.get("/", response_class=HTMLResponse)
        async def read_root(request: Request) -> Any:
            return await self.read_root(request)

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
                print(f"HTTP error occurred: {e}")
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
        # Get OpenID configuration using the discovery URL
        try:
            response = httpx.get(self.discovery_url)
            response.raise_for_status()
            oidc_config = response.json()
            self.authorization_endpoint = oidc_config["authorization_endpoint"]
            self.token_endpoint = oidc_config["token_endpoint"]
        except httpx.HTTPError as e:
            print(f"Failed to get OpenID configuration: {e}")
            return

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
        print("Please open the following URL in your browser to authenticate:")
        print(auth_url)
        webbrowser.open(auth_url)

        # Wait for the token response
        print("Waiting for authentication...")
        self.token_event.wait()

        # Use the retrieved tokens
        if self.token_response:
            print("Authentication successful!")
            print("Token response:")
            print(self.token_response)
        else:
            print("Authentication failed.")

        # Wait for the server thread to finish
        server_thread.join()

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
    args = parser.parse_args()

    client = OpenIDClient(args.discovery_url, args.client_id, args.client_secret)
    client.authenticate()


if __name__ == "__main__":
    main()
