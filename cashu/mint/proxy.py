from ipaddress import ip_address
from os.path import abspath, isabs
from typing import Optional

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send
from uvicorn.middleware.proxy_headers import _TrustedHosts

from ..core.settings import settings


def _cloudflare_address(headers: Headers) -> Optional[str]:
    values = headers.getlist("cf-connecting-ip")
    if len(values) != 1:
        return None
    try:
        return str(ip_address(values[0].strip()))
    except ValueError:
        return None


def _transport_peer(scope: Scope, receive: Receive) -> Optional[str]:
    server = scope.get("server")
    if server and server[1] is None and isabs(server[0]):
        return server[0]

    # Uvicorn 0.31 exposes the original socket on its HTTP and WebSocket
    # receive methods when the scope contains only a forwarded address or None.
    protocol = getattr(receive, "__self__", None)
    transport = getattr(protocol, "transport", None)
    if transport is not None:
        peer = transport.get_extra_info("peername")
        if isinstance(peer, tuple) and peer:
            return peer[0]
        name = transport.get_extra_info("sockname")
        if isinstance(name, str) and name and not name.startswith("\0"):
            return abspath(name)
    return None


class ForwardedClientMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app
        self.enabled = settings.mint_rate_limit_proxy_trust
        self.cloudflare = settings.mint_trust_cloudflare_connecting_ip
        self.trusted = _TrustedHosts(settings.mint_forwarded_allow_ips)

    def resolve(self, scope: Scope, receive: Receive) -> None:
        client = scope.get("client")
        resolved = bool(client and client[1] == 0)
        if resolved and not self.cloudflare:
            return
        peer = client[0] if client and not resolved else _transport_peer(scope, receive)
        if (resolved and peer is None) or peer not in self.trusted:
            return

        headers = Headers(scope=scope)
        address = _cloudflare_address(headers) if self.cloudflare else None
        if not resolved:
            forwarded = dict(scope["headers"])
            scheme = forwarded.get(b"x-forwarded-proto", b"").decode("latin1").strip()
            if scheme in {"http", "https", "ws", "wss"}:
                scope["scheme"] = (
                    scheme.replace("http", "ws")
                    if scope["type"] == "websocket"
                    else scheme
                )
            if address is None and b"x-forwarded-for" in forwarded:
                address = self.trusted.get_trusted_client_host(
                    forwarded[b"x-forwarded-for"].decode("latin1")
                )
        if address:
            scope["client"] = (address, 0)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self.enabled and scope["type"] in {"http", "websocket"}:
            self.resolve(scope, receive)
        await self.app(scope, receive, send)
