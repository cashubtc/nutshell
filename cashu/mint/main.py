from ipaddress import ip_address
from typing import Optional, cast

import click
import uvicorn
from click import Context
from starlette.datastructures import Headers
from uvicorn._types import (
    ASGI3Application,
    ASGIReceiveCallable,
    ASGISendCallable,
    Scope,
)
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from ..core.settings import VERSION, settings


def _cloudflare_address(headers: Headers) -> Optional[str]:
    values = headers.getlist("cf-connecting-ip")
    if len(values) != 1:
        return None
    try:
        return str(ip_address(values[0].strip()))
    except ValueError:
        return None


class CloudflareProxyHeadersMiddleware(ProxyHeadersMiddleware):
    async def __call__(
        self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
    ) -> None:
        if scope["type"] != "lifespan":
            peer = scope.get("client")
            if (peer[0] if peer else None) in self.trusted_hosts:
                headers = Headers(raw=list(scope["headers"]))
                address = _cloudflare_address(headers)
                if address is not None:
                    forwarded = headers.mutablecopy()
                    forwarded["x-forwarded-for"] = address
                    scope = scope.copy()
                    scope["headers"] = forwarded.raw
        await super().__call__(scope, receive, send)


def create_server_app() -> ASGI3Application:
    from .app import app

    asgi_app = cast(ASGI3Application, app)
    if not settings.mint_rate_limit_proxy_trust:
        return asgi_app
    middleware = (
        CloudflareProxyHeadersMiddleware
        if settings.mint_trust_cloudflare_connecting_ip
        else ProxyHeadersMiddleware
    )
    return middleware(asgi_app, trusted_hosts=settings.mint_forwarded_allow_ips)


@click.command(
    context_settings=dict(
        ignore_unknown_options=True,
        allow_extra_args=True,
    )
)
@click.version_option(version=VERSION, prog_name="Nutshell")
@click.option("--port", default=settings.mint_listen_port, help="Port to listen on")
@click.option("--host", default=settings.mint_listen_host, help="Host to run mint on")
@click.option("--ssl-keyfile", default=None, help="Path to SSL keyfile")
@click.option("--ssl-certfile", default=None, help="Path to SSL certificate")
@click.pass_context
def main(
    ctx: Context,
    port: int = settings.mint_listen_port,
    host: str = settings.mint_listen_host,
    ssl_keyfile: Optional[str] = None,
    ssl_certfile: Optional[str] = None,
):
    """This routine starts the uvicorn server if the Cashu mint is
    launched with `poetry run mint` at root level"""
    # this beautiful beast parses all command line arguments and passes them to the uvicorn server
    d = dict()
    for a in ctx.args:
        item = a.split("=")
        if len(item) > 1:  # argument like --key=value
            d[item[0].strip("--").replace("-", "_")] = (
                int(item[1])  # need to convert to int if it's a number
                if item[1].isdigit()
                else item[1]
            )
        else:
            d[a.strip("--")] = True  # argument like --key

    config = uvicorn.Config(
        "cashu.mint.main:create_server_app",
        factory=True,
        port=port,
        host=host,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
        proxy_headers=False,
        **d,  # type: ignore
    )

    server = uvicorn.Server(config)
    server.run()
