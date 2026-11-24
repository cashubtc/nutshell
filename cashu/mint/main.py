from functools import partial
from os.path import abspath
from typing import Optional

import click
import uvicorn
from click import Context
from starlette.types import ASGIApp, Receive, Scope, Send

from ..core.settings import VERSION, settings


def _unix_socket_app(path: str) -> ASGIApp:
    from .app import app

    async def serve(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in {"http", "websocket"} and scope.get("server") is None:
            scope["server"] = (path, None)
        await app(scope, receive, send)

    return serve


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

    uds = d.get("uds")
    application = (
        partial(_unix_socket_app, abspath(uds))
        if isinstance(uds, str) and "fd" not in d
        else "cashu.mint.app:app"
    )
    config = uvicorn.Config(
        application,
        factory=not isinstance(application, str),
        port=port,
        host=host,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
        proxy_headers=False,
        **d,  # type: ignore
    )

    server = uvicorn.Server(config)
    server.run()
