from typing import Optional

import click
import uvicorn
from click import Context

from ..core.settings import settings


@click.command(
    context_settings=dict(
        ignore_unknown_options=True,
        allow_extra_args=True,
    )
)
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
            print(a, item)
            d[item[0].strip("--").replace("-", "_")] = (
                int(item[1])  # need to convert to int if it's a number
                if item[1].isdigit()
                else item[1]
            )
        else:
            d[a.strip("--")] = True  # argument like --key

    config = uvicorn.Config(
        "cashu.mint.app:app",
        port=port,
        host=host,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
        **d,
    )
    server = uvicorn.Server(config)
    server.run()
