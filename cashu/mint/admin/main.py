"""CLI entry point for the Nutshell Admin UI.

Usage:
    poetry run mint-admin [OPTIONS]

Starts a local web server that provides a dashboard for managing a Cashu mint
via its gRPC management interface.
"""

import click
import uvicorn


@click.command("mint-admin")
@click.option("--host", default="127.0.0.1", help="Admin UI listen address.")
@click.option("--port", default=4448, type=int, help="Admin UI listen port.")
@click.option(
    "--grpc-host", default="localhost", help="Mint gRPC management host."
)
@click.option(
    "--grpc-port", default=8086, type=int, help="Mint gRPC management port."
)
@click.option(
    "--mint-url",
    default="http://localhost:3338",
    help="Mint REST API base URL.",
)
@click.option(
    "--no-tls/--tls",
    "insecure",
    default=True,
    help="Connect to gRPC without mTLS (default: --no-tls).",
)
@click.option("--ca-cert", default=None, help="CA certificate for mTLS.")
@click.option("--client-key", default=None, help="Client key for mTLS.")
@click.option("--client-cert", default=None, help="Client certificate for mTLS.")
@click.option(
    "--admin-password",
    default=None,
    envvar="ADMIN_PASSWORD",
    help="Password for HTTP Basic Auth (user: admin). Can also set ADMIN_PASSWORD env var.",
)
@click.option("--reload", is_flag=True, default=False, help="Enable auto-reload.")
def main(
    host: str,
    port: int,
    grpc_host: str,
    grpc_port: int,
    mint_url: str,
    insecure: bool,
    ca_cert: str | None,
    client_key: str | None,
    client_cert: str | None,
    admin_password: str | None,
    reload: bool,
):
    """Start the Nutshell Mint Admin UI."""
    import os

    # Pass config to the app module via env vars so uvicorn can import it
    os.environ["ADMIN_GRPC_HOST"] = grpc_host
    os.environ["ADMIN_GRPC_PORT"] = str(grpc_port)
    os.environ["ADMIN_MINT_URL"] = mint_url
    os.environ["ADMIN_INSECURE"] = "1" if insecure else "0"
    if ca_cert:
        os.environ["ADMIN_CA_CERT"] = ca_cert
    if client_key:
        os.environ["ADMIN_CLIENT_KEY"] = client_key
    if client_cert:
        os.environ["ADMIN_CLIENT_CERT"] = client_cert
    if admin_password:
        os.environ["ADMIN_PASSWORD"] = admin_password

    click.echo(f"Nutshell Admin UI starting on http://{host}:{port}")
    click.echo(f"  gRPC target: {grpc_host}:{grpc_port}")
    click.echo(f"  Mint REST:   {mint_url}")
    if admin_password:
        click.echo("  Auth:        enabled (HTTP Basic)")
    else:
        click.echo("  Auth:        disabled (set --admin-password to enable)")
    uvicorn.run(
        "cashu.mint.admin.startup:app",
        host=host,
        port=port,
        reload=reload,
    )


if __name__ == "__main__":
    main()
