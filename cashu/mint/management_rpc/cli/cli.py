import os

import click
import grpc
from click import Context

from cashu.mint.management_rpc.protos import management_pb2, management_pb2_grpc


class NaturalOrderGroup(click.Group):
    """For listing commands in help in order of definition"""

    def list_commands(self, ctx):
        return self.commands.keys()

'''
# https://github.com/pallets/click/issues/85#issuecomment-503464628
def coro(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper
'''

@click.group(cls=NaturalOrderGroup)
@click.option(
    "--host",
    "-h",
    default="localhost",
    help="Mint address."
)
@click.option(
    "--port",
    "-p",
    default=8086,
    help="Mint gRPC port."
)
@click.option(
    "--insecure",
    "-i",
    is_flag=True,
    default=False,
    help="Connect without mutual TLS."
)
@click.option(
    "--ca-cert-path",
    "-ca",
    default=None,
    help="path to the Certificate Authority (CA) certificate file."
)
@click.option(
    "--client-key-path",
    "-k",
    default=None,
    help="path to the client's TLS key file."
)
@click.option(
    "--client-cert-path",
    "-c",
    default=None,
    help="path to the client's TLS certificate file."
)
@click.pass_context
def cli(
    ctx: Context,
    host: str,
    port: int,
    insecure: bool,
    ca_cert_path: str,
    client_key_path: str,
    client_cert_path: str,
):
    ctx.ensure_object(dict)
    if not insecure:
        # Verify the existence of the paths
        for path in [ca_cert_path, client_key_path, client_cert_path]:
            if not path or not os.path.exists(path):
                click.echo(f"Error: The path '{path}' does not exist.", err=True)
                ctx.exit(1)

        with open(client_key_path, "rb") as key_file, open(client_cert_path, "rb") as cert_file, open(ca_cert_path, "rb") as ca_file:
            credentials = grpc.ssl_channel_credentials(
                root_certificates=ca_file.read(),
                private_key=key_file.read(),       
                certificate_chain=cert_file.read()
            )

            channel = grpc.secure_channel(f"{host}:{port}", credentials)
            ctx.obj['STUB'] = management_pb2_grpc.MintStub(channel)
    else:
        channel = grpc.insecure_channel(f"{host}:{port}")
        ctx.obj['STUB'] = management_pb2_grpc.MintStub(channel)

@cli.command("get-info", help="Get Mint info")
@click.pass_context
def get_info(ctx: Context):
    """Fetch server information"""
    stub = ctx.obj['STUB']
    try:
        response = stub.GetInfo(management_pb2.GetInfoRequest())
        click.echo(f"Mint Info:\n{response}")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)

@cli.group()
@click.pass_context
def update(ctx: Context):
    """Update server information"""
    pass

@update.command("motd", help="Set the message of the day.")
@click.argument("motd")
@click.pass_context
def update_motd(ctx: Context, motd: str):
    stub = ctx.obj['STUB']
    try:
        stub.UpdateMotd(management_pb2.UpdateMotdRequest(motd))
        click.echo("Motd successfully updated!")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)

@update.command("description", help="Update the short description.")
@click.argument("description")
@click.pass_context
def update_short_description(ctx: Context, description: str):
    stub = ctx.obj['STUB']
    try:
        stub.UpdateShortDescription(management_pb2.UpdateDescriptionRequest(description))
        click.echo("Short description successfully updated!")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)

@update.command("long-description", help="Update the long description.")
@click.argument("description")
@click.pass_context
def update_long_description(ctx: Context, description: str):
    stub = ctx.obj['STUB']
    try:
        stub.UpdateLongDescription(management_pb2.UpdateDescriptionRequest(description))
        click.echo("Long description successfully updated!")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)

@update.command("icon-url", help="Update the icon url.")
@click.argument("url")
@click.pass_context
def update_icon_url(ctx: Context, url: str):
    stub = ctx.obj['STUB']
    try:
        stub.UpdateLongDescription(management_pb2.UpdateIconUrlRequest(icon_url=url))
        click.echo("Icon url successfully updated!")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)

@update.command("name", help="Set the Mint's name.")
@click.argument("name")
@click.pass_context
def update_name(ctx: Context, name: str):
    stub = ctx.obj['STUB']
    try:
        stub.UpdateName(management_pb2.UpdateNameRequest(name))
        click.echo("Name successfully updated!")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)

@update.group()
@click.pass_context
def url(ctx: Context):
    pass

@url.command("add", help="Add a new URL for this Mint.")
@click.argument("url")
@click.pass_context
def add_mint_url(ctx: Context, url: str):
    stub = ctx.obj['STUB']
    try:
        stub.AddUrl(management_pb2.UpdateUrlRequest(url))
        click.echo("Url successfully added!")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)

@url.command("remove", help="Remove a URL of this Mint.")
@click.argument("url")
@click.pass_context
def remove_mint_url(ctx: Context, url: str):
    stub = ctx.obj['STUB']
    try:
        stub.RemoveUrl(management_pb2.UpdateUrlRequest(url))
        click.echo("Url successfully removed!")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)