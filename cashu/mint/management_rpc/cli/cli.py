import click
import grpc
import os
from functools import wraps
from click import Context
from loguru import logger

from cashu.core.logging import configure_logger
from cashu.mint.management_rpc.protos import management_pb2_grpc, management_pb2

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
        raise e