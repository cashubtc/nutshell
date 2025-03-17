import os
from typing import Optional

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
        stub.UpdateMotd(management_pb2.UpdateMotdRequest(motd=motd))
        click.echo("Motd successfully updated!")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)

@update.command("description", help="Update the short description.")
@click.argument("description")
@click.pass_context
def update_short_description(ctx: Context, description: str):
    stub = ctx.obj['STUB']
    try:
        stub.UpdateShortDescription(management_pb2.UpdateDescriptionRequest(description=description))
        click.echo("Short description successfully updated!")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)

@update.command("long-description", help="Update the long description.")
@click.argument("description")
@click.pass_context
def update_long_description(ctx: Context, description: str):
    stub = ctx.obj['STUB']
    try:
        stub.UpdateLongDescription(management_pb2.UpdateDescriptionRequest(description=description))
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
        stub.UpdateName(management_pb2.UpdateNameRequest(name=name))
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
        stub.AddUrl(management_pb2.UpdateUrlRequest(url=url))
        click.echo("Url successfully added!")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)

@url.command("remove", help="Remove a URL of this Mint.")
@click.argument("url")
@click.pass_context
def remove_mint_url(ctx: Context, url: str):
    stub = ctx.obj['STUB']
    try:
        stub.RemoveUrl(management_pb2.UpdateUrlRequest(url=url))
        click.echo("Url successfully removed!")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)

@update.group()
@click.pass_context
def contact(context: Context):
    pass

@contact.command("add", help="Add contact information.")
@click.argument("method")
@click.argument("info")
@click.pass_context
def add_contact(ctx: Context, method: str, info: str):
    stub = ctx.obj['STUB']
    try:
        stub.AddContact(management_pb2.UpdateContactRequest(method=method, info=info))
        click.echo("Contact successfully added!")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)

@contact.command("remove", help="Remove contact information.")
@click.argument("method")
@click.pass_context
def remove_contact(ctx: Context, method: str):
    stub = ctx.obj['STUB']
    try:
        stub.RemoveContact(management_pb2.UpdateContactRequest(method=method, info=""))
        click.echo("Contact successfully removed!")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)

@update.command("mint-quote", help="Set the state for a specific mint quote")
@click.argument("quote_id")
@click.argument("state")
@click.pass_context
def update_mint_quote(ctx: Context, quote_id: str, state: str):
    allowed_states = ["PENDING", "UNPAID", "PAID", "ISSUED"]
    if state not in allowed_states:
        click.echo(f"state must be one of: {allowed_states}", err=True)
        ctx.exit(1)
    stub = ctx.obj['STUB']
    try:
        stub.UpdateNut04Quote(management_pb2.UpdateQuoteRequest(quote_id=quote_id, state=state))
        click.echo("Successfully updated!")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)

@update.command("melt-quote", help="Set the state for a specific melt quote.")
@click.argument("quote_id")
@click.argument("state")
@click.pass_context
def update_melt_quote(ctx: Context, quote_id: str, state: str):
    allowed_states = ["PENDING", "UNPAID", "PAID"]
    if state not in allowed_states:
        click.echo(f"State must be one of: {allowed_states}", err=True)
        ctx.exit(1)
    stub = ctx.obj['STUB']
    try:
        stub.UpdateNut05Quote(management_pb2.UpdateQuoteRequest(quote_id=quote_id, state=state))
        click.echo("Successfully updated!")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)

@update.command("lightning-fee", help="Set new lightning fees.")
@click.argument("fee_percent", required=False)
@click.argument("min_fee_reserve", required=False)
@click.pass_context
def update_lightning_fee(ctx: Context, fee_percent: Optional[float], min_fee_reserve: Optional[int]):
    stub = ctx.obj['STUB']
    try:
        stub.UpdateLightningFee(management_pb2.UpdateLightningFeeRequest(
                fee_percent=fee_percent,
                fee_min_reserve=min_fee_reserve,
            )
        )
        click.echo("Lightning fee successfully updated!")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)

@update.command("auth", help="Set the limits for auth requests")
@click.argument("rate_limit_per_minute", required=False)
@click.argument("max_tokens_per_request", required=False)
@click.pass_context
def update_auth_limits(ctx: Context, rate_limit_per_minute: Optional[int], max_tokens_per_request: Optional[int]):
    stub = ctx.obj['STUB']
    try:
        stub.UpdateAuthLimits(
            management_pb2.UpdateAuthLimitsRequest(
                auth_rate_limit_per_minute=rate_limit_per_minute,
                auth_max_blind_tokens=max_tokens_per_request,
            )
        )
        click.echo("Rate limit per minute successfully updated!")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)

@cli.group()
@click.pass_context
def get(ctx: Context):
    """Get mint information"""
    pass

@get.command("mint-quote", help="Get a mint quote by id.")
@click.argument("quote_id")
@click.pass_context
def get_mint_quote(ctx: Context, quote_id: str):
    stub = ctx.obj['STUB']
    try:
        mint_quote = stub.GetNut04Quote(management_pb2.GetNut04QuoteRequest(quote_id=quote_id))
        click.echo(f"mint quote:\n{mint_quote}")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)

@get.command("melt-quote", help="Get a melt quote by id.")
@click.argument("quote_id")
@click.pass_context
def get_melt_quote(ctx: Context, quote_id: str):
    stub = ctx.obj['STUB']
    try:
        melt_quote = stub.GetNut05Quote(management_pb2.GetNut05QuoteRequest(quote_id=quote_id))
        click.echo(f"mint quote:\n{melt_quote}")
    except grpc.RpcError as e:
        click.echo(f"Error: {e.details()}", err=True)