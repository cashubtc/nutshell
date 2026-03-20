
import os

import grpc
from loguru import logger

import cashu.mint.management_rpc.protos.management_pb2 as management_pb2
import cashu.mint.management_rpc.protos.management_pb2_grpc as management_pb2_grpc
from cashu.core.base import (
    MeltQuoteState,
    MintQuoteState,
    Unit,
)
from cashu.core.settings import settings

from ..ledger import Ledger


class MintManagementRPC(management_pb2_grpc.MintServicer):

    def __init__(self, ledger: Ledger):
        self.ledger = ledger
        super().__init__()

    def GetInfo(self, request, _):
        logger.debug("gRPC GetInfo has been called")
        mint_info_dict = self.ledger.mint_info.dict()
        del mint_info_dict["nuts"]
        mint_info_dict["long_description"] = mint_info_dict["description_long"]
        del mint_info_dict["description_long"]
        response = management_pb2.GetInfoResponse(**mint_info_dict)
        return response
    
    async def UpdateMotd(self, request, _):
        logger.debug("gRPC UpdateMotd has been called")
        settings.mint_info_motd = request.motd
        return management_pb2.UpdateResponse()

    async def UpdateShortDescription(self, request, context):
        logger.debug("gRPC UpdateShortDescription has been called")
        settings.mint_info_description = request.description
        return management_pb2.UpdateResponse()

    async def UpdateLongDescription(self, request, context):
        logger.debug("gRPC UpdateLongDescription has been called")
        settings.mint_info_description_long = request.description
        return management_pb2.UpdateResponse()

    async def UpdateIconUrl(self, request, context):
        logger.debug("gRPC UpdateIconUrl has been called")
        settings.mint_info_icon_url = request.icon_url
        return management_pb2.UpdateResponse()

    async def UpdateName(self, request, context):
        logger.debug("gRPC UpdateName has been called")
        settings.mint_info_name = request.name
        return management_pb2.UpdateResponse()

    async def AddUrl(self, request, context):
        logger.debug("gRPC AddUrl has been called")
        if settings.mint_info_urls and request.url not in settings.mint_info_urls:
            settings.mint_info_urls.append(request.url)
        elif settings.mint_info_urls is None:
            settings.mint_info_urls = [request.url]
        else:
            raise Exception("URL already in mint_info_urls")
        return management_pb2.UpdateResponse()

    async def RemoveUrl(self, request, context):
        logger.debug("gRPC RemoveUrl has been called")
        if settings.mint_info_urls and request.url in settings.mint_info_urls:
            settings.mint_info_urls.remove(request.url)
            return management_pb2.UpdateResponse()
        else:
            raise Exception("No such URL in mint_info_urls")

    async def AddContact(self, request, context):
        logger.debug("gRPC AddContact has been called")
        for contact in settings.mint_info_contact:
            if contact[0] == request.method:
                raise Exception("Contact method already set")
        settings.mint_info_contact.append([request.method, request.info])
        return management_pb2.UpdateResponse()

    async def RemoveContact(self, request, context):
        logger.debug("gRPC RemoveContact has been called")
        for i, contact in enumerate(settings.mint_info_contact):
            if contact[0] == request.method:
                del settings.mint_info_contact[i]
                return management_pb2.UpdateResponse()
        raise Exception("Contact method not found")

    async def UpdateNut04(self, request, context):
        """Cannot implement this yet"""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    async def UpdateNut05(self, request, context):
        """Cannot implement this yet"""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    async def UpdateQuoteTtl(self, request, context):
        logger.debug("gRPC UpdateQuoteTtl has been called")
        if request.mint_ttl:
            settings.mint_redis_cache_ttl = request.mint_ttl
        elif request.melt_ttl:
            settings.mint_redis_cache_ttl = request.melt_ttl
        else:
            raise Exception("No quote ttl was specified")
        return management_pb2.UpdateResponse()

    async def GetNut04Quote(self, request, _):
        logger.debug("gRPC GetNut04Quote has been called")
        mint_quote = await self.ledger.get_mint_quote(request.quote_id)
        mint_quote_dict = mint_quote.dict()
        mint_quote_dict['state'] = str(mint_quote_dict['state'])
        del mint_quote_dict['mint'] # unused
        del mint_quote_dict['privkey'] # unused
        return management_pb2.GetNut04QuoteResponse(
            quote=management_pb2.Nut04Quote(**mint_quote_dict)
        )

    async def UpdateNut04Quote(self, request, _):
        logger.debug("gRPC UpdateNut04Quote has been called")
        state = MintQuoteState(request.state)
        await self.ledger.db_write._update_mint_quote_state(request.quote_id, state)
        return management_pb2.UpdateResponse()

    async def GetNut05Quote(self, request, _):
        logger.debug("gRPC GetNut05Quote has been called")
        melt_quote = await self.ledger.get_melt_quote(request.quote_id)
        melt_quote_dict = melt_quote.dict()
        melt_quote_dict['state'] = str(melt_quote_dict['state'])
        del melt_quote_dict['mint']
        return management_pb2.GetNut05QuoteResponse(
            quote=management_pb2.Nut05Quote(**melt_quote_dict)
        )

    async def UpdateNut05Quote(self, request, _):
        logger.debug("gRPC UpdateNut05Quote has been called")
        state = MeltQuoteState(request.state)
        await self.ledger.db_write._update_melt_quote_state(request.quote_id, state)
        return management_pb2.UpdateResponse()

    async def RotateNextKeyset(self, request, context):
        logger.debug("gRPC RotateNextKeyset has been called")
        # TODO: Fix this. Currently, we do not allow setting a max_order because
        # it influences the keyset ID and -in turn- the Mint behaviour when activating keysets
        # upon a restar (it will activate a new keyset with the standard max order)
        if request.max_order:
            logger.warning(f"Ignoring custom max_order of 2**{request.max_order}. This functionality is restricted.")
        logger.debug(f"{request.final_expiry = }")
        new_keyset = await self.ledger.rotate_next_keyset(
            Unit[request.unit],
            input_fee_ppk=request.input_fee_ppk,
            final_expiry=request.final_expiry
        )
        return management_pb2.RotateNextKeysetResponse(
            id=new_keyset.id,
            unit=str(new_keyset.unit),
            max_order=new_keyset.amounts[-1].bit_length(), # Neat trick to get log_2(last_amount) + 1
            input_fee_ppk=new_keyset.input_fee_ppk,
            final_expiry=new_keyset.final_expiry,
        )

    async def UpdateLightningFee(self, request, _):
        logger.debug("gRPC UpdateLightningFee has been called")
        if request.fee_percent:
            settings.lightning_fee_percent = request.fee_percent
        elif request.fee_min_reserve:
            settings.lightning_reserve_fee_min = request.fee_min_reserve
        else:
            raise Exception("No fee specified")
        return management_pb2.UpdateResponse()
    
    async def UpdateAuthLimits(self, request, _):
        logger.debug("gRPC UpdateAuthLimits has been called")
        if request.auth_rate_limit_per_minute:
            settings.mint_auth_rate_limit_per_minute = request.auth_rate_limit_per_minute
        elif request.auth_max_blind_tokens:
            settings.mint_auth_max_blind_tokens = request.auth_max_blind_tokens
        else:
            raise Exception("No auth limit was specified")
        return management_pb2.UpdateResponse()

async def serve(ledger: Ledger):
    host = settings.mint_rpc_server_addr
    port = settings.mint_rpc_server_port
    server = grpc.aio.server()
    management_pb2_grpc.add_MintServicer_to_server(MintManagementRPC(ledger=ledger), server)

    if settings.mint_rpc_server_mutual_tls:
        # Verify the existence of the required paths
        mint_rpc_key_path = settings.mint_rpc_server_key
        mint_rpc_ca_path = settings.mint_rpc_server_ca
        mint_rpc_cert_path = settings.mint_rpc_server_cert

        if not all(os.path.exists(path) if path else False for path in [mint_rpc_key_path, mint_rpc_ca_path, mint_rpc_cert_path]):
            logger.error("One or more required files for mTLS are missing:")
            if not mint_rpc_key_path or not os.path.exists(mint_rpc_key_path):
                logger.error(f"Missing key file: {mint_rpc_key_path}")
            if not mint_rpc_ca_path or not os.path.exists(mint_rpc_ca_path):
                logger.error(f"Missing CA file: {mint_rpc_ca_path}")
            if not mint_rpc_cert_path or not os.path.exists(mint_rpc_cert_path):
                logger.error(f"Missing cert file: {mint_rpc_cert_path}")
            raise FileNotFoundError("Required mTLS files are missing. Please check the paths.")

        logger.info(f"Starting mTLS Management RPC service on {host}:{port}")
        # Load server credentials
        server_credentials = grpc.ssl_server_credentials(
            ((open(mint_rpc_key_path, 'rb').read(), open(mint_rpc_cert_path, 'rb').read()),), # type: ignore
            root_certificates=open(mint_rpc_ca_path, 'rb').read(), # type: ignore
            require_client_auth=True,
        )
        server.add_secure_port(f"{host}:{port}", server_credentials)
    else:
        logger.info(f"Starting INSECURE Management RPC service on {host}:{port}")
        server.add_insecure_port(f"{host}:{port}")
    
    await server.start()
    return server

async def shutdown(server: grpc.aio.Server):
    logger.info("Shutting down management RPC gracefully...")
    await server.stop(grace=2)  # Give clients 2 seconds to finish requests
    logger.debug("Management RPC shut down.")