
import grpc
from loguru import logger

import cashu.mint.management_rpc.protos.management_pb2 as management_pb2
import cashu.mint.management_rpc.protos.management_pb2_grpc as management_pb2_grpc
from cashu.core.base import (
    MeltQuoteState,
    MintQuoteState,
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
        settings.mint_redis_cache_ttl = request.ttl
        return management_pb2.UpdateResponse()

    async def GetNut04Quote(self, request, _):
        mint_quote = await self.ledger.get_mint_quote(request.quote_id)
        return management_pb2.GetNut04QuoteResponse(**mint_quote.dict())

    async def UpdateNut04Quote(self, request, _):
        state = MintQuoteState[request.state]
        await self.ledger.db_write._update_mint_quote_state(request.quote_id, state)
        return management_pb2.UpdateResponse()

    async def GetNut05Quote(self, request, context):
        melt_quote = await self.ledger.get_melt_quote(request.quote_id)
        return management_pb2.GetNut05QuoteResponse(**melt_quote.dict())

    async def UpdateNut05Quote(self, request, _):
        state = MeltQuoteState[request.state]
        await self.ledger.db_write._update_melt_quote_state(request.quote_id, state)
        return management_pb2.UpdateResponse()

    async def RotateNextKeyset(self, request, context):
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


async def serve(ledger: Ledger):
    host = settings.mint_rpc_addr
    port = settings.mint_rpc_port

    logger.info(f"Starting Management RPC service on {host}:{port}")
    server = grpc.aio.server()
    management_pb2_grpc.add_MintServicer_to_server(MintManagementRPC(ledger=ledger), server)
    server.add_insecure_port(f"{host}:{port}")
    
    await server.start()
    return server

async def shutdown(server: grpc.aio.Server):
    logger.info("Shutting down management RPC gracefully...")
    await server.stop(grace=2)  # Give clients 2 seconds to finish requests
    logger.debug("Management RPC shut down.")