
import grpc
from cashu.core.settings import settings
from loguru import logger

import cashu.mint.management_rpc.protos.management_pb2 as management_pb2
import cashu.mint.management_rpc.protos.management_pb2_grpc as management_pb2_grpc

from ..ledger import Ledger


class MintManagementRPC(management_pb2_grpc.MintServicer):

    def __init__(self, ledger: Ledger):
        self.ledger = ledger
        super().__init__()

    def GetInfo(self, request, context):
        mint_info = self.ledger.mint_info
        response = management_pb2.GetInfoResponse(
            **vars(mint_info).copy().pop("nuts", None)
        )
        return response

    '''
    async def UpdateMotd(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    async def UpdateShortDescription(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    async def UpdateLongDescription(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    async def UpdateIconUrl(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    async def UpdateName(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    async def AddUrl(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    async def RemoveUrl(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    async def AddContact(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    async def RemoveContact(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    async def UpdateNut04(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    async def UpdateNut05(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    async def UpdateQuoteTtl(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    async def UpdateNut04Quote(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    async def RotateNextKeyset(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')    
    '''


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