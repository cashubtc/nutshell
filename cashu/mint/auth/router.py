from fastapi import APIRouter
from loguru import logger

from ..startup import auth_ledger

auth_router: APIRouter = APIRouter()


@auth_router.get(
    "/v1/auth/blind",
    name="Mint information",
    summary="Mint information, operator contact information, and other info.",
    # response_model=GetInfoResponse,
    response_model_exclude_none=True,
)
async def info():
    logger.trace("> GET /v1/info")
    await auth_ledger.init_keysets()
    return "asd"
