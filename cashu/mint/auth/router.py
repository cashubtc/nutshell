from fastapi import APIRouter

from ...mint.startup import auth_ledger
from .models import PostAuthBlindMintRequest, PostAuthBlindMintResponse

auth_router: APIRouter = APIRouter()


@auth_router.post(
    "/v1/auth/blind/mint",
    name="Mint blind auth tokens",
    summary="Mint blind auth tokens for a user.",
    response_model=PostAuthBlindMintResponse,
)
async def auth_blind_mint(
    request: PostAuthBlindMintRequest,
) -> PostAuthBlindMintResponse:
    signatures = await auth_ledger.auth_mint(outputs=request.outputs, auth=request.auth)
    return PostAuthBlindMintResponse(signatures=signatures)
