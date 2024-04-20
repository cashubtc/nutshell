from fastapi import APIRouter, Request
from loguru import logger

from ..core.base import (
    PostMeltQuoteResponse,
    PostMeltResponse,
)
from .models import (
    GatewayMeltQuoteRequest,
    GatewayMeltQuoteResponse,
    GatewayMeltRequest,
    GatewayMeltResponse,
)
from .startup import gateway

router: APIRouter = APIRouter()


@router.post(
    "/v1/melt/quote/bolt11",
    summary="Request a quote for melting tokens",
    response_model=GatewayMeltQuoteResponse,
    response_description="Melt tokens for a payment on a supported payment method.",
)
async def get_melt_quote(
    request: Request, payload: GatewayMeltQuoteRequest
) -> GatewayMeltQuoteResponse:
    """
    Request a quote for melting tokens.
    """
    logger.trace(f"> POST /v1/melt/quote/bolt11: {payload}")
    quote = await gateway.melt_quote(payload)  # TODO
    logger.trace(f"< POST /v1/melt/quote/bolt11: {quote}")
    return quote


@router.get(
    "/v1/melt/quote/bolt11/{quote}",
    summary="Get melt quote",
    response_model=PostMeltQuoteResponse,
    response_description="Get an existing melt quote to check its status.",
)
async def melt_quote(request: Request, quote: str) -> PostMeltQuoteResponse:
    """
    Get melt quote state.
    """
    logger.trace(f"> GET /v1/melt/quote/bolt11/{quote}")
    melt_quote = await gateway.get_melt_quote(quote)
    resp = PostMeltQuoteResponse(
        quote=melt_quote.quote,
        amount=melt_quote.amount,
        fee_reserve=melt_quote.fee_reserve,
        paid=melt_quote.paid,
        expiry=melt_quote.expiry,
    )
    logger.trace(f"< GET /v1/melt/quote/bolt11/{quote}")
    return resp


@router.post(
    "/v1/melt/bolt11",
    name="Melt tokens",
    summary=(
        "Melt tokens for a Bitcoin payment that the mint will make for the user in"
        " exchange"
    ),
    response_model=PostMeltResponse,
    response_description=(
        "The state of the payment, a preimage as proof of payment, and a list of"
        " promises for change."
    ),
)
async def melt(request: Request, payload: GatewayMeltRequest) -> GatewayMeltResponse:
    """
    Requests tokens to be destroyed and sent out via Lightning.
    """
    logger.trace(f"> POST /v1/melt/bolt11: {payload}")
    melt_response = await gateway.melt(proofs=payload.inputs, quote=payload.quote)
    logger.trace(f"< POST /v1/melt/bolt11: {melt_response}")
    return melt_response
