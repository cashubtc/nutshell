from fastapi import APIRouter, Request
from loguru import logger

from ..core.models import (
    PostMeltResponse,
    PostMintResponse,
)
from .models import (
    GatewayInfo,
    GatewayMeltQuoteRequest,
    GatewayMeltQuoteResponse,
    GatewayMeltRequest,
    GatewayMeltResponse,
    GatewayMint,
    GatewayMintQuoteRequest,
    GatewayMintQuoteResponse,
    GatewayMintRequest,
    GatewayMintResponse,
)
from .startup import gateway

router: APIRouter = APIRouter()


@router.get(
    "/v1/info",
    summary="Get gateway information",
    response_model=GatewayInfo,
)
async def get_info(request: Request) -> GatewayInfo:
    """
    Get information about the gateway.
    """
    logger.trace("> GET /v1/info")
    info = GatewayInfo(mints=[GatewayMint(mint=url) for url in gateway.wallets.keys()])
    logger.trace("< GET /v1/info")
    return info


@router.post(
    "/v1/mint/quote/bolt11",
    summary="Request a quote for minting tokens",
    response_model=GatewayMintQuoteResponse,
    response_description="Mint tokens for a payment on a supported payment method.",
)
async def get_mint_quote(
    request: Request, payload: GatewayMintQuoteRequest
) -> GatewayMintQuoteResponse:
    """
    Request a quote for minting tokens.
    """
    logger.trace(f"> POST /v1/mint/quote/bolt11: {payload}")
    quote = await gateway.gateway_mint_quote(payload)
    logger.trace(f"< POST /v1/mint/quote/bolt11: {quote}")
    return quote


@router.post(
    "/v1/mint/bolt11",
    name="Mint tokens",
    summary=(
        "Mint tokens for a Bitcoin payment that the mint will make for the user in"
        " exchange"
    ),
    response_model=PostMintResponse,
    response_description=(
        "The state of the payment, a preimage as proof of payment, and a list of"
        " promises for change."
    ),
)
async def mint(request: Request, payload: GatewayMintRequest) -> GatewayMintResponse:
    """
    Requests tokens to be destroyed and sent out via Lightning.
    """
    logger.trace(f"> POST /v1/mint/bolt11: {payload}")
    # TODO: CHECK IF IT WORKS (WIP COMMIT)
    mint_response = await gateway.gateway_mint(quote=payload.quote)
    logger.trace(f"< POST /v1/mint/bolt11: {mint_response}")
    return mint_response


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
    quote = await gateway.gateway_melt_quote(payload)
    logger.trace(f"< POST /v1/melt/quote/bolt11: {quote}")
    return quote


@router.get(
    "/v1/melt/quote/bolt11/{quote}",
    summary="Get melt quote",
    response_model=GatewayMeltQuoteResponse,
    response_description="Get an existing melt quote to check its status.",
)
async def melt_quote(request: Request, quote: str) -> GatewayMeltQuoteResponse:
    """
    Get melt quote state.
    """
    logger.trace(f"> GET /v1/melt/quote/bolt11/{quote}")
    melt_quote = await gateway.gateway_get_melt_quote(
        quote, check_quote_with_backend=True
    )
    resp = GatewayMeltQuoteResponse(
        pubkey=melt_quote.pubkey,
        quote=melt_quote.quote,
        amount=melt_quote.amount,
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
    melt_response = await gateway.gateway_melt(
        proofs=payload.inputs, quote=payload.quote
    )
    logger.trace(f"< POST /v1/melt/bolt11: {melt_response}")
    return melt_response
