import asyncio
import time

from fastapi import APIRouter, Request, WebSocket
from loguru import logger

from ..core.errors import KeysetNotFoundError
from ..core.models import (
    GetInfoResponse,
    KeysetsResponse,
    KeysetsResponseKeyset,
    KeysResponse,
    KeysResponseKeyset,
    MintInfoContact,
    PostCheckStateRequest,
    PostCheckStateResponse,
    PostMeltQuoteRequest,
    PostMeltQuoteResponse,
    PostMeltRequest,
    PostMintQuoteRequest,
    PostMintQuoteResponse,
    PostMintRequest,
    PostMintResponse,
    PostRestoreRequest,
    PostRestoreResponse,
    PostSwapRequest,
    PostSwapResponse,
)
from ..core.settings import settings
from ..mint.startup import ledger
from .limit import limit_websocket, limiter

router: APIRouter = APIRouter()


@router.get(
    "/v1/info",
    name="Mint information",
    summary="Mint information, operator contact information, and other info.",
    response_model=GetInfoResponse,
    response_model_exclude_none=True,
)
async def info() -> GetInfoResponse:
    logger.trace("> GET /v1/info")
    mint_features = ledger.mint_features()
    contact_info = [
        MintInfoContact(method=m, info=i)
        for m, i in settings.mint_info_contact
        if m and i
    ]
    return GetInfoResponse(
        name=settings.mint_info_name,
        pubkey=ledger.pubkey.serialize().hex() if ledger.pubkey else None,
        version=f"Nutshell/{settings.version}",
        description=settings.mint_info_description,
        description_long=settings.mint_info_description_long,
        contact=contact_info,
        nuts=mint_features,
        icon_url=settings.mint_info_icon_url,
        urls=settings.mint_info_urls,
        motd=settings.mint_info_motd,
        time=int(time.time()),
    )


@router.get(
    "/v1/keys",
    name="Mint public keys",
    summary="Get the public keys of the newest mint keyset",
    response_description=(
        "All supported token values their associated public keys for all active keysets"
    ),
    response_model=KeysResponse,
)
async def keys():
    """This endpoint returns a dictionary of all supported token values of the mint and their associated public key."""
    logger.trace("> GET /v1/keys")
    keyset = ledger.keyset
    keyset_for_response = []
    for keyset in ledger.keysets.values():
        if keyset.active:
            keyset_for_response.append(
                KeysResponseKeyset(
                    id=keyset.id,
                    unit=keyset.unit.name,
                    keys={k: v for k, v in keyset.public_keys_hex.items()},
                )
            )
    return KeysResponse(keysets=keyset_for_response)


@router.get(
    "/v1/keys/{keyset_id}",
    name="Keyset public keys",
    summary="Public keys of a specific keyset",
    response_description=(
        "All supported token values of the mint and their associated"
        " public key for a specific keyset."
    ),
    response_model=KeysResponse,
)
async def keyset_keys(keyset_id: str) -> KeysResponse:
    """
    Get the public keys of the mint from a specific keyset id.
    """
    logger.trace(f"> GET /v1/keys/{keyset_id}")
    # BEGIN BACKWARDS COMPATIBILITY < 0.15.0
    # if keyset_id is not hex, we assume it is base64 and sanitize it
    try:
        int(keyset_id, 16)
    except ValueError:
        keyset_id = keyset_id.replace("-", "+").replace("_", "/")
    # END BACKWARDS COMPATIBILITY < 0.15.0

    keyset = ledger.keysets.get(keyset_id)
    if keyset is None:
        raise KeysetNotFoundError(keyset_id)

    keyset_for_response = KeysResponseKeyset(
        id=keyset.id,
        unit=keyset.unit.name,
        keys={k: v for k, v in keyset.public_keys_hex.items()},
    )
    return KeysResponse(keysets=[keyset_for_response])


@router.get(
    "/v1/keysets",
    name="Active keysets",
    summary="Get all active keyset id of the mind",
    response_model=KeysetsResponse,
    response_description="A list of all active keyset ids of the mint.",
)
async def keysets() -> KeysetsResponse:
    """This endpoint returns a list of keysets that the mint currently supports and will accept tokens from."""
    logger.trace("> GET /v1/keysets")
    keysets = []
    for id, keyset in ledger.keysets.items():
        keysets.append(
            KeysetsResponseKeyset(
                id=keyset.id,
                unit=keyset.unit.name,
                active=keyset.active,
                input_fee_ppk=keyset.input_fee_ppk,
            )
        )
    return KeysetsResponse(keysets=keysets)


@router.post(
    "/v1/mint/quote/bolt11",
    name="Request mint quote",
    summary="Request a quote for minting of new tokens",
    response_model=PostMintQuoteResponse,
    response_description="A payment request to mint tokens of a denomination",
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def mint_quote(
    request: Request, payload: PostMintQuoteRequest
) -> PostMintQuoteResponse:
    """
    Request minting of new tokens. The mint responds with a Lightning invoice.
    This endpoint can be used for a Lightning invoice UX flow.

    Call `POST /v1/mint/bolt11` after paying the invoice.
    """
    logger.trace(f"> POST /v1/mint/quote/bolt11: payload={payload}")
    quote = await ledger.mint_quote(payload)
    resp = PostMintQuoteResponse(
        request=quote.request,
        quote=quote.quote,
        paid=quote.paid,  # deprecated
        state=quote.state.value,
        expiry=quote.expiry,
    )
    logger.trace(f"< POST /v1/mint/quote/bolt11: {resp}")
    return resp


@router.get(
    "/v1/mint/quote/bolt11/{quote}",
    summary="Get mint quote",
    response_model=PostMintQuoteResponse,
    response_description="Get an existing mint quote to check its status.",
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def get_mint_quote(request: Request, quote: str) -> PostMintQuoteResponse:
    """
    Get mint quote state.
    """
    logger.trace(f"> GET /v1/mint/quote/bolt11/{quote}")
    mint_quote = await ledger.get_mint_quote(quote)
    resp = PostMintQuoteResponse(
        quote=mint_quote.quote,
        request=mint_quote.request,
        paid=mint_quote.paid,  # deprecated
        state=mint_quote.state.value,
        expiry=mint_quote.expiry,
    )
    logger.trace(f"< GET /v1/mint/quote/bolt11/{quote}")
    return resp


@router.websocket("/v1/ws", name="Websocket endpoint for subscriptions")
async def websocket_endpoint(websocket: WebSocket):
    limit_websocket(websocket)
    try:
        client = ledger.events.add_client(websocket, ledger.db, ledger.crud)
    except Exception as e:
        logger.debug(f"Exception: {e}")
        await asyncio.wait_for(websocket.close(), timeout=1)
        return

    try:
        # this will block until the session is closed
        await client.start()
    except Exception as e:
        logger.debug(f"Exception: {e}")
        ledger.events.remove_client(client)
    finally:
        await asyncio.wait_for(websocket.close(), timeout=1)


@router.post(
    "/v1/mint/bolt11",
    name="Mint tokens with a Lightning payment",
    summary="Mint tokens by paying a bolt11 Lightning invoice.",
    response_model=PostMintResponse,
    response_description=(
        "A list of blinded signatures that can be used to create proofs."
    ),
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def mint(
    request: Request,
    payload: PostMintRequest,
) -> PostMintResponse:
    """
    Requests the minting of tokens belonging to a paid payment request.

    Call this endpoint after `POST /v1/mint/quote`.
    """
    logger.trace(f"> POST /v1/mint/bolt11: {payload}")

    promises = await ledger.mint(outputs=payload.outputs, quote_id=payload.quote)
    blinded_signatures = PostMintResponse(signatures=promises)
    logger.trace(f"< POST /v1/mint/bolt11: {blinded_signatures}")
    return blinded_signatures


@router.post(
    "/v1/melt/quote/bolt11",
    summary="Request a quote for melting tokens",
    response_model=PostMeltQuoteResponse,
    response_description="Melt tokens for a payment on a supported payment method.",
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def melt_quote(
    request: Request, payload: PostMeltQuoteRequest
) -> PostMeltQuoteResponse:
    """
    Request a quote for melting tokens.
    """
    logger.trace(f"> POST /v1/melt/quote/bolt11: {payload}")
    quote = await ledger.melt_quote(payload)  # TODO
    logger.trace(f"< POST /v1/melt/quote/bolt11: {quote}")
    return quote


@router.get(
    "/v1/melt/quote/bolt11/{quote}",
    summary="Get melt quote",
    response_model=PostMeltQuoteResponse,
    response_description="Get an existing melt quote to check its status.",
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def get_melt_quote(request: Request, quote: str) -> PostMeltQuoteResponse:
    """
    Get melt quote state.
    """
    logger.trace(f"> GET /v1/melt/quote/bolt11/{quote}")
    melt_quote = await ledger.get_melt_quote(quote)
    resp = PostMeltQuoteResponse(
        quote=melt_quote.quote,
        amount=melt_quote.amount,
        fee_reserve=melt_quote.fee_reserve,
        paid=melt_quote.paid,
        state=melt_quote.state.value,
        expiry=melt_quote.expiry,
        payment_preimage=melt_quote.payment_preimage,
        change=melt_quote.change,
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
    response_model=PostMeltQuoteResponse,
    response_description=(
        "The state of the payment, a preimage as proof of payment, and a list of"
        " promises for change."
    ),
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def melt(request: Request, payload: PostMeltRequest) -> PostMeltQuoteResponse:
    """
    Requests tokens to be destroyed and sent out via Lightning.
    """
    logger.trace(f"> POST /v1/melt/bolt11: {payload}")
    resp = await ledger.melt(
        proofs=payload.inputs, quote=payload.quote, outputs=payload.outputs
    )
    logger.trace(f"< POST /v1/melt/bolt11: {resp}")
    return resp


@router.post(
    "/v1/swap",
    name="Swap tokens",
    summary="Swap inputs for outputs of the same value",
    response_model=PostSwapResponse,
    response_description=(
        "An array of blinded signatures that can be used to create proofs."
    ),
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def swap(
    request: Request,
    payload: PostSwapRequest,
) -> PostSwapResponse:
    """
    Requests a set of Proofs to be swapped for another set of BlindSignatures.

    This endpoint can be used by Alice to swap a set of proofs before making a payment to Carol.
    It can then used by Carol to redeem the tokens for new proofs.
    """
    logger.trace(f"> POST /v1/swap: {payload}")
    assert payload.outputs, Exception("no outputs provided.")

    signatures = await ledger.swap(proofs=payload.inputs, outputs=payload.outputs)

    return PostSwapResponse(signatures=signatures)


@router.post(
    "/v1/checkstate",
    name="Check proof state",
    summary="Check whether a proof is spent already or is pending in a transaction",
    response_model=PostCheckStateResponse,
    response_description=(
        "Two lists of booleans indicating whether the provided proofs "
        "are spendable or pending in a transaction respectively."
    ),
)
async def check_state(
    payload: PostCheckStateRequest,
) -> PostCheckStateResponse:
    """Check whether a secret has been spent already or not."""
    logger.trace(f"> POST /v1/checkstate: {payload}")
    proof_states = await ledger.db_read.get_proofs_states(payload.Ys)
    return PostCheckStateResponse(states=proof_states)


@router.post(
    "/v1/restore",
    name="Restore",
    summary="Restores blind signature for a set of outputs.",
    response_model=PostRestoreResponse,
    response_description=(
        "Two lists with the first being the list of the provided outputs that "
        "have an associated blinded signature which is given in the second list."
    ),
)
async def restore(payload: PostRestoreRequest) -> PostRestoreResponse:
    assert payload.outputs, Exception("no outputs provided.")
    outputs, signatures = await ledger.restore(payload.outputs)
    return PostRestoreResponse(outputs=outputs, signatures=signatures)
