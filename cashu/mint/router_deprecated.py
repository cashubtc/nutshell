from typing import Optional

from fastapi import APIRouter
from loguru import logger

from ..core.base import (
    GetMintResponse_deprecated,
    KeysetsResponse_deprecated,
    KeysResponse_deprecated,
    PostMeltRequest_deprecated,
    PostMeltResponse_deprecated,
    PostMintRequest,
    PostMintResponse,
)
from ..core.errors import CashuError
from ..core.settings import settings
from .startup import ledger

router_deprecated: APIRouter = APIRouter()


@router_deprecated.get(
    "/keys",
    name="Mint public keys",
    summary="Get the public keys of the newest mint keyset",
    response_description=(
        "A dictionary of all supported token values of the mint and their associated"
        " public key of the current keyset."
    ),
    response_model=KeysResponse_deprecated,
    deprecated=True,
)
async def keys_deprecated():
    """This endpoint returns a dictionary of all supported token values of the mint and their associated public key."""
    logger.trace("> GET /keys")
    keyset = ledger.get_keyset()
    keys = KeysResponse_deprecated.parse_obj(keyset)
    return keys.__root__


@router_deprecated.get(
    "/keys/{idBase64Urlsafe}",
    name="Keyset public keys",
    summary="Public keys of a specific keyset",
    response_description=(
        "A dictionary of all supported token values of the mint and their associated"
        " public key for a specific keyset."
    ),
    response_model=KeysResponse_deprecated,
    deprecated=True,
)
async def keyset_deprecated(idBase64Urlsafe: str):
    """
    Get the public keys of the mint from a specific keyset id.
    The id is encoded in idBase64Urlsafe (by a wallet) and is converted back to
    normal base64 before it can be processed (by the mint).
    """
    logger.trace(f"> GET /keys/{idBase64Urlsafe}")
    id = idBase64Urlsafe.replace("-", "+").replace("_", "/")
    keyset = ledger.get_keyset(keyset_id=id)
    keys = KeysResponse_deprecated.parse_obj(keyset)
    return keys.__root__


@router_deprecated.get(
    "/keysets",
    name="Active keysets",
    summary="Get all active keyset id of the mind",
    response_model=KeysetsResponse_deprecated,
    response_description="A list of all active keyset ids of the mint.",
    deprecated=True,
)
async def keysets_deprecated() -> KeysetsResponse_deprecated:
    """This endpoint returns a list of keysets that the mint currently supports and will accept tokens from."""
    logger.trace("> GET /keysets")
    keysets = KeysetsResponse_deprecated(keysets=ledger.keysets.get_ids())
    return keysets


@router_deprecated.get(
    "/mint",
    name="Request mint",
    summary="Request minting of new tokens",
    response_model=GetMintResponse_deprecated,
    response_description=(
        "A Lightning invoice to be paid and a hash to request minting of new tokens"
        " after payment."
    ),
    deprecated=True,
)
async def request_mint_deprecated(amount: int = 0) -> GetMintResponse_deprecated:
    """
    Request minting of new tokens. The mint responds with a Lightning invoice.
    This endpoint can be used for a Lightning invoice UX flow.

    Call `POST /mint` after paying the invoice.
    """
    logger.trace(f"> GET /mint: amount={amount}")
    if amount > 21_000_000 * 100_000_000 or amount <= 0:
        raise CashuError(code=0, detail="Amount must be a valid amount of sat.")
    if settings.mint_peg_out_only:
        raise CashuError(code=0, detail="Mint does not allow minting new tokens.")

    payment_request, hash = await ledger.request_mint(amount)
    resp = GetMintResponse_deprecated(pr=payment_request, hash=hash)
    logger.trace(f"< GET /mint: {resp}")
    return resp


@router_deprecated.post(
    "/mint",
    name="Mint tokens",
    summary="Mint tokens in exchange for a Bitcoin payment that the user has made",
    response_model=PostMintResponse,
    response_description=(
        "A list of blinded signatures that can be used to create proofs."
    ),
    deprecated=True,
)
async def mint_deprecated(
    payload: PostMintRequest,
    hash: Optional[str] = None,
    payment_hash: Optional[str] = None,
) -> PostMintResponse:
    """
    Requests the minting of tokens belonging to a paid payment request.

    Call this endpoint after `GET /mint`.
    """
    logger.trace(f"> POST /mint: {payload}")

    # BEGIN: backwards compatibility < 0.12 where we used to lookup payments with payment_hash
    # We use the payment_hash to lookup the hash from the database and pass that one along.
    hash = payment_hash or hash
    # END: backwards compatibility < 0.12

    promises = await ledger.mint(outputs=payload.outputs, id=hash)
    blinded_signatures = PostMintResponse(promises=promises)
    logger.trace(f"< POST /mint: {blinded_signatures}")
    return blinded_signatures


@router_deprecated.post(
    "/melt",
    name="Melt tokens",
    summary=(
        "Melt tokens for a Bitcoin payment that the mint will make for the user in"
        " exchange"
    ),
    response_model=PostMeltResponse_deprecated,
    response_description=(
        "The state of the payment, a preimage as proof of payment, and a list of"
        " promises for change."
    ),
    deprecated=True,
)
async def melt_deprecated(
    payload: PostMeltRequest_deprecated,
) -> PostMeltResponse_deprecated:
    """
    Requests tokens to be destroyed and sent out via Lightning.
    """
    logger.trace(f"> POST /melt: {payload}")
    ok, preimage, change_promises = await ledger.melt(
        payload.proofs, payload.pr, payload.outputs
    )
    resp = PostMeltResponse_deprecated(
        paid=ok, preimage=preimage, change=change_promises
    )
    logger.trace(f"< POST /melt: {resp}")
    return resp
