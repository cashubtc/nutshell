from fastapi import APIRouter, Request
from loguru import logger

from ...core.errors import KeysetNotFoundError
from ...core.models import (
    KeysetsResponse,
    KeysetsResponseKeyset,
    KeysResponse,
    KeysResponseKeyset,
    PostAuthBlindMintRequest,
    PostAuthBlindMintResponse,
)
from ...mint.startup import auth_ledger

auth_router: APIRouter = APIRouter()


@auth_router.get(
    "/v1/auth/blind/keys",
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
    keyset = auth_ledger.keyset
    keyset_for_response = []
    for keyset in auth_ledger.keysets.values():
        if keyset.active:
            keyset_for_response.append(
                KeysResponseKeyset(
                    id=keyset.id,
                    unit=keyset.unit.name,
                    keys={k: v for k, v in keyset.public_keys_hex.items()},
                )
            )
    return KeysResponse(keysets=keyset_for_response)


@auth_router.get(
    "/v1/auth/blind/keys/{keyset_id}",
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

    keyset = auth_ledger.keysets.get(keyset_id)
    if keyset is None:
        raise KeysetNotFoundError(keyset_id)

    keyset_for_response = KeysResponseKeyset(
        id=keyset.id,
        unit=keyset.unit.name,
        keys={k: v for k, v in keyset.public_keys_hex.items()},
    )
    return KeysResponse(keysets=[keyset_for_response])


@auth_router.get(
    "/v1/auth/blind/keysets",
    name="Active keysets",
    summary="Get all active keyset id of the mind",
    response_model=KeysetsResponse,
    response_description="A list of all active keyset ids of the mint.",
)
async def keysets() -> KeysetsResponse:
    """This endpoint returns a list of keysets that the mint currently supports and will accept tokens from."""
    logger.trace("> GET /v1/keysets")
    keysets = []
    for id, keyset in auth_ledger.keysets.items():
        keysets.append(
            KeysetsResponseKeyset(
                id=keyset.id,
                unit=keyset.unit.name,
                active=keyset.active,
            )
        )
    return KeysetsResponse(keysets=keysets)


@auth_router.post(
    "/v1/auth/blind/mint",
    name="Mint blind auth tokens",
    summary="Mint blind auth tokens for a user.",
    response_model=PostAuthBlindMintResponse,
)
async def auth_blind_mint(
    request_data: PostAuthBlindMintRequest, request: Request
) -> PostAuthBlindMintResponse:
    clear_auth_token = request.headers.get("clear-auth")
    if not clear_auth_token:
        raise Exception("Missing clearauth token.")
    try:
        user = await auth_ledger.verify_clear_auth(clear_auth_token=clear_auth_token)
    except Exception as e:
        raise e
    signatures = await auth_ledger.mint_blind_auth(
        outputs=request_data.outputs, user=user
    )
    return PostAuthBlindMintResponse(signatures=signatures)
