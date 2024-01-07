from typing import Any, Dict, List

from fastapi import APIRouter, Request
from loguru import logger

from ..core.base import (
    GetInfoResponse,
    KeysetsResponse,
    KeysetsResponseKeyset,
    KeysResponse,
    KeysResponseKeyset,
    PostCheckStateRequest,
    PostCheckStateResponse,
    PostMeltQuoteRequest,
    PostMeltQuoteResponse,
    PostMeltRequest,
    PostMeltResponse,
    PostMintQuoteRequest,
    PostMintQuoteResponse,
    PostMintRequest,
    PostMintResponse,
    PostRestoreResponse,
    PostSplitRequest,
    PostSplitResponse,
)
from ..core.errors import CashuError
from ..core.settings import settings
from ..mint.startup import ledger

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

    # determine all method-unit pairs
    method_unit_pairs: List[List[str]] = []
    for method, unit_dict in ledger.backends.items():
        for unit in unit_dict.keys():
            method_unit_pairs.append([method.name, unit.name])
    supported_dict = dict(supported=True)

    mint_features: Dict[int, Dict[str, Any]] = {
        4: dict(
            methods=method_unit_pairs,
        ),
        5: dict(
            methods=method_unit_pairs,
            disabled=False,
        ),
        7: supported_dict,
        8: supported_dict,
        9: supported_dict,
        10: supported_dict,
        11: supported_dict,
        12: supported_dict,
    }

    return GetInfoResponse(
        name=settings.mint_info_name,
        pubkey=ledger.pubkey.serialize().hex() if ledger.pubkey else None,
        version=f"Nutshell/{settings.version}",
        description=settings.mint_info_description,
        description_long=settings.mint_info_description_long,
        contact=settings.mint_info_contact,
        nuts=mint_features,
        motd=settings.mint_info_motd,
    )


@router.get(
    "/v1/keys",
    name="Mint public keys",
    summary="Get the public keys of the newest mint keyset",
    response_description=(
        "A dictionary of all supported token values of the mint and their associated"
        " public key of the current keyset."
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
        "A dictionary of all supported token values of the mint and their associated"
        " public key for a specific keyset."
    ),
    response_model=KeysResponse,
)
async def keyset_keys(keyset_id: str, request: Request) -> KeysResponse:
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
        raise CashuError(code=0, detail="Keyset not found.")

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
                id=id, unit=keyset.unit.name, active=keyset.active or False
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
async def mint_quote(payload: PostMintQuoteRequest) -> PostMintQuoteResponse:
    """
    Request minting of new tokens. The mint responds with a Lightning invoice.
    This endpoint can be used for a Lightning invoice UX flow.

    Call `POST /v1/mint/bolt11` after paying the invoice.
    """
    logger.trace(f"> POST /v1/mint/quote/bolt11: payload={payload}")
    amount = payload.amount
    if amount > 21_000_000 * 100_000_000 or amount <= 0:
        raise CashuError(code=0, detail="Amount must be a valid amount of sat.")
    if settings.mint_peg_out_only:
        raise CashuError(code=0, detail="Mint does not allow minting new tokens.")

    quote = await ledger.mint_quote(payload)
    resp = PostMintQuoteResponse(
        request=quote.request,
        quote=quote.quote,
        paid=quote.paid,
        expiry=quote.expiry,
    )
    logger.trace(f"< POST /v1/mint/quote/bolt11: {resp}")
    return resp


@router.get(
    "/v1/mint/quote/{quote}",
    summary="Get mint quote",
    response_model=PostMintQuoteResponse,
    response_description="Get an existing mint quote to check its status.",
)
async def get_mint_quote(quote: str) -> PostMintQuoteResponse:
    """
    Get mint quote state.
    """
    logger.trace(f"> POST /v1/mint/quote/{quote}")
    mint_quote = await ledger.get_mint_quote(quote)
    resp = PostMintQuoteResponse(
        quote=mint_quote.quote,
        request=mint_quote.request,
        paid=mint_quote.paid,
        expiry=mint_quote.expiry,
    )
    logger.trace(f"< POST /v1/mint/quote/{quote}")
    return resp


@router.post(
    "/v1/mint/bolt11",
    name="Mint tokens",
    summary="Mint tokens in exchange for a Bitcoin payment that the user has made",
    response_model=PostMintResponse,
    response_description=(
        "A list of blinded signatures that can be used to create proofs."
    ),
)
async def mint(
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
async def get_melt_quote(payload: PostMeltQuoteRequest) -> PostMeltQuoteResponse:
    """
    Request a quote for melting tokens.
    """
    logger.trace(f"> POST /v1/melt/quote/bolt11: {payload}")
    quote = await ledger.melt_quote(payload)  # TODO
    logger.trace(f"< POST /v1/melt/quote/bolt11: {quote}")
    return quote


@router.get(
    "/v1/melt/quote/{quote}",
    summary="Get melt quote",
    response_model=PostMeltQuoteResponse,
    response_description="Get an existing melt quote to check its status.",
)
async def melt_quote(quote: str) -> PostMeltQuoteResponse:
    """
    Get melt quote state.
    """
    logger.trace(f"> POST /v1/melt/quote/{quote}")
    melt_quote = await ledger.get_melt_quote(quote)
    resp = PostMeltQuoteResponse(
        quote=melt_quote.quote,
        amount=melt_quote.amount,
        fee_reserve=melt_quote.fee_reserve,
        paid=melt_quote.paid,
    )
    logger.trace(f"< POST /v1/melt/quote/{quote}")
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
async def melt(payload: PostMeltRequest) -> PostMeltResponse:
    """
    Requests tokens to be destroyed and sent out via Lightning.
    """
    logger.trace(f"> POST /v1/melt/bolt11: {payload}")
    preimage, change_promises = await ledger.melt(
        proofs=payload.inputs, quote=payload.quote, outputs=payload.outputs
    )
    resp = PostMeltResponse(
        paid=True, payment_preimage=preimage, change=change_promises
    )
    logger.trace(f"< POST /v1/melt/bolt11: {resp}")
    return resp


@router.post(
    "/v1/swap",
    name="Swap tokens",
    summary="Swap inputs for outputs of the same value",
    response_model=PostSplitResponse,
    response_description=(
        "An array of blinded signatures that can be used to create proofs."
    ),
)
async def split(
    payload: PostSplitRequest,
) -> PostSplitResponse:
    """
    Requests a set of Proofs to be split into two a new set of BlindedSignatures.

    This endpoint is used by Alice to split a set of proofs before making a payment to Carol.
    It is then used by Carol (by setting split=total) to redeem the tokens.
    """
    logger.trace(f"> POST /v1/swap: {payload}")
    assert payload.outputs, Exception("no outputs provided.")

    signatures = await ledger.split(proofs=payload.inputs, outputs=payload.outputs)

    return PostSplitResponse(signatures=signatures)


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
    proof_states = await ledger.check_proofs_state(payload.secrets)
    return PostCheckStateResponse(states=proof_states)


@router.post(
    "/v1/restore",
    name="Restore",
    summary="Restores a blinded signature from a secret",
    response_model=PostRestoreResponse,
    response_description=(
        "Two lists with the first being the list of the provided outputs that "
        "have an associated blinded signature which is given in the second list."
    ),
)
async def restore(payload: PostMintRequest) -> PostRestoreResponse:
    assert payload.outputs, Exception("no outputs provided.")
    outputs, promises = await ledger.restore(payload.outputs)
    return PostRestoreResponse(outputs=outputs, promises=promises)
