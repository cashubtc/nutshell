import asyncio
import datetime
import hashlib
import time
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from loguru import logger
from pydantic import BaseModel

from ..core.crypto.b_dhke import hash_to_curve
from ..core.errors import KeysetNotFoundError
from ..core.models import (
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
    PostMintBatchRequest,
    PostMintBatchResponse,
    PostMintQuoteCheckRequest,
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
from .cache import RedisCache
from .limit import limit_websocket, limiter
from .pol import (
    build_trees_for_keyset_at_timestamp,
    generate_output_receipt,
    generate_spent_receipt,
    get_latest_pol_epoch,
    get_mint_signing_key,
    get_pol_epoch_by_index,
    parse_db_timestamp,
    update_pol_manifests,
)

router = APIRouter()
redis = RedisCache()


@router.get(
    "/v1/info",
    name="Mint information",
    summary="Mint information, operator contact information, and other info.",
    response_model=GetInfoResponse,
    response_model_exclude_none=True,
)
async def info() -> GetInfoResponse:
    logger.trace("> GET /v1/info")
    mint_info = ledger.mint_info
    return GetInfoResponse(
        name=mint_info.name,
        pubkey=mint_info.pubkey,
        version=mint_info.version,
        description=mint_info.description,
        description_long=mint_info.description_long,
        contact=mint_info.contact,
        nuts=mint_info.nuts,
        icon_url=mint_info.icon_url,
        tos_url=mint_info.tos_url,
        urls=settings.mint_info_urls,
        motd=mint_info.motd,
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
                    active=keyset.active,
                    input_fee_ppk=keyset.input_fee_ppk,
                    keys={k: v for k, v in keyset.public_keys_hex.items()},
                    final_expiry=keyset.final_expiry,  # NEW: Include final expiry to align with NUT-02 PR #182
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
        active=keyset.active,
        input_fee_ppk=keyset.input_fee_ppk,
        keys={k: v for k, v in keyset.public_keys_hex.items()},
        final_expiry=keyset.final_expiry,
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
                final_expiry=keyset.final_expiry,
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
        quote=quote.quote,
        request=quote.request,
        amount=quote.amount,
        unit=quote.unit,
        state=str(quote.state.value),
        expiry=quote.expiry,
        pubkey=quote.pubkey,
        amount_paid=quote.amount_paid,
        amount_issued=quote.amount_issued,
        updated_at=quote.updated_at,
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
        amount=mint_quote.amount,
        unit=mint_quote.unit,
        state=str(mint_quote.state.value),
        expiry=mint_quote.expiry,
        pubkey=mint_quote.pubkey,
        amount_paid=mint_quote.amount_paid,
        amount_issued=mint_quote.amount_issued,
        updated_at=mint_quote.updated_at,
    )
    logger.trace(f"< GET /v1/mint/quote/bolt11/{quote}")
    return resp


@router.post(
    "/v1/mint/quote/bolt11/check",
    name="Batch check mint quotes",
    summary="Batch check mint quotes",
    response_model=list[PostMintQuoteResponse],
    response_description="A list of mint quotes",
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def mint_quote_check(
    request: Request, payload: PostMintQuoteCheckRequest
) -> list[PostMintQuoteResponse]:
    logger.trace(f"> POST /v1/mint/quote/bolt11/check: payload={payload}")
    quotes = await ledger.mint_quote_check(payload)
    resp = [
        PostMintQuoteResponse(
            quote=quote.quote,
            request=quote.request,
            amount=quote.amount,
            unit=quote.unit,
            state=str(quote.state.value),
            expiry=quote.expiry,
            pubkey=quote.pubkey,
            amount_paid=quote.amount_paid,
            amount_issued=quote.amount_issued,
            updated_at=quote.updated_at,
        )
        for quote in quotes
    ]
    logger.trace(f"< POST /v1/mint/quote/bolt11/check: {resp}")
    return resp


@router.post(
    "/v1/mint/bolt11/batch",
    name="Batch mint tokens",
    summary="Batch mint tokens",
    response_model=PostMintBatchResponse,
    response_description="A list of blinded signatures that can be used to create proofs.",
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def mint_batch(
    request: Request, payload: PostMintBatchRequest
) -> PostMintBatchResponse:
    logger.trace(f"> POST /v1/mint/bolt11/batch: payload={payload}")
    signatures = await ledger.mint_batch(payload)

    for sig, output in zip(signatures, payload.outputs):
        sig.pol_receipt = await generate_output_receipt(
            ledger, keyset_id=sig.id, amount=sig.amount, b_hex=output.B_
        )
    resp = PostMintBatchResponse(signatures=signatures)
    logger.trace(f"< POST /v1/mint/bolt11/batch: {resp}")
    return resp


@router.websocket("/v1/ws", name="Websocket endpoint for subscriptions")
async def websocket_endpoint(websocket: WebSocket):
    limit_websocket(websocket)
    client = None
    try:
        client = ledger.events.add_client(websocket, ledger.db, ledger.crud)
    except Exception as e:
        logger.debug(f"Exception: {e}")
        await asyncio.wait_for(websocket.close(), timeout=1)
        return

    try:
        # this will block until the session is closed
        await client.start()
    except WebSocketDisconnect as e:
        logger.debug(f"Websocket disconnected: {e}")
    except Exception as e:
        logger.debug(f"Exception: {e}")
    finally:
        if client and client in ledger.events.clients:
            ledger.events.remove_client(client)
        if websocket.client_state.name != "DISCONNECTED":
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
@redis.cache()
async def mint(
    request: Request,
    payload: PostMintRequest,
) -> PostMintResponse:
    """
    Requests the minting of tokens belonging to a paid payment request.

    Call this endpoint after `POST /v1/mint/quote`.
    """
    logger.trace(f"> POST /v1/mint/bolt11: {payload}")

    promises = await ledger.mint(
        outputs=payload.outputs, quote_id=payload.quote, signature=payload.signature
    )

    for sig, output in zip(promises, payload.outputs):
        sig.pol_receipt = await generate_output_receipt(
            ledger, keyset_id=sig.id, amount=sig.amount, b_hex=output.B_
        )
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
        unit=melt_quote.unit,
        request=melt_quote.request,
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
@redis.cache()
async def melt(request: Request, payload: PostMeltRequest) -> PostMeltQuoteResponse:
    """
    Requests tokens to be destroyed and sent out via Lightning.
    """
    logger.trace(f"> POST /v1/melt/bolt11: {payload}")
    if payload.prefer_async:
        resp = await ledger.async_melt(
            proofs=payload.inputs, quote=payload.quote, outputs=payload.outputs
        )
    else:
        resp = await ledger.melt(
            proofs=payload.inputs, quote=payload.quote, outputs=payload.outputs
        )
    try:
        spent_receipts = []
        for p in payload.inputs:
            y_hex = hash_to_curve(p.secret.encode("utf-8")).format().hex()
            r_spent = await generate_spent_receipt(
                ledger, keyset_id=p.id, amount=p.amount, y_hex=y_hex
            )
            spent_receipts.append(r_spent)
        resp.spent_receipts = spent_receipts
    except Exception as e:
        logger.error(f"Failed to generate spent PoL receipts for melt: {e}")
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
@redis.cache()
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

    for sig, output in zip(signatures, payload.outputs):
        sig.pol_receipt = await generate_output_receipt(
            ledger, keyset_id=sig.id, amount=sig.amount, b_hex=output.B_
        )

    spent_receipts = []
    for p in payload.inputs:
        y_hex = hash_to_curve(p.secret.encode("utf-8")).format().hex()
        r_spent = await generate_spent_receipt(
            ledger, keyset_id=p.id, amount=p.amount, y_hex=y_hex
        )
        spent_receipts.append(r_spent)

    return PostSwapResponse(signatures=signatures, spent_receipts=spent_receipts)


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


class PolIssuedRequest(BaseModel):
    blinded_messages: List[str]


class PolSpentRequest(BaseModel):
    ys: List[str]


class SiblingInfo(BaseModel):
    hash: str
    sum: int


class PolProofItem(BaseModel):
    item: str
    index: str
    value: int
    compact_mask: str
    siblings: List[SiblingInfo]


class PolProofsResponse(BaseModel):
    proofs: List[PolProofItem]


class ManifestRoot(BaseModel):
    hash: str
    sum: int


class PolManifestResponse(BaseModel):
    keyset_id: str
    epoch_index: int
    timestamp: str
    signing_pubkey: str
    root_issued: ManifestRoot
    root_spent: ManifestRoot
    outstanding_balance: int
    ots_receipt: str
    mint_signature: str


@router.get(
    "/v1/pol/{keyset_id}/manifest",
    name="Proof of Liabilities Manifest",
    summary="Get the PoL manifest including MS-SMT roots, OTS receipt, and signature for a specific epoch (defaults to latest).",
    response_model=PolManifestResponse,
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def pol_manifest(
    request: Request,
    keyset_id: str,
    epoch_index: Optional[int] = None,
) -> PolManifestResponse:
    if keyset_id not in ledger.keysets:
        raise HTTPException(status_code=404, detail="Keyset not found")

    # Try to run regular manifest updates first
    await update_pol_manifests(ledger)

    if epoch_index is not None:
        epoch = await get_pol_epoch_by_index(ledger, keyset_id, epoch_index)
    else:
        epoch = await get_latest_pol_epoch(ledger, keyset_id)

    if not epoch:
        raise HTTPException(
            status_code=404, detail="No completed PoL epoch found for this keyset."
        )

    ts_val = epoch["timestamp"]
    ts_str = (
        ts_val.isoformat() if isinstance(ts_val, datetime.datetime) else str(ts_val)
    )

    _, pub_key_hex = get_mint_signing_key(ledger)

    return PolManifestResponse(
        keyset_id=epoch["keyset_id"],
        epoch_index=epoch["epoch_index"],
        timestamp=ts_str,
        signing_pubkey=pub_key_hex,
        root_issued=ManifestRoot(
            hash=epoch["root_issued_hash"], sum=epoch["root_issued_sum"]
        ),
        root_spent=ManifestRoot(
            hash=epoch["root_spent_hash"], sum=epoch["root_spent_sum"]
        ),
        outstanding_balance=epoch["outstanding_balance"],
        ots_receipt=epoch["ots_receipt"],
        mint_signature=epoch["signature"],
    )


@router.post(
    "/v1/pol/{keyset_id}/proofs/issued",
    name="Batch Issued Proofs",
    summary="Get MS-SMT inclusion proofs for a list of blinded messages relative to the last-tree.",
    response_model=PolProofsResponse,
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def pol_proofs_issued(
    request: Request,
    keyset_id: str,
    payload: PolIssuedRequest,
    epoch_index: Optional[int] = None,
) -> PolProofsResponse:
    if keyset_id not in ledger.keysets:
        raise HTTPException(status_code=404, detail="Keyset not found")

    if epoch_index is not None:
        epoch = await get_pol_epoch_by_index(ledger, keyset_id, epoch_index)
    else:
        epoch = await get_latest_pol_epoch(ledger, keyset_id)

    if not epoch:
        raise HTTPException(
            status_code=400,
            detail="No completed PoL epoch found for this keyset. Proofs are only available after an epoch has ended.",
        )

    epoch_time = parse_db_timestamp(epoch["timestamp"])

    # Build tree as of the epoch timestamp
    issued_tree, _ = await build_trees_for_keyset_at_timestamp(
        ledger, keyset_id, epoch_time, epoch_index=epoch["epoch_index"]
    )

    proof_items = []
    for b_hex in payload.blinded_messages:
        h_b = hashlib.sha256(bytes.fromhex(b_hex)).digest()
        idx_int = int.from_bytes(h_b, "big")

        # Check if active leaf
        level_nodes = issued_tree.tree_levels[0]
        leaf_node = level_nodes.get(idx_int) if level_nodes is not None else None
        value = leaf_node[1] if leaf_node else 0

        compact_mask, siblings = issued_tree.get_proof(idx_int)

        proof_items.append(
            PolProofItem(
                item=b_hex,
                index=h_b.hex(),
                value=value,
                compact_mask=compact_mask,
                siblings=[SiblingInfo(**s) for s in siblings],
            )
        )

    return PolProofsResponse(proofs=proof_items)


@router.post(
    "/v1/pol/{keyset_id}/proofs/spent",
    name="Batch Spent Proofs",
    summary="Get MS-SMT inclusion proofs for a list of spent secrets relative to the last-tree.",
    response_model=PolProofsResponse,
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def pol_proofs_spent(
    request: Request,
    keyset_id: str,
    payload: PolSpentRequest,
    epoch_index: Optional[int] = None,
) -> PolProofsResponse:
    if keyset_id not in ledger.keysets:
        raise HTTPException(status_code=404, detail="Keyset not found")

    if epoch_index is not None:
        epoch = await get_pol_epoch_by_index(ledger, keyset_id, epoch_index)
    else:
        epoch = await get_latest_pol_epoch(ledger, keyset_id)

    if not epoch:
        raise HTTPException(
            status_code=400,
            detail="No completed PoL epoch found for this keyset. Proofs are only available after an epoch has ended.",
        )

    epoch_time = parse_db_timestamp(epoch["timestamp"])

    # Build tree as of the epoch timestamp
    _, spent_tree = await build_trees_for_keyset_at_timestamp(
        ledger, keyset_id, epoch_time, epoch_index=epoch["epoch_index"]
    )

    proof_items = []
    for y_hex in payload.ys:
        h_y = hashlib.sha256(bytes.fromhex(y_hex)).digest()
        idx_int = int.from_bytes(h_y, "big")

        # Check if active leaf
        level_nodes = spent_tree.tree_levels[0]
        leaf_node = level_nodes.get(idx_int) if level_nodes is not None else None
        value = leaf_node[1] if leaf_node else 0

        compact_mask, siblings = spent_tree.get_proof(idx_int)

        proof_items.append(
            PolProofItem(
                item=y_hex,
                index=h_y.hex(),
                value=value,
                compact_mask=compact_mask,
                siblings=[SiblingInfo(**s) for s in siblings],
            )
        )

    return PolProofsResponse(proofs=proof_items)
