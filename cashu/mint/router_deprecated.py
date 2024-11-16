from typing import Dict, List, Optional

from fastapi import APIRouter, Request
from loguru import logger

from ..core.base import BlindedMessage, BlindedSignature, Unit
from ..core.errors import CashuError
from ..core.models import (
    CheckFeesRequest_deprecated,
    CheckFeesResponse_deprecated,
    CheckSpendableRequest_deprecated,
    CheckSpendableResponse_deprecated,
    GetInfoResponse_deprecated,
    GetMintResponse_deprecated,
    KeysetsResponse_deprecated,
    KeysResponse_deprecated,
    PostMeltQuoteRequest,
    PostMeltRequest_deprecated,
    PostMeltResponse_deprecated,
    PostMintQuoteRequest,
    PostMintRequest_deprecated,
    PostMintResponse_deprecated,
    PostRestoreRequest_Deprecated,
    PostRestoreResponse,
    PostSwapRequest_Deprecated,
    PostSwapResponse_Deprecated,
    PostSwapResponse_Very_Deprecated,
)
from ..core.settings import settings
from .limit import limiter
from .startup import ledger

router_deprecated: APIRouter = APIRouter()


@router_deprecated.get(
    "/info",
    name="Mint information",
    summary="Mint information, operator contact information, and other info.",
    response_model=GetInfoResponse_deprecated,
    response_model_exclude_none=True,
    deprecated=True,
)
async def info() -> GetInfoResponse_deprecated:
    logger.trace("> GET /info")
    return GetInfoResponse_deprecated(
        name=settings.mint_info_name,
        pubkey=ledger.pubkey.serialize().hex() if ledger.pubkey else None,
        version=f"Nutshell/{settings.version}",
        description=settings.mint_info_description,
        description_long=settings.mint_info_description_long,
        contact=settings.mint_info_contact,
        nuts=["NUT-07", "NUT-08", "NUT-09"],
        motd=settings.mint_info_motd,
        parameter={
            "max_peg_in": settings.mint_max_peg_in,
            "max_peg_out": settings.mint_max_peg_out,
            "peg_out_only": settings.mint_peg_out_only,
        },
    )


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
async def keys_deprecated() -> Dict[str, str]:
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
    response_model=Dict[str, str],
    deprecated=True,
)
async def keyset_deprecated(idBase64Urlsafe: str) -> Dict[str, str]:
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
    sat_keysets = {k: v for k, v in ledger.keysets.items() if v.unit == Unit.sat}
    keysets = KeysetsResponse_deprecated(keysets=list(sat_keysets.keys()))
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
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def request_mint_deprecated(
    request: Request, amount: int = 0
) -> GetMintResponse_deprecated:
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
    quote = await ledger.mint_quote(PostMintQuoteRequest(amount=amount, unit="sat"))
    resp = GetMintResponse_deprecated(pr=quote.request, hash=quote.quote)
    logger.trace(f"< GET /mint: {resp}")
    return resp


@router_deprecated.post(
    "/mint",
    name="Mint tokens",
    summary="Mint tokens in exchange for a Bitcoin payment that the user has made",
    response_model=PostMintResponse_deprecated,
    response_description=(
        "A list of blinded signatures that can be used to create proofs."
    ),
    deprecated=True,
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def mint_deprecated(
    request: Request,
    payload: PostMintRequest_deprecated,
    hash: Optional[str] = None,
    payment_hash: Optional[str] = None,
) -> PostMintResponse_deprecated:
    """
    Requests the minting of tokens belonging to a paid payment request.

    Call this endpoint after `GET /mint`.
    """
    logger.trace(f"> POST /mint: {payload}")

    # BEGIN BACKWARDS COMPATIBILITY < 0.15
    # Mint expects "id" in outputs to know which keyset to use to sign them.
    outputs: list[BlindedMessage] = [
        BlindedMessage(id=ledger.keyset.id, **o.dict(exclude={"id"}))
        for o in payload.outputs
    ]
    # END BACKWARDS COMPATIBILITY < 0.15

    # BEGIN: backwards compatibility < 0.12 where we used to lookup payments with payment_hash
    # We use the payment_hash to lookup the hash from the database and pass that one along.
    hash = payment_hash or hash
    assert hash, "hash must be set."
    # END: backwards compatibility < 0.12

    promises = await ledger.mint(outputs=outputs, quote_id=hash)
    blinded_signatures = PostMintResponse_deprecated(promises=promises)

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
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def melt_deprecated(
    request: Request,
    payload: PostMeltRequest_deprecated,
) -> PostMeltResponse_deprecated:
    """
    Requests tokens to be destroyed and sent out via Lightning.
    """
    logger.trace(f"> POST /melt: {payload}")
    # BEGIN BACKWARDS COMPATIBILITY < 0.14: add "id" to outputs
    if payload.outputs:
        outputs: list[BlindedMessage] = [
            BlindedMessage(id=ledger.keyset.id, **o.dict(exclude={"id"}))
            for o in payload.outputs
        ]
    else:
        outputs = []
    # END BACKWARDS COMPATIBILITY < 0.14
    quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=payload.pr, unit="sat")
    )
    melt_resp = await ledger.melt(
        proofs=payload.proofs, quote=quote.quote, outputs=outputs
    )
    resp = PostMeltResponse_deprecated(
        paid=True, preimage=melt_resp.payment_preimage, change=melt_resp.change
    )
    logger.trace(f"< POST /melt: {resp}")
    return resp


@router_deprecated.post(
    "/checkfees",
    name="Check fees",
    summary="Check fee reserve for a Lightning payment",
    response_model=CheckFeesResponse_deprecated,
    response_description="The fees necessary to pay a Lightning invoice.",
    deprecated=True,
)
async def check_fees(
    payload: CheckFeesRequest_deprecated,
) -> CheckFeesResponse_deprecated:
    """
    Responds with the fees necessary to pay a Lightning invoice.
    Used by wallets for figuring out the fees they need to supply together with the payment amount.
    This is can be useful for checking whether an invoice is internal (Cashu-to-Cashu).
    """
    logger.trace(f"> POST /checkfees: {payload}")
    quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=payload.pr, unit="sat")
    )
    fees_sat = quote.fee_reserve
    logger.trace(f"< POST /checkfees: {fees_sat}")
    return CheckFeesResponse_deprecated(fee=fees_sat)


@router_deprecated.post(
    "/split",
    name="Split",
    summary="Split proofs at a specified amount",
    # response_model=Union[
    #     PostSwapResponse_Very_Deprecated, PostSwapResponse_Deprecated
    # ],
    response_description=(
        "A list of blinded signatures that can be used to create proofs."
    ),
    deprecated=True,
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def split_deprecated(
    request: Request,
    payload: PostSwapRequest_Deprecated,
    # ) -> Union[PostSwapResponse_Very_Deprecated, PostSwapResponse_Deprecated]:
):
    """
    Requests a set of Proofs to be split into two a new set of BlindedSignatures.

    This endpoint is used by Alice to split a set of proofs before making a payment to Carol.
    It is then used by Carol (by setting split=total) to redeem the tokens.
    """
    logger.trace(f"> POST /split: {payload}")
    assert payload.outputs, Exception("no outputs provided.")
    # BEGIN BACKWARDS COMPATIBILITY < 0.14: add "id" to outputs
    outputs: list[BlindedMessage] = [
        BlindedMessage(id=ledger.keyset.id, **o.dict(exclude={"id"}))
        for o in payload.outputs
    ]
    # END BACKWARDS COMPATIBILITY < 0.14
    promises = await ledger.swap(proofs=payload.proofs, outputs=outputs)

    if payload.amount:
        # BEGIN backwards compatibility < 0.13
        # old clients expect two lists of promises where the second one's amounts
        # sum up to `amount`. The first one is the rest.
        # The returned value `promises` has the form [keep1, keep2, ..., send1, send2, ...]
        # The sum of the sendx is `amount`. We need to split this into two lists and keep the order of the elements.
        frst_promises: List[BlindedSignature] = []
        scnd_promises: List[BlindedSignature] = []
        scnd_amount = 0
        for promise in promises[::-1]:  # we iterate backwards
            if scnd_amount < payload.amount:
                scnd_promises.insert(0, promise)  # and insert at the beginning
                scnd_amount += promise.amount
            else:
                frst_promises.insert(0, promise)  # and insert at the beginning
        logger.trace(
            f"Split into keep: {len(frst_promises)}:"
            f" {sum([p.amount for p in frst_promises])} sat and send:"
            f" {len(scnd_promises)}: {sum([p.amount for p in scnd_promises])} sat"
        )
        return PostSwapResponse_Very_Deprecated(fst=frst_promises, snd=scnd_promises)
        # END backwards compatibility < 0.13
    else:
        return PostSwapResponse_Deprecated(promises=promises)


@router_deprecated.post(
    "/check",
    name="Check proof state",
    summary="Check whether a proof is spent already or is pending in a transaction",
    response_model=CheckSpendableResponse_deprecated,
    response_description=(
        "Two lists of booleans indicating whether the provided proofs "
        "are spendable or pending in a transaction respectively."
    ),
    deprecated=True,
)
async def check_spendable_deprecated(
    payload: CheckSpendableRequest_deprecated,
) -> CheckSpendableResponse_deprecated:
    """Check whether a secret has been spent already or not."""
    logger.trace(f"> POST /check: {payload}")
    proofs_state = await ledger.db_read.get_proofs_states([p.Y for p in payload.proofs])
    spendableList: List[bool] = []
    pendingList: List[bool] = []
    for proof_state in proofs_state:
        if proof_state.unspent:
            spendableList.append(True)
            pendingList.append(False)
        elif proof_state.spent:
            spendableList.append(False)
            pendingList.append(False)
        elif proof_state.pending:
            spendableList.append(True)
            pendingList.append(True)
    return CheckSpendableResponse_deprecated(
        spendable=spendableList, pending=pendingList
    )


@router_deprecated.post(
    "/restore",
    name="Restore",
    summary="Restores a blinded signature from a secret",
    response_model=PostRestoreResponse,
    response_description=(
        "Two lists with the first being the list of the provided outputs that "
        "have an associated blinded signature which is given in the second list."
    ),
    deprecated=True,
)
async def restore(payload: PostRestoreRequest_Deprecated) -> PostRestoreResponse:
    assert payload.outputs, Exception("no outputs provided.")
    if payload.outputs:
        outputs: list[BlindedMessage] = [
            BlindedMessage(id=ledger.keyset.id, **o.dict(exclude={"id"}))
            for o in payload.outputs
        ]
    else:
        outputs = []

    outputs, promises = await ledger.restore(outputs)
    return PostRestoreResponse(outputs=outputs, signatures=promises)
