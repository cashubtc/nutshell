from typing import Dict, List, Optional, Union

from fastapi import APIRouter
from secp256k1 import PublicKey

from ..core.base import (
    BlindedMessage,
    BlindedSignature,
    CheckFeesRequest,
    CheckFeesResponse,
    CheckSpendableRequest,
    CheckSpendableResponse,
    GetInfoResponse,
    GetMeltResponse,
    GetMintResponse,
    KeysetsResponse,
    KeysResponse,
    PostMeltRequest,
    PostMintRequest,
    PostMintResponse,
    PostSplitRequest,
    PostSplitResponse,
)
from ..core.errors import CashuError
from ..core.settings import settings
from ..mint.startup import ledger

router: APIRouter = APIRouter()


@router.get(
    "/info",
    name="Mint information",
    summary="Mint information, operator contact information, and other info.",
    response_model=GetInfoResponse,
    response_model_exclude_none=True,
)
async def info():
    return GetInfoResponse(
        name=settings.mint_info_name,
        pubkey=ledger.pubkey.serialize().hex() if ledger.pubkey else None,
        version=f"Nutshell/{settings.version}",
        description=settings.mint_info_description,
        description_long=settings.mint_info_description_long,
        contact=settings.mint_info_contact,
        nuts=settings.mint_info_nuts,
        motd=settings.mint_info_motd,
        parameter={"max_peg_in": settings.mint_max_peg_in,
                   "max_peg_out": settings.mint_max_peg_out,
                   "peg_out_only": settings.mint_peg_out_only
                   }
    )


@router.get(
    "/keys",
    name="Mint public keys",
    summary="Get the public keys of the newest mint keyset",
)
async def keys() -> KeysResponse:
    """This endpoint returns a dictionary of all supported token values of the mint and their associated public key."""
    keyset = ledger.get_keyset()
    keys = KeysResponse.parse_obj(keyset)
    return keys


@router.get(
    "/keys/{idBase64Urlsafe}",
    name="Keyset public keys",
    summary="Public keys of a specific keyset",
)
async def keyset_keys(idBase64Urlsafe: str) -> Union[KeysResponse, CashuError]:
    """
    Get the public keys of the mint from a specific keyset id.
    The id is encoded in idBase64Urlsafe (by a wallet) and is converted back to
    normal base64 before it can be processed (by the mint).
    """
    try:
        id = idBase64Urlsafe.replace("-", "+").replace("_", "/")
        keyset = ledger.get_keyset(keyset_id=id)
        keys = KeysResponse.parse_obj(keyset)
        return keys
    except Exception as exc:
        return CashuError(code=0, error=str(exc))


@router.get(
    "/keysets", name="Active keysets", summary="Get all active keyset id of the mind"
)
async def keysets() -> KeysetsResponse:
    """This endpoint returns a list of keysets that the mint currently supports and will accept tokens from."""
    keysets = KeysetsResponse(keysets=ledger.keysets.get_ids())
    return keysets


@router.get("/mint", name="Request mint", summary="Request minting of new tokens")
async def request_mint(amount: int = 0) -> Union[GetMintResponse, CashuError]:
    """
    Request minting of new tokens. The mint responds with a Lightning invoice.
    This endpoint can be used for a Lightning invoice UX flow.

    Call `POST /mint` after paying the invoice.
    """
    if settings.mint_peg_out_only:
        return CashuError(code=0, error="Mint does not allow minting new tokens.")
    if settings.mint_max_peg_in and amount > settings.mint_max_peg_in:
        return CashuError(code=0, error=f"Maximum amount to mint is {settings.mint_max_peg_in} sats "
                                        f"({amount} sats requested).")
    payment_request, hash = await ledger.request_mint(amount)
    print(f"Lightning invoice: {payment_request}")
    resp = GetMintResponse(pr=payment_request, hash=hash)
    return resp


@router.post(
    "/mint",
    name="Mint tokens",
    summary="Mint tokens in exchange for a Bitcoin paymemt that the user has made",
)
async def mint(
    payload: PostMintRequest,
    hash: Optional[str] = None,
    payment_hash: Optional[str] = None,
) -> Union[PostMintResponse, CashuError]:
    """
    Requests the minting of tokens belonging to a paid payment request.

    Call this endpoint after `GET /mint`.
    """
    if settings.mint_peg_out_only:
        return CashuError(code=0, error="Mint does not allow minting new tokens.")
    if settings.mint_max_peg_in:
        amount_requested = sum([b.amount for b in payload.outputs])
        if amount_requested > settings.mint_max_peg_in:
            return CashuError(code=0, error=f"Maximum amount to mint is {settings.mint_max_peg_in} sats "
                                            f"({amount_requested} sats requested).")
    try:
        # BEGIN: backwards compatibility < 0.12 where we used to lookup payments with payment_hash
        # We use the payment_hash to lookup the hash from the database and pass that one along.
        hash = payment_hash or hash
        # END: backwards compatibility < 0.12

        promises = await ledger.mint(payload.outputs, hash=hash)
        blinded_signatures = PostMintResponse(promises=promises)
        return blinded_signatures
    except Exception as exc:
        return CashuError(code=0, error=str(exc))


@router.post(
    "/melt",
    name="Melt tokens",
    summary="Melt tokens for a Bitcoin payment that the mint will make for the user in exchange",
)
async def melt(payload: PostMeltRequest) -> Union[CashuError, GetMeltResponse]:
    """
    Requests tokens to be destroyed and sent out via Lightning.
    """
    try:
        ok, preimage, change_promises = await ledger.melt(
            payload.proofs, payload.pr, payload.outputs
        )
        resp = GetMeltResponse(paid=ok, preimage=preimage, change=change_promises)
        return resp
    except Exception as exc:
        return CashuError(code=0, error=str(exc))


@router.post(
    "/check",
    name="Check spendable",
    summary="Check whether a proof has already been spent",
)
async def check_spendable(
    payload: CheckSpendableRequest,
) -> CheckSpendableResponse:
    """Check whether a secret has been spent already or not."""
    spendableList = await ledger.check_spendable(payload.proofs)
    return CheckSpendableResponse(spendable=spendableList)


@router.post(
    "/checkfees",
    name="Check fees",
    summary="Check fee reserve for a Lightning payment",
)
async def check_fees(payload: CheckFeesRequest) -> CheckFeesResponse:
    """
    Responds with the fees necessary to pay a Lightning invoice.
    Used by wallets for figuring out the fees they need to supply together with the payment amount.
    This is can be useful for checking whether an invoice is internal (Cashu-to-Cashu).
    """
    fees_sat = await ledger.check_fees(payload.pr)
    return CheckFeesResponse(fee=fees_sat)


@router.post("/split", name="Split", summary="Split proofs at a specified amount")
async def split(
    payload: PostSplitRequest,
) -> Union[CashuError, PostSplitResponse]:
    """
    Requetst a set of tokens with amount "total" to be split into two
    newly minted sets with amount "split" and "total-split".

    This endpoint is used by Alice to split a set of proofs before making a payment to Carol.
    It is then used by Carol (by setting split=total) to redeem the tokens.
    """
    assert payload.outputs, Exception("no outputs provided.")
    try:
        split_return = await ledger.split(
            payload.proofs, payload.amount, payload.outputs
        )
    except Exception as exc:
        return CashuError(code=0, error=str(exc))
    if not split_return:
        return CashuError(code=0, error="there was an error with the split")
    frst_promises, scnd_promises = split_return
    resp = PostSplitResponse(fst=frst_promises, snd=scnd_promises)
    return resp
