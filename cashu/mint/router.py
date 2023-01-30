from typing import Dict, List, Union

from fastapi import APIRouter
from secp256k1 import PublicKey

from cashu.core.base import (
    BlindedMessage,
    BlindedSignature,
    CheckFeesRequest,
    CheckFeesResponse,
    CheckSpendableRequest,
    CheckSpendableResponse,
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
from cashu.core.errors import CashuError
from cashu.mint.startup import ledger

router: APIRouter = APIRouter()


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
async def keyset_keys(idBase64Urlsafe: str) -> KeysResponse:
    """
    Get the public keys of the mint from a specific keyset id.
    The id is encoded in idBase64Urlsafe (by a wallet) and is converted back to
    normal base64 before it can be processed (by the mint).
    """
    id = idBase64Urlsafe.replace("-", "+").replace("_", "/")
    keyset = ledger.get_keyset(keyset_id=id)
    keys = KeysResponse.parse_obj(keyset)
    return keys


@router.get(
    "/keysets", name="Active keysets", summary="Get all active keyset id of the mind"
)
async def keysets() -> KeysetsResponse:
    """This endpoint returns a list of keysets that the mint currently supports and will accept tokens from."""
    keysets = KeysetsResponse(keysets=ledger.keysets.get_ids())
    return keysets


@router.get("/mint", name="Request mint", summary="Request minting of new tokens")
async def request_mint(amount: int = 0) -> GetMintResponse:
    """
    Request minting of new tokens. The mint responds with a Lightning invoice.
    This endpoint can be used for a Lightning invoice UX flow.

    Call `POST /mint` after paying the invoice.
    """
    payment_request, payment_hash = await ledger.request_mint(amount)
    print(f"Lightning invoice: {payment_request}")
    resp = GetMintResponse(pr=payment_request, hash=payment_hash)
    return resp


@router.post(
    "/mint",
    name="Mint tokens",
    summary="Mint tokens in exchange for a Bitcoin paymemt that the user has made",
)
async def mint(
    payload: PostMintRequest,
    payment_hash: Union[str, None] = None,
) -> Union[PostMintResponse, CashuError]:
    """
    Requests the minting of tokens belonging to a paid payment request.

    Call this endpoint after `GET /mint`.
    """
    try:
        promises = await ledger.mint(payload.outputs, payment_hash=payment_hash)
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
        ok, preimage = await ledger.melt(payload.proofs, payload.pr)
        resp = GetMeltResponse(paid=ok, preimage=preimage)
    except Exception as exc:
        return CashuError(code=0, error=str(exc))
    return resp


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
    fees_msat = await ledger.check_fees(payload.pr)
    return CheckFeesResponse(fee=fees_msat // 1000)


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
