from typing import Union

from fastapi import APIRouter
from secp256k1 import PublicKey

from cashu.core.base import (
    CheckFeesRequest,
    CheckFeesResponse,
    CheckRequest,
    GetMeltResponse,
    GetMintResponse,
    MeltRequest,
    MintRequest,
    PostSplitResponse,
    SplitRequest,
)
from cashu.core.errors import CashuError
from cashu.mint import ledger

router: APIRouter = APIRouter()


@router.get("/keys")
def keys():
    """Get the public keys of the mint"""
    return ledger.get_keyset()


@router.get("/keysets")
def keysets():
    """Get all active keysets of the mint"""
    return {"keysets": ledger.keysets.get_ids()}


@router.get("/mint")
async def request_mint(amount: int = 0):
    """
    Request minting of new tokens. The mint responds with a Lightning invoice.
    This endpoint can be used for a Lightning invoice UX flow.

    Call `POST /mint` after paying the invoice.
    """
    payment_request, payment_hash = await ledger.request_mint(amount)
    print(f"Lightning invoice: {payment_request}")
    resp = GetMintResponse(pr=payment_request, hash=payment_hash)
    return resp


@router.post("/mint")
async def mint(
    payloads: MintRequest,
    bolt11: Union[str, None] = None,
    payment_hash: Union[str, None] = None,
):
    """
    Requests the minting of tokens belonging to a paid payment request.

    Call this endpoint after `GET /mint`.
    """
    amounts = []
    B_s = []
    for payload in payloads.blinded_messages:
        amounts.append(payload.amount)
        B_s.append(PublicKey(bytes.fromhex(payload.B_), raw=True))
    try:
        promises = await ledger.mint(B_s, amounts, payment_hash=payment_hash)
        return promises
    except Exception as exc:
        return CashuError(error=str(exc))


@router.post("/melt")
async def melt(payload: MeltRequest):
    """
    Requests tokens to be destroyed and sent out via Lightning.
    """
    ok, preimage = await ledger.melt(payload.proofs, payload.invoice)
    resp = GetMeltResponse(paid=ok, preimage=preimage)
    return resp


@router.post("/check")
async def check_spendable(payload: CheckRequest):
    return await ledger.check_spendable(payload.proofs)


@router.post("/checkfees")
async def check_fees(payload: CheckFeesRequest):
    fees_msat = await ledger.check_fees(payload.pr)
    return CheckFeesResponse(fee=fees_msat / 1000)


@router.post("/split")
async def split(payload: SplitRequest):
    """
    Requetst a set of tokens with amount "total" to be split into two
    newly minted sets with amount "split" and "total-split".
    """
    proofs = payload.proofs
    amount = payload.amount
    outputs = payload.outputs.blinded_messages if payload.outputs else None
    try:
        split_return = await ledger.split(proofs, amount, outputs)
    except Exception as exc:
        return CashuError(error=str(exc))
    if not split_return:
        return {"error": "there was a problem with the split."}
    frst_promises, scnd_promises = split_return
    resp = PostSplitResponse(fst=frst_promises, snd=scnd_promises)
    return resp
