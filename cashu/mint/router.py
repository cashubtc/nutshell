from typing import Dict, List, Union

from fastapi import APIRouter
from secp256k1 import PublicKey

from cashu.core.base import (
    BlindedSignature,
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
from cashu.mint.startup import ledger

router: APIRouter = APIRouter()


@router.get("/keys")
async def keys() -> dict[int, str]:
    """Get the public keys of the mint"""
    keyset = ledger.get_keyset()
    return keyset


@router.get("/keysets")
async def keysets() -> dict[str, list[str]]:
    """Get all active keysets of the mint"""
    return {"keysets": ledger.keysets.get_ids()}


@router.get("/mint")
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


@router.post("/mint")
async def mint(
    mint_request: MintRequest,
    payment_hash: Union[str, None] = None,
) -> Union[List[BlindedSignature], CashuError]:
    """
    Requests the minting of tokens belonging to a paid payment request.

    Call this endpoint after `GET /mint`.
    """
    try:
        promises = await ledger.mint(
            mint_request.blinded_messages, payment_hash=payment_hash
        )
        return promises
    except Exception as exc:
        return CashuError(error=str(exc))


@router.post("/melt")
async def melt(payload: MeltRequest) -> GetMeltResponse:
    """
    Requests tokens to be destroyed and sent out via Lightning.
    """
    ok, preimage = await ledger.melt(payload.proofs, payload.invoice)
    resp = GetMeltResponse(paid=ok, preimage=preimage)
    return resp


@router.post("/check")
async def check_spendable(payload: CheckRequest) -> Dict[int, bool]:
    """Check whether a secret has been spent already or not."""
    return await ledger.check_spendable(payload.proofs)


@router.post("/checkfees")
async def check_fees(payload: CheckFeesRequest) -> CheckFeesResponse:
    """
    Responds with the fees necessary to pay a Lightning invoice.
    Used by wallets for figuring out the fees they need to supply.
    This is can be useful for checking whether an invoice is internal (Cashu-to-Cashu).
    """
    fees_msat = await ledger.check_fees(payload.pr)
    return CheckFeesResponse(fee=fees_msat / 1000)


@router.post("/split")
async def split(
    payload: SplitRequest,
) -> Union[CashuError, PostSplitResponse]:
    """
    Requetst a set of tokens with amount "total" to be split into two
    newly minted sets with amount "split" and "total-split".
    """
    proofs = payload.proofs
    amount = payload.amount
    outputs = payload.outputs.blinded_messages if payload.outputs else None
    # backwards compatibility with clients < v0.2.2
    assert outputs, Exception("no outputs provided.")
    try:
        split_return = await ledger.split(proofs, amount, outputs)
    except Exception as exc:
        return CashuError(error=str(exc))
    if not split_return:
        return CashuError(error="there was an error with the split")
    frst_promises, scnd_promises = split_return
    resp = PostSplitResponse(fst=frst_promises, snd=scnd_promises)
    return resp
