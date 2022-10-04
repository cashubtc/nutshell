from typing import Union

from fastapi import APIRouter
from secp256k1 import PublicKey

from cashu.core.base import (CheckPayload, MeltPayload, MintPayloads,
                             SplitPayload)
from cashu.mint import ledger

router: APIRouter = APIRouter()


@router.get("/keys")
def keys():
    """Get the public keys of the mint"""
    return ledger.get_pubkeys()


@router.get("/mint")
async def request_mint(amount: int = 0):
    """Request minting of tokens. Server responds with a Lightning invoice."""
    payment_request, payment_hash = await ledger.request_mint(amount)
    print(f"Lightning invoice: {payment_request}")
    return {"pr": payment_request, "hash": payment_hash}


@router.post("/mint")
async def mint(payloads: MintPayloads, payment_hash: Union[str, None] = None):
    """
    Requests the minting of tokens belonging to a paid payment request.

    Parameters:
    pr: payment_request of the Lightning paid invoice.

    Body (JSON):
    payloads: contains a list of blinded messages waiting to be signed.

    NOTE:
    - This needs to be replaced by the preimage otherwise someone knowing
        the payment_request can request the tokens instead of the rightful
        owner.
    - The blinded message should ideally be provided to the server *before* payment
        in the GET /mint endpoint so that the server knows to sign only these tokens
        when the invoice is paid.
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
        return {"error": str(exc)}


@router.post("/melt")
async def melt(payload: MeltPayload):
    """
    Requests tokens to be destroyed and sent out via Lightning.
    """
    ok, preimage = await ledger.melt(payload.proofs, payload.amount, payload.invoice)
    return {"paid": ok, "preimage": preimage}


@router.post("/check")
async def check_spendable(payload: CheckPayload):
    return await ledger.check_spendable(payload.proofs)


@router.post("/split")
async def split(payload: SplitPayload):
    """
    Requetst a set of tokens with amount "total" to be split into two
    newly minted sets with amount "split" and "total-split".
    """
    proofs = payload.proofs
    amount = payload.amount
    output_data = payload.output_data.blinded_messages
    try:
        split_return = await ledger.split(proofs, amount, output_data)
    except Exception as exc:
        return {"error": str(exc)}
    if not split_return:
        return {"error": "there was a problem with the split."}
    fst_promises, snd_promises = split_return
    return {"fst": fst_promises, "snd": snd_promises}
