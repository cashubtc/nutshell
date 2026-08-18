from hashlib import sha256
from time import time
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI

from cashu.core.base import MintQuote, MintQuoteState
from cashu.core.crypto.secp import PrivateKey
from cashu.core.errors import BatchSizeExceededError, CashuError
from cashu.core.models import (
    GetInfoResponse,
    PostMintQuotesByPubkeyRequest,
)
from cashu.core.nuts import nutxx
from cashu.core.nuts.nuts import MINT_QUOTE_LOOKUP_NUT
from cashu.mint import app as app_module
from cashu.mint import router as router_module
from cashu.mint.ledger import Ledger


def lookup_payload(
    mint_pubkey: str, owners: list[PrivateKey]
) -> PostMintQuotesByPubkeyRequest:
    pubkeys = [owner.public_key.format().hex() for owner in owners]
    signatures = [
        owner.sign_schnorr(
            sha256(nutxx.construct_message(mint_pubkey, pubkey)).digest()
        ).hex()
        for owner, pubkey in zip(owners, pubkeys)
    ]
    return PostMintQuotesByPubkeyRequest(pubkeys=pubkeys, pubkey_signatures=signatures)


def test_mint_quote_lookup_message_vector():
    mint = PrivateKey(bytes.fromhex("00" * 31 + "01"))
    owner = PrivateKey(bytes.fromhex("00" * 31 + "02"))

    message = nutxx.construct_message(
        mint.public_key.format().hex(), owner.public_key.format().hex()
    )
    assert message.decode() == (
        "Cashu_MintQuoteLookup_v1"
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    )


def test_mint_info_accepts_provisional_nut_key_without_changing_numeric_keys():
    info = GetInfoResponse(nuts={"4": {"disabled": False}, "XX": {"supported": True}})

    assert info.nuts is not None
    assert 4 in info.nuts
    assert info.nuts[MINT_QUOTE_LOOKUP_NUT] == {"supported": True}


async def store_quote(
    ledger: Ledger,
    *,
    amount: int,
    pubkey: str | None,
    method: str = "bolt11",
) -> MintQuote:
    quote_id = uuid4().hex
    quote = MintQuote(
        quote=quote_id,
        method=method,
        request=f"lnbc-{quote_id}",
        checking_id=quote_id,
        unit="sat",
        amount=amount,
        state=MintQuoteState.unpaid,
        created_time=int(time()),
        pubkey=pubkey,
    )
    await ledger.crud.store_mint_quote(quote=quote, db=ledger.db)
    return quote


def lookup_app(monkeypatch: pytest.MonkeyPatch, ledger: Ledger) -> FastAPI:
    monkeypatch.setattr(router_module, "ledger", ledger)
    app = FastAPI()
    app.middleware("http")(app_module.catch_exceptions)
    app.include_router(router_module.router)
    return app


@pytest.mark.asyncio
async def test_mint_quotes_by_pubkey_returns_only_owned_quotes(ledger: Ledger):
    owner_1 = PrivateKey()
    owner_2 = PrivateKey()
    other_owner = PrivateKey()

    own_quote_1 = await store_quote(
        ledger, amount=10, pubkey=owner_1.public_key.format().hex()
    )
    own_quote_2 = await store_quote(
        ledger, amount=20, pubkey=owner_2.public_key.format().hex()
    )
    await store_quote(ledger, amount=30, pubkey=other_owner.public_key.format().hex())
    await store_quote(ledger, amount=40, pubkey=None)
    await store_quote(
        ledger,
        amount=50,
        pubkey=owner_1.public_key.format().hex(),
        method="custom",
    )

    payload = lookup_payload(ledger.pubkey.format().hex(), [owner_1, owner_2])
    quotes = await ledger.mint_quotes_by_pubkey(payload)

    assert {quote.quote for quote in quotes} == {
        own_quote_1.quote,
        own_quote_2.quote,
    }


@pytest.mark.asyncio
async def test_mint_quotes_by_pubkey_accepts_empty_request(ledger: Ledger):
    quotes = await ledger.mint_quotes_by_pubkey(
        PostMintQuotesByPubkeyRequest(pubkeys=[], pubkey_signatures=[])
    )
    assert quotes == []


@pytest.mark.asyncio
async def test_mint_quotes_by_pubkey_rejects_missing_signature(ledger: Ledger):
    owner = PrivateKey()
    payload = PostMintQuotesByPubkeyRequest(
        pubkeys=[owner.public_key.format().hex()], pubkey_signatures=[]
    )

    with pytest.raises(CashuError, match="signature missing or invalid"):
        await ledger.mint_quotes_by_pubkey(payload)


@pytest.mark.asyncio
async def test_mint_quotes_by_pubkey_rejects_wrong_owner(ledger: Ledger):
    owner = PrivateKey()
    attacker = PrivateKey()
    owner_pubkey = owner.public_key.format().hex()
    attacker_signature = attacker.sign_schnorr(
        sha256(
            nutxx.construct_message(ledger.pubkey.format().hex(), owner_pubkey)
        ).digest()
    ).hex()
    payload = PostMintQuotesByPubkeyRequest(
        pubkeys=[owner_pubkey], pubkey_signatures=[attacker_signature]
    )

    with pytest.raises(CashuError, match="signature missing or invalid"):
        await ledger.mint_quotes_by_pubkey(payload)


@pytest.mark.asyncio
async def test_mint_quotes_by_pubkey_rejects_other_mint_signature(ledger: Ledger):
    owner = PrivateKey()
    other_mint = PrivateKey()
    payload = lookup_payload(other_mint.public_key.format().hex(), [owner])

    with pytest.raises(CashuError, match="signature missing or invalid"):
        await ledger.mint_quotes_by_pubkey(payload)


@pytest.mark.asyncio
async def test_mint_quotes_by_pubkey_rejects_oversized_request(ledger: Ledger):
    owner = PrivateKey()
    pubkey = owner.public_key.format().hex()
    payload = PostMintQuotesByPubkeyRequest.model_construct(
        pubkeys=[pubkey] * (nutxx.MAX_LOOKUP_PUBKEYS + 1),
        pubkey_signatures=[],
    )

    with pytest.raises(BatchSizeExceededError):
        await ledger.mint_quotes_by_pubkey(payload)


def test_mint_info_advertises_mint_quote_lookup(ledger: Ledger):
    assert ledger.mint_info.nuts[MINT_QUOTE_LOOKUP_NUT] == {"supported": True}


@pytest.mark.asyncio
async def test_mint_quote_lookup_api_response_shape(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch
):
    owner = PrivateKey()
    pubkey = owner.public_key.format().hex()
    quote = await store_quote(ledger, amount=50, pubkey=pubkey)

    payload = lookup_payload(ledger.pubkey.format().hex(), [owner])
    transport = httpx.ASGITransport(app=lookup_app(monkeypatch, ledger))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        info_response = await client.get("/v1/info")
        response = await client.post(
            "/v1/mint/quote/bolt11/pubkey", json=payload.model_dump()
        )

    assert info_response.status_code == 200
    assert info_response.json()["nuts"][MINT_QUOTE_LOOKUP_NUT] == {"supported": True}
    assert response.status_code == 200, response.text
    quotes = response.json()["quotes"]
    assert len(quotes) == 1
    assert quotes[0]["quote"] == quote.quote
    assert quotes[0]["method"] == "bolt11"
    assert quotes[0]["pubkey"] == pubkey


@pytest.mark.asyncio
async def test_mint_quote_lookup_api_rejects_unsigned_request(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch
):
    owner = PrivateKey()
    transport = httpx.ASGITransport(app=lookup_app(monkeypatch, ledger))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/mint/quote/bolt11/pubkey",
            json={
                "pubkeys": [owner.public_key.format().hex()],
                "pubkey_signatures": [],
            },
        )

    assert response.status_code == 400
    assert "signature missing or invalid" in response.json()["detail"]
