import time
from hashlib import sha256
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from pydantic import ValidationError

from cashu.core.base import MintQuote, MintQuoteState
from cashu.core.crypto.secp import PrivateKey
from cashu.core.errors import BatchSizeExceededError, CashuError
from cashu.core.models import PostMintQuotesByPubkeyRequest
from cashu.core.nuts import nutxx
from cashu.core.nuts.nuts import MINT_QUOTE_PUBKEY_NUT
from cashu.core.settings import settings
from cashu.mint import ledger as ledger_module
from cashu.mint import quote_lookup
from cashu.mint.ledger import Ledger


def signed_payload(ledger, keys, timestamp=None, **kwargs):
    timestamp = int(time.time()) if timestamp is None else timestamp
    pubkeys = [key.public_key.format().hex() for key in keys]
    signatures = [
        key.sign_schnorr(
            sha256(
                nutxx.construct_message(ledger.pubkey.format().hex(), pubkey, timestamp)
            ).digest()
        ).hex()
        for key, pubkey in zip(keys, pubkeys)
    ]
    return PostMintQuotesByPubkeyRequest(
        pubkeys=pubkeys, pubkey_signatures=signatures, timestamp=timestamp, **kwargs
    )


async def store_quote(ledger, quote_id, pubkey, state=MintQuoteState.unpaid, **kwargs):
    quote = MintQuote(
        quote=quote_id,
        method=kwargs.pop("method", "bolt11"),
        request=f"request-{quote_id}",
        checking_id=f"check-{quote_id}",
        unit="sat",
        amount=1,
        pubkey=pubkey,
        state=state,
        expiry=1,
        **kwargs,
    )
    await ledger.crud.store_mint_quote(quote=quote, db=ledger.db)
    return quote


def test_lookup_signature_message():
    assert nutxx.construct_message("mint", "key", 1788825600) == (
        b"Cashu_MintQuoteLookup_v1mintkey1788825600"
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("timestamp", None),
        ("timestamp", -1),
        ("timestamp", 1.5),
        ("timestamp", 1.0),
        ("timestamp", "1"),
        ("timestamp", True),
        ("limit", None),
        ("limit", 0),
        ("limit", -1),
        ("limit", 1.5),
        ("limit", 1.0),
        ("limit", "1"),
        ("limit", True),
        ("cursor", ""),
        ("cursor", 1),
    ],
)
def test_lookup_strict_request_fields(field, value):
    payload = dict(pubkeys=[], pubkey_signatures=[], timestamp=0)
    payload[field] = value
    with pytest.raises(ValidationError):
        PostMintQuotesByPubkeyRequest.model_validate(payload)


def test_lookup_timestamp_required():
    with pytest.raises(ValidationError, match="timestamp"):
        PostMintQuotesByPubkeyRequest(pubkeys=[], pubkey_signatures=[])


@pytest.mark.asyncio
@pytest.mark.parametrize("offset", [-301, -300, 0, 300, 301])
async def test_lookup_timestamp_window(ledger: Ledger, monkeypatch, offset):
    now = 1788825600
    monkeypatch.setattr(ledger_module.time, "time", lambda: now)
    lookup = AsyncMock(return_value=[])
    verify = Mock(wraps=nutxx.verify_signature)
    monkeypatch.setattr(ledger.crud, "get_mint_quotes_by_pubkeys", lookup)
    monkeypatch.setattr(nutxx, "verify_signature", verify)
    payload = signed_payload(ledger, [PrivateKey()], timestamp=now + offset)
    if abs(offset) > 300:
        with pytest.raises(CashuError, match="timestamp.*outside"):
            await ledger.mint_quotes_by_pubkey(payload)
        lookup.assert_not_awaited()
        verify.assert_not_called()
    else:
        assert await ledger.mint_quotes_by_pubkey(payload) == ([], None)
        lookup.assert_awaited_once()
        verify.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure", ["empty", "duplicate", "case_duplicate", "count", "length"]
)
async def test_lookup_invalid_key_sets(ledger: Ledger, monkeypatch, failure):
    keys = [PrivateKey(), PrivateKey(), PrivateKey()]
    payload = signed_payload(ledger, keys)
    if failure == "empty":
        payload = payload.model_copy(update={"pubkeys": [], "pubkey_signatures": []})
    elif failure in {"duplicate", "case_duplicate"}:
        key = payload.pubkeys[0]
        duplicate = key.upper() if failure == "case_duplicate" else key
        payload = payload.model_copy(update={"pubkeys": [key, duplicate]})
    elif failure == "count":
        monkeypatch.setattr(settings, "mint_quote_lookup_max_pubkeys", 2)
    else:
        payload = payload.model_copy(update={"pubkey_signatures": []})
    lookup = AsyncMock()
    verify = Mock(wraps=nutxx.verify_signature)
    monkeypatch.setattr(ledger.crud, "get_mint_quotes_by_pubkeys", lookup)
    monkeypatch.setattr(nutxx, "verify_signature", verify)
    with pytest.raises(CashuError) as exc:
        await ledger.mint_quotes_by_pubkey(payload)
    if failure == "count":
        assert isinstance(exc.value, BatchSizeExceededError)
        assert exc.value.code == 11017
    lookup.assert_not_awaited()
    verify.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure", ["legacy", "timestamp", "mint", "key", "hex", "point"]
)
async def test_lookup_invalid_signatures(ledger: Ledger, monkeypatch, failure):
    keys = [PrivateKey(), PrivateKey()]
    payload = signed_payload(ledger, keys)
    # The first signature remains valid: a later failure must still reject all keys.
    if failure == "legacy":
        message = (
            nutxx.MINT_QUOTE_LOOKUP_DOMAIN
            + ledger.pubkey.format().hex().encode()
            + payload.pubkeys[1].encode()
        )
        payload.pubkey_signatures[1] = (
            keys[1].sign_schnorr(sha256(message).digest()).hex()
        )
    elif failure == "timestamp":
        payload.timestamp += 1
    elif failure == "mint":
        message = nutxx.construct_message(
            PrivateKey().public_key.format().hex(),
            payload.pubkeys[1],
            payload.timestamp,
        )
        payload.pubkey_signatures[1] = (
            keys[1].sign_schnorr(sha256(message).digest()).hex()
        )
    elif failure == "key":
        payload.pubkey_signatures[1] = payload.pubkey_signatures[0]
    elif failure == "hex":
        payload.pubkey_signatures[1] = "zz" * 64
    else:
        payload.pubkeys[1] = "02" + "ff" * 32
    lookup = AsyncMock()
    monkeypatch.setattr(ledger.crud, "get_mint_quotes_by_pubkeys", lookup)
    with pytest.raises(CashuError, match="signature missing or invalid"):
        await ledger.mint_quotes_by_pubkey(payload)
    lookup.assert_not_awaited()


@pytest.mark.asyncio
async def test_lookup_complete_stable_scan(ledger: Ledger, monkeypatch):
    keys = [PrivateKey(), PrivateKey()]
    pubkeys = [key.public_key.format().hex() for key in keys]
    monkeypatch.setattr(settings, "mint_quote_lookup_max_page_size", 2)
    stored = []
    for index, state in enumerate(MintQuoteState):
        stored.append(
            await store_quote(
                ledger,
                f"quote-{index}",
                pubkeys[index % 2],
                state,
                created_time=100 - index,
            )
        )
    await store_quote(ledger, "other-key", PrivateKey().public_key.format().hex())
    await store_quote(ledger, "other-method", pubkeys[0], method="custom")
    await store_quote(ledger, "unlocked", None)

    first = signed_payload(ledger, keys, limit=999)
    page, cursor = await ledger.mint_quotes_by_pubkey(first)
    seen = [quote.quote for quote in page]
    assert seen == ["quote-0", "quote-1"]
    assert cursor
    retry, _ = await ledger.mint_quotes_by_pubkey(first)
    assert [quote.quote for quote in retry] == seen

    # Payment and issuance updates cannot move an already returned quote.
    stored[0].state = MintQuoteState.paid
    stored[0].state = MintQuoteState.pending
    stored[0].state = MintQuoteState.issued
    await ledger.crud.update_mint_quote(quote=stored[0], db=ledger.db)
    page, cursor = await ledger.mint_quotes_by_pubkey(
        signed_payload(
            ledger,
            list(reversed(keys)),
            timestamp=first.timestamp + 1,
            limit=1,
            cursor=cursor,
        )
    )
    seen.extend(quote.quote for quote in page)
    assert [quote.quote for quote in page] == ["quote-2"]
    assert cursor
    # Omitting limit uses the advertised page size. The final short page ends the scan.
    page, cursor = await ledger.mint_quotes_by_pubkey(
        signed_payload(
            ledger,
            keys,
            cursor=cursor,
        )
    )
    seen.extend(quote.quote for quote in page)
    assert [quote.quote for quote in page] == ["quote-3"]
    assert cursor is None
    assert seen == [quote.quote for quote in stored]
    assert len(seen) == len(set(seen))
    assert await ledger.mint_quotes_by_pubkey(
        signed_payload(ledger, [PrivateKey()])
    ) == ([], None)


@pytest.mark.asyncio
async def test_lookup_hex_case_and_cursor_scope(ledger: Ledger):
    key = PrivateKey()
    pubkey = key.public_key.format().hex()
    await store_quote(ledger, "case-0", pubkey.upper())
    await store_quote(ledger, "case-1", pubkey)
    payload = signed_payload(ledger, [key], limit=1)
    payload.pubkeys[0] = pubkey.upper()
    payload.pubkey_signatures[0] = key.sign_schnorr(
        sha256(
            nutxx.construct_message(
                ledger.pubkey.format().hex(),
                pubkey.upper(),
                payload.timestamp,
            )
        ).digest()
    ).hex()
    page, cursor = await ledger.mint_quotes_by_pubkey(payload)
    assert [quote.quote for quote in page] == ["case-0"]
    assert cursor
    page, cursor = await ledger.mint_quotes_by_pubkey(
        signed_payload(ledger, [key], cursor=cursor)
    )
    assert [quote.quote for quote in page] == ["case-1"]
    assert cursor is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "malformed",
        "tampered",
        "keys",
        "method",
        "expired",
        "restart",
        "signature",
        "timestamp",
    ],
)
async def test_lookup_continuation_validation(ledger: Ledger, monkeypatch, failure):
    keys = [PrivateKey()]
    initial = signed_payload(ledger, keys)
    pubkeys = initial.pubkeys
    cursor = ledger.quote_lookup_cursor.encode("bolt11", pubkeys, "quote-0")
    if failure == "malformed":
        cursor = "invalid-cursor"
    elif failure == "tampered":
        cursor = cursor[:-1] + ("0" if cursor[-1] != "0" else "1")
    elif failure == "keys":
        keys = [PrivateKey()]
    elif failure == "method":
        cursor = ledger.quote_lookup_cursor.encode("custom", pubkeys, "quote-0")
    elif failure == "expired":
        monkeypatch.setattr(quote_lookup, "CURSOR_LIFETIME_SECONDS", -1)
        cursor = ledger.quote_lookup_cursor.encode("bolt11", pubkeys, "quote-0")
    elif failure == "restart":
        monkeypatch.setattr(
            ledger, "quote_lookup_cursor", quote_lookup.QuoteLookupCursor()
        )
    payload = signed_payload(ledger, keys, cursor=cursor)
    if failure == "signature":
        payload.pubkey_signatures[0] = "00" * 64
    elif failure == "timestamp":
        payload = signed_payload(
            ledger, keys, timestamp=int(time.time()) - 301, cursor=cursor
        )
    lookup = AsyncMock()
    monkeypatch.setattr(ledger.crud, "get_mint_quotes_by_pubkeys", lookup)
    with pytest.raises(CashuError):
        await ledger.mint_quotes_by_pubkey(payload)
    lookup.assert_not_awaited()


@pytest.mark.asyncio
async def test_lookup_api_pagination_and_limits(ledger: Ledger, monkeypatch):
    from cashu.mint import router
    from cashu.mint.app import app

    monkeypatch.setattr(router, "ledger", ledger)
    monkeypatch.setattr(settings, "mint_quote_lookup_max_pubkeys", 1)
    monkeypatch.setattr(settings, "mint_quote_lookup_max_page_size", 1)
    key = PrivateKey()
    pubkey = key.public_key.format().hex()
    for index in range(2):
        await store_quote(ledger, f"api-quote-{index}", pubkey)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost"
    ) as client:
        response = await client.get("/v1/info")
        assert response.status_code == 200
        info = response.json()
        assert info["pubkey"] == ledger.pubkey.format().hex()
        assert info["nuts"][MINT_QUOTE_PUBKEY_NUT] == {
            "supported": True,
            "max_pubkeys": 1,
            "max_page_size": 1,
        }
        assert ledger.mint_info.supports_nut(MINT_QUOTE_PUBKEY_NUT)
        payload = signed_payload(ledger, [key], limit=999).model_dump(exclude_none=True)
        response = await client.post("/v1/mint/quote/bolt11/pubkey", json=payload)
        assert response.status_code == 200, response.text
        result = response.json()
        assert [quote["quote"] for quote in result["quotes"]] == ["api-quote-0"]
        assert result["quotes"][0]["pubkey"] == pubkey
        assert result["quotes"][0]["amount_paid"] == 0
        assert result["quotes"][0]["amount_issued"] == 0
        assert result["quotes"][0]["method"] == "bolt11"
        assert "updated_at" in result["quotes"][0]
        payload["cursor"] = result["next_cursor"]
        response = await client.post("/v1/mint/quote/bolt11/pubkey", json=payload)
        assert response.status_code == 200, response.text
        assert [quote["quote"] for quote in response.json()["quotes"]] == [
            "api-quote-1"
        ]
        assert response.json()["next_cursor"] is None
        oversized = signed_payload(ledger, [key, PrivateKey()]).model_dump(
            exclude_none=True
        )
        response = await client.post("/v1/mint/quote/bolt11/pubkey", json=oversized)
        assert response.status_code == 400
        assert response.json()["code"] == 11017
        payload["pubkey_signatures"] = ["00" * 64]
        response = await client.post("/v1/mint/quote/bolt11/pubkey", json=payload)
        assert response.status_code == 400
        payload.pop("timestamp")
        response = await client.post("/v1/mint/quote/bolt11/pubkey", json=payload)
        assert response.status_code == 422
        assert "timestamp" in response.text
        payload = signed_payload(ledger, [PrivateKey()]).model_dump(exclude_none=True)
        response = await client.post("/v1/mint/quote/bolt11/pubkey", json=payload)
        assert response.status_code == 200
        assert response.json() == {"quotes": [], "next_cursor": None}
