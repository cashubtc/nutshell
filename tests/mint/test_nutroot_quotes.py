import asyncio

import pytest

from cashu.core.base import BlindedMessage, MintQuoteState, NutrootOption, Proof
from cashu.core.crypto import b_dhke, bls_dhke
from cashu.core.crypto.keys import is_bls_keyset
from cashu.core.crypto.nutroot import NUTROOT_NUMS, NutrootLeaf, serialize_nutroot_leaf
from cashu.core.crypto.secp import PrivateKey
from cashu.core.errors import QuoteSignatureInvalidError, TransactionError
from cashu.core.models import PostMintBatchRequest, PostMintQuoteRequest
from cashu.core.nutroot import (
    create_nutroot_witness,
    create_requested_nutroot_output,
    resolve_nutroot_ownership,
)
from cashu.core.nuts import nut20
from cashu.core.settings import settings
from tests.helpers import pay_if_regtest


@pytest.fixture(autouse=True)
def immediate_fake_payment(monkeypatch):
    monkeypatch.setattr(settings, "fakewallet_delay_incoming_payment", 0)


def outputs(ledger, amounts, start):
    result = []
    for index, amount in enumerate(amounts, start=start):
        secret = PrivateKey(index.to_bytes(32, "big")).public_key.format().hex()
        blinded, _ = bls_dhke.step1_alice(secret)
        result.append(
            BlindedMessage(
                amount=amount, id=ledger.keyset.id, B_=blinded.format().hex()
            )
        )
    return result


async def quote(ledger, lock):
    result = await ledger.mint_quote(
        PostMintQuoteRequest(
            unit="sat", amount=8, pubkey=lock.public_key.format().hex()
        )
    )
    await pay_if_regtest(result.request)
    return result


@pytest.mark.asyncio
async def test_v3_partial_draws_bind_the_starting_issued_amount(ledger):
    lock = PrivateKey()
    q = await quote(ledger, lock)
    first = outputs(ledger, [4], 100)
    await ledger.mint(
        outputs=first,
        quote_id=q.quote,
        signature=nut20.sign_mint_quote_v3(q.quote, 4, first, lock.to_hex(), 0),
    )
    state = await ledger.get_mint_quote(q.quote)
    assert state.amount_issued == 4
    assert state.state == MintQuoteState.paid
    second = outputs(ledger, [4], 101)
    with pytest.raises(QuoteSignatureInvalidError):
        await ledger.mint(
            outputs=second,
            quote_id=q.quote,
            signature=nut20.sign_mint_quote_v3(q.quote, 4, second, lock.to_hex(), 0),
        )
    assert (await ledger.get_mint_quote(q.quote)).amount_issued == 4
    await ledger.mint(
        outputs=second,
        quote_id=q.quote,
        signature=nut20.sign_mint_quote_v3(q.quote, 4, second, lock.to_hex(), 4),
    )
    final = await ledger.get_mint_quote(q.quote)
    assert final.amount_issued == 8
    assert final.state == MintQuoteState.issued


@pytest.mark.asyncio
async def test_v3_quote_can_mint_using_its_script_path(ledger):
    owner = PrivateKey((3).to_bytes(32, "big"))
    leaf = serialize_nutroot_leaf(
        NutrootLeaf(type="after", n=1, keys=[owner.public_key], time=0)
    )
    lock, info = create_requested_nutroot_output(
        NutrootOption(k=NUTROOT_NUMS.format().hex(), l=[leaf.hex()])
    )
    q = await ledger.mint_quote(PostMintQuoteRequest(unit="sat", amount=8, pubkey=lock))
    await pay_if_regtest(q.request)
    out = outputs(ledger, [8], 150)
    proof = Proof(
        id=ledger.keyset.id, amount=8, secret=lock, C="aa" * 48, spend_info=info
    )
    witness = create_nutroot_witness(
        proof,
        nut20.construct_transaction_message(q.quote, 8, out, lock, 0),
        resolve_nutroot_ownership(proof, [owner]),
    )
    signatures = await ledger.mint(outputs=out, quote_id=q.quote, signature=witness)
    assert len(signatures) == 1
    assert (await ledger.get_mint_quote(q.quote)).amount_issued == 8


@pytest.mark.asyncio
async def test_concurrent_v3_draws_use_one_quote_state(ledger):
    lock = PrivateKey()
    q = await quote(ledger, lock)
    requests = [outputs(ledger, [4], i) for i in (200, 201)]
    results = await asyncio.gather(
        *(
            ledger.mint(
                outputs=out,
                quote_id=q.quote,
                signature=nut20.sign_mint_quote_v3(q.quote, 4, out, lock.to_hex(), 0),
            )
            for out in requests
        ),
        return_exceptions=True,
    )
    assert sum(not isinstance(result, Exception) for result in results) == 1
    assert (await ledger.get_mint_quote(q.quote)).amount_issued == 4


@pytest.mark.asyncio
async def test_batch_partial_draws_update_every_quote_monotonically(ledger):
    locks = [PrivateKey(), PrivateKey()]
    quotes = [await quote(ledger, lock) for lock in locks]
    for issued, start in [(0, 300), (4, 301)]:
        out = outputs(ledger, [8], start)
        transcript_quotes = [(q.quote, 4, q.pubkey, issued) for q in quotes]
        signatures = [
            nut20.sign_mint_quote_batch_v3(
                transcript_quotes, out, lock.to_hex(), q.quote
            )
            for q, lock in zip(quotes, locks)
        ]
        await ledger.mint_batch(
            PostMintBatchRequest(
                quotes=[q.quote for q in quotes],
                quote_amounts=[4, 4],
                outputs=out,
                signatures=signatures,
            )
        )
        for q in quotes:
            assert (await ledger.get_mint_quote(q.quote)).amount_issued == issued + 4


@pytest.mark.asyncio
async def test_quote_balance_is_shared_between_keyset_versions(ledger):
    lock = PrivateKey()
    q = await quote(ledger, lock)
    first = outputs(ledger, [4], 400)
    await ledger.mint(
        outputs=first,
        quote_id=q.quote,
        signature=nut20.sign_mint_quote_v3(q.quote, 4, first, lock.to_hex(), 0),
    )
    legacy_keyset = next(
        keyset
        for keyset in ledger.keysets.values()
        if not is_bls_keyset(keyset.id) and keyset.unit.name == "sat"
    )
    blinded, _ = b_dhke.step1_alice("legacy-quote-draw")
    legacy_output = [
        BlindedMessage(amount=8, id=legacy_keyset.id, B_=blinded.format().hex())
    ]
    with pytest.raises(TransactionError, match="mintable"):
        await ledger.mint(
            outputs=legacy_output,
            quote_id=q.quote,
            signature=nut20.sign_mint_quote(q.quote, legacy_output, lock.to_hex()),
        )
    assert (await ledger.get_mint_quote(q.quote)).amount_issued == 4
    last = outputs(ledger, [4], 401)
    await ledger.mint(
        outputs=last,
        quote_id=q.quote,
        signature=nut20.sign_mint_quote_v3(q.quote, 4, last, lock.to_hex(), 4),
    )
    assert (await ledger.get_mint_quote(q.quote)).amount_issued == 8
