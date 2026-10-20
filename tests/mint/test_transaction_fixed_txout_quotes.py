import asyncio
import os

import pytest
import pytest_asyncio
from pydantic import ValidationError

from cashu.core.crypto.nutroot import (
    is_nutroot_point_secret,
    keyset_id_transcript_bytes,
    proof_transcript_y,
)
from cashu.core.crypto.transcript import (
    TransactionShape,
    TranscriptMintQuoteOutput,
    TranscriptProofInput,
    TranscriptQuote,
    derived_quote_id,
    input_bound_quote_id,
)
from cashu.core.errors import TransactionDuplicateOutputsError, TransactionError
from cashu.core.models import (
    PostTransactionRequest,
    TransactionMintQuoteOutput,
    TransactionQuoteInput,
)
from cashu.core.nuts import nut20
from cashu.core.nuts.nuts import SCRIPT_NUT, TRANSACTION_NUT
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import is_fake, pay_if_regtest
from tests.mint.test_mint_transaction import draw, locked_quote, quote_witness


def fixed_output(pubkey: str, amount: int) -> TransactionMintQuoteOutput:
    return TransactionMintQuoteOutput(
        pubkey=pubkey, amount=amount, id_preimage=os.urandom(32).hex()
    )


def transcript_fixed(c: TransactionMintQuoteOutput) -> TranscriptMintQuoteOutput:
    return TranscriptMintQuoteOutput(bytes.fromhex(c.pubkey), c.quote_id, c.amount)


@pytest_asyncio.fixture(scope="function")
async def wallet1(ledger: Ledger):
    # stays on the v3 keyset: the inputs must be point secrets to sign
    wallet1 = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet_transaction_txout",
        name="wallet_transaction_txout",
    )
    await wallet1.load_mint()
    yield wallet1


async def _funded(wallet: Wallet, amount: int):
    mint_quote = await wallet.request_mint(amount)
    await pay_if_regtest(mint_quote.request)
    return await wallet.mint(amount, quote_id=mint_quote.quote)


def _value(ledger: Ledger, proofs) -> int:
    return sum(p.amount for p in proofs) - ledger.get_fees_for_proofs(proofs)


async def _to_txout(ledger: Ledger, wallet: Wallet, proofs, quote_outputs):
    return await ledger.transaction(
        PostTransactionRequest(
            proof_inputs=wallet._attach_nutroot_witnesses(
                proofs, [], mint_quote_outputs=quote_outputs
            ),
            mint_quote_outputs=quote_outputs,
        )
    )


@pytest.mark.asyncio
async def test_proofs_park_in_a_fixed_txout_quote(wallet1: Wallet, ledger: Ledger):
    """Proofs in, one fixed txout quote out: no blinded outputs and no melt quote."""
    proofs = await _funded(wallet1, 8)
    assert all(is_nutroot_point_secret(p.secret, p.id) for p in proofs)
    _, pubkey = nut20.generate_keypair()
    outputs = [fixed_output(pubkey, _value(ledger, proofs))]
    result = await _to_txout(ledger, wallet1, proofs, outputs)

    assert result.state == "PAID"
    assert result.signatures == []
    assert result.melt_quotes == []
    (quote,) = result.mint_quotes
    assert quote is not None
    assert (quote.method, quote.amount, quote.pubkey) == ("txout", outputs[0].amount, pubkey)
    assert quote.quote == outputs[0].quote_id
    assert outputs[0].id_preimage not in result.model_dump_json()
    fetched = await ledger.get_mint_quote(quote.quote)
    assert outputs[0].id_preimage not in fetched.model_dump_json()


@pytest.mark.asyncio
async def test_proofs_to_two_fixed_txout_quotes(wallet1: Wallet, ledger: Ledger):
    """3 sat and the rest, in request order (the proof_to_two_fixed_txouts shape)."""
    proofs = await _funded(wallet1, 8)
    first, second = nut20.generate_keypair()[1], nut20.generate_keypair()[1]
    outputs = [
        fixed_output(first, 3),
        fixed_output(second, _value(ledger, proofs) - 3),
    ]
    result = await _to_txout(ledger, wallet1, proofs, outputs)
    assert result.state == "PAID"
    a, b = result.mint_quotes
    assert a is not None and b is not None
    assert (a.amount, a.pubkey) == (3, first)
    assert (b.amount, b.pubkey) == (outputs[1].amount, second)
    assert [a.quote, b.quote] == [c.quote_id for c in outputs]


@pytest.mark.asyncio
async def test_fixed_txout_quote_without_preimage_takes_an_input_bound_id(
    wallet1: Wallet, ledger: Ledger
):
    """The proof_to_input_bound_txout shape: the second output has no id_preimage."""
    proofs = await _funded(wallet1, 8)
    pubkey = nut20.generate_keypair()[1]
    outputs = [
        fixed_output(nut20.generate_keypair()[1], 3),
        TransactionMintQuoteOutput(pubkey=pubkey, amount=_value(ledger, proofs) - 3),
    ]
    result = await _to_txout(ledger, wallet1, proofs, outputs)
    assert result.state == "PAID"
    fixed, bound = result.mint_quotes
    assert fixed is not None and bound is not None
    assert fixed.quote == outputs[0].quote_id
    inputs = TransactionShape(
        proof_inputs=[
            TranscriptProofInput(
                amount=p.amount,
                keyset_id=keyset_id_transcript_bytes(p.id),
                Y=proof_transcript_y(p.secret, p.id),
                C=bytes.fromhex(p.C),
            )
            for p in proofs
        ]
    )
    assert bound.quote == input_bound_quote_id(inputs, 1)
    fetched = await ledger.get_mint_quote(bound.quote)
    assert (fetched.pubkey, fetched.amount) == (pubkey, bound.amount)


@pytest.mark.asyncio
async def test_fixed_txout_quote_ids_are_single_use_and_lock_keys_repeat(
    wallet1: Wallet, ledger: Ledger, monkeypatch
):
    proofs = await _funded(wallet1, 8)
    _, pubkey = nut20.generate_keypair()
    first = fixed_output(pubkey, 3)

    # The same id from two spellings of one preimage.
    upper = TransactionMintQuoteOutput(
        pubkey=pubkey, amount=1, id_preimage=(first.id_preimage or "").upper()
    )
    with pytest.raises(TransactionDuplicateOutputsError, match="repeats a txout quote id"):
        await _to_txout(ledger, wallet1, proofs, [first, upper])

    same_key = [first, fixed_output(pubkey, _value(ledger, proofs) - 3)]
    result = await _to_txout(ledger, wallet1, proofs, same_key)
    assert result.state == "PAID"
    assert [q.pubkey for q in result.mint_quotes if q] == [pubkey] * 2

    fresh = await _funded(wallet1, 4)
    other = fixed_output(pubkey, 1)
    reuse = TransactionMintQuoteOutput(
        pubkey=pubkey, amount=_value(ledger, fresh) - 1, id_preimage=first.id_preimage
    )
    events = []
    submit = ledger.events.submit

    async def record(event):
        events.append(event)
        await submit(event)

    monkeypatch.setattr(ledger.events, "submit", record)
    with pytest.raises(TransactionDuplicateOutputsError, match="txout quote id already claimed"):
        await _to_txout(ledger, wallet1, fresh, [other, reuse])
    # A refused transaction takes none of its ids and reserves none of its inputs.
    rows = await ledger.db.fetchall("SELECT quote_id FROM mint_quote_id_claims")
    assert other.quote_id not in [r["quote_id"] for r in rows]
    assert events == []


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="fake backend pays the quotes")
async def test_concurrent_transactions_naming_one_id(ledger: Ledger):
    """Ids are claimed at acceptance, so of two concurrent transactions naming one id, one runs."""
    shared = fixed_output(nut20.generate_keypair()[1], 8)

    async def quote_to_txout():
        quote, key = await locked_quote(ledger, 8)
        shape = TransactionShape(
            mint_quote_inputs=[
                TranscriptQuote(amount=8, quote_id=quote.quote, pubkey=bytes.fromhex(quote.pubkey), issued=quote.amount_issued or 0)
            ],
            mint_quote_outputs=[transcript_fixed(shared)],
        )
        request = PostTransactionRequest(
            mint_quote_inputs=[
                TransactionQuoteInput(
                    quote=quote.quote, amount=8, witness=quote_witness(key, shape, quote.quote)
                )
            ],
            mint_quote_outputs=[shared],
        )
        return quote, request

    (quote_a, request_a), (quote_b, request_b) = (
        await quote_to_txout(),
        await quote_to_txout(),
    )
    results = await asyncio.gather(
        ledger.transaction(request_a), ledger.transaction(request_b), return_exceptions=True
    )
    errors = [str(r) for r in results if isinstance(r, Exception)]
    assert errors == ["txout quote id already claimed."]
    assert [r.state for r in results if not isinstance(r, Exception)] == ["PAID"]
    assert (await ledger.get_mint_quote(shared.quote_id or "")).amount == 8
    loser = quote_b if isinstance(results[1], Exception) else quote_a
    released = await ledger.get_mint_quote(loser.quote)
    assert released.paid and released.mintable == 8


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="fake backend pays the quote")
async def test_a_txout_quote_does_not_hop_into_another(ledger: Ledger):
    quote, key = await locked_quote(ledger, 8)
    txout_key, txout_pubkey = nut20.generate_keypair()
    parked = fixed_output(txout_pubkey, 8)
    shape = TransactionShape(
        mint_quote_inputs=[
            TranscriptQuote(amount=8, quote_id=quote.quote, pubkey=bytes.fromhex(quote.pubkey), issued=quote.amount_issued or 0)
        ],
        mint_quote_outputs=[transcript_fixed(parked)],
    )
    await ledger.transaction(
        PostTransactionRequest(
            mint_quote_inputs=[
                TransactionQuoteInput(
                    quote=quote.quote, amount=8, witness=quote_witness(key, shape, quote.quote)
                )
            ],
            mint_quote_outputs=[parked],
        )
    )
    txout = await ledger.get_mint_quote(parked.quote_id or "")
    onward = fixed_output(nut20.generate_keypair()[1], 8)
    with pytest.raises(TransactionError, match="cannot pay into a fixed txout quote"):
        await ledger.transaction(
            PostTransactionRequest(
                mint_quote_inputs=[TransactionQuoteInput(quote=txout.quote, amount=8, witness="{}")],
                mint_quote_outputs=[onward],
            )
        )
    # It redeems in full into proofs instead.
    with pytest.raises(TransactionError, match="drawn only in full"):
        await ledger.transaction(draw(ledger, txout, txout_key, 4))
    assert (await ledger.transaction(draw(ledger, txout, txout_key, 8))).state == "PAID"


def test_fixed_txout_amount_is_required_and_positive():
    pubkey = nut20.generate_keypair()[1]
    with pytest.raises(ValidationError):
        TransactionMintQuoteOutput(pubkey=pubkey)
    with pytest.raises(ValidationError):
        fixed_output(pubkey, 0)


@pytest.mark.parametrize(
    "id_preimage", ["", "00" * 31, "00" * 33, "zz" * 32, " " + "0" * 63, "0" * 63 + "\n"]
)
def test_id_preimage_is_32_byte_hex(id_preimage):
    with pytest.raises(ValidationError):
        TransactionMintQuoteOutput(id_preimage=id_preimage, pubkey="02" + "11" * 32, amount=1)


def test_quote_id_derives_from_preimage():
    preimage = "2caf99f5aef46b625beb02484fc76b467cd9c025c68ce8af02b70b65b6d21f1d"
    c = TransactionMintQuoteOutput(id_preimage=preimage, pubkey="02" + "11" * 32, amount=1)
    assert c.quote_id == derived_quote_id(bytes.fromhex(preimage))


def test_fixed_txout_quotes_are_advertised(ledger: Ledger):
    assert ledger.mint_features[TRANSACTION_NUT]["fixed_txout_quotes"] is True
    assert ledger.mint_features[SCRIPT_NUT]["leaves"] == [
        "0001",
        "0002",
        "0003",
        "0004",
        "0005",
    ]
