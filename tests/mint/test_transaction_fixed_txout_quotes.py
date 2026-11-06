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
    input_bound_quote_id,
)
from cashu.core.errors import TransactionError
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
    return TransactionMintQuoteOutput(pubkey=pubkey, amount=amount)


def transcript_fixed(c: TransactionMintQuoteOutput) -> TranscriptMintQuoteOutput:
    return TranscriptMintQuoteOutput(bytes.fromhex(c.pubkey), c.amount)


def _bound_ids(proofs, count: int) -> list[str]:
    """The input-bound ids of a proofs-only transaction's fixed txout quotes."""
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
    return [input_bound_quote_id(inputs, k) for k in range(count)]


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
    assert [quote.quote] == _bound_ids(proofs, 1)


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
    assert [a.quote, b.quote] == _bound_ids(proofs, 2)


@pytest.mark.asyncio
async def test_fixed_txout_quote_ids_are_bound_to_the_inputs_and_position(
    wallet1: Wallet, ledger: Ledger
):
    """The proof_to_input_bound_txout shape, each id bound to the inputs at its position."""
    proofs = await _funded(wallet1, 8)
    pubkey = nut20.generate_keypair()[1]
    outputs = [
        fixed_output(nut20.generate_keypair()[1], 3),
        fixed_output(pubkey, _value(ledger, proofs) - 3),
    ]
    result = await _to_txout(ledger, wallet1, proofs, outputs)
    assert result.state == "PAID"
    first, second = result.mint_quotes
    assert first is not None and second is not None
    assert [first.quote, second.quote] == _bound_ids(proofs, 2)
    fetched = await ledger.get_mint_quote(second.quote)
    assert (fetched.pubkey, fetched.amount) == (pubkey, second.amount)


@pytest.mark.asyncio
async def test_fixed_txout_lock_keys_repeat_under_their_own_ids(
    wallet1: Wallet, ledger: Ledger
):
    proofs = await _funded(wallet1, 8)
    _, pubkey = nut20.generate_keypair()
    same_key = [fixed_output(pubkey, 3), fixed_output(pubkey, _value(ledger, proofs) - 3)]
    result = await _to_txout(ledger, wallet1, proofs, same_key)
    assert result.state == "PAID"
    assert [q.pubkey for q in result.mint_quotes if q] == [pubkey] * 2

    fresh = await _funded(wallet1, 4)
    again = await _to_txout(ledger, wallet1, fresh, [fixed_output(pubkey, _value(ledger, fresh))])
    (quote,) = again.mint_quotes
    assert quote is not None and quote.quote not in [q.quote for q in result.mint_quotes if q]


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
    result = await ledger.transaction(
        PostTransactionRequest(
            mint_quote_inputs=[
                TransactionQuoteInput(
                    quote=quote.quote, amount=8, witness=quote_witness(key, shape, quote.quote)
                )
            ],
            mint_quote_outputs=[parked],
        )
    )
    (created,) = result.mint_quotes
    assert created is not None
    txout = await ledger.get_mint_quote(created.quote)
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


def test_fixed_txout_quotes_are_advertised(ledger: Ledger):
    assert ledger.mint_features[TRANSACTION_NUT]["fixed_txout_quotes"] is True
    assert ledger.mint_features[SCRIPT_NUT]["leaves"] == [
        "0001",
        "0002",
        "0003",
        "0004",
        "0005",
    ]
