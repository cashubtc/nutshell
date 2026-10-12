import asyncio
import json

import pytest
import pytest_asyncio
from pydantic import ValidationError

from cashu.core.crypto.nutroot import is_nutroot_point_secret
from cashu.core.crypto.transcript import (
    TransactionShape,
    TranscriptQuote,
    derived_quote_id,
)
from cashu.core.errors import TransactionError
from cashu.core.json_rpc.base import JSONRPCSubscriptionKinds
from cashu.core.models import (
    PostTransactionRequest,
    TransactionChangeOutput,
    TransactionQuoteInput,
)
from cashu.core.nuts import nut20
from cashu.core.nuts.nuts import WEBSOCKETS_NUT
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import is_fake, pay_if_regtest
from tests.mint.test_mint_transaction import (
    change_output,
    locked_quote,
    quote_witness,
    transcript_change,
)
from tests.mint.test_mint_websocket_protocol import FakeWebSocket


@pytest_asyncio.fixture(scope="function")
async def wallet1(ledger: Ledger):
    # stays on the v3 keyset: the inputs must be point secrets to sign
    wallet1 = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet_transaction_change",
        name="wallet_transaction_change",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest.mark.asyncio
async def test_transaction_proofs_only_to_change_quote(wallet1: Wallet, ledger: Ledger):
    """Proofs in, a change quote out: no blinded outputs and no melt quote
    (the proof_to_change transcript vector)."""
    mint_quote = await wallet1.request_mint(8)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(8, quote_id=mint_quote.quote)
    assert wallet1.balance == 8

    proofs = wallet1.proofs
    assert all(is_nutroot_point_secret(p.secret, p.id) for p in proofs)

    _, change_pubkey = nut20.generate_keypair()
    change_outputs = [change_output(change_pubkey)]
    proofs = wallet1._attach_nutroot_witnesses(
        proofs, [], change_quote_outputs=change_outputs
    )

    result = await ledger.transaction(
        PostTransactionRequest(proof_inputs=proofs, change_quote_outputs=change_outputs)
    )

    assert result.state == "PAID"
    assert result.signatures == []
    assert result.melt_quotes == []
    (change_quote,) = result.change_quotes
    assert change_quote is not None
    assert change_quote.method == "change"
    assert change_quote.amount == sum(p.amount for p in proofs)
    assert change_quote.pubkey == change_pubkey
    assert change_quote.quote == change_outputs[0].quote_id
    assert change_outputs[0].id_preimage not in result.model_dump_json()
    fetched = await ledger.get_mint_quote(change_quote.quote)
    assert change_outputs[0].id_preimage not in fetched.model_dump_json()


@pytest.mark.asyncio
async def test_transaction_proofs_to_fixed_and_remainder_quotes(
    wallet1: Wallet, ledger: Ledger
):
    """A 3-sat change quote plus a remainder quote, in request order
    (the proof_to_two_changes transcript vector)."""
    mint_quote = await wallet1.request_mint(8)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(8, quote_id=mint_quote.quote)
    proofs = wallet1.proofs

    _, fixed_pubkey = nut20.generate_keypair()
    _, remainder_pubkey = nut20.generate_keypair()
    change_outputs = [
        change_output(fixed_pubkey, amount=3),
        change_output(remainder_pubkey),
    ]
    proofs = wallet1._attach_nutroot_witnesses(
        proofs, [], change_quote_outputs=change_outputs
    )
    result = await ledger.transaction(
        PostTransactionRequest(proof_inputs=proofs, change_quote_outputs=change_outputs)
    )
    assert result.state == "PAID"
    fixed, remainder = result.change_quotes
    assert fixed is not None and remainder is not None
    assert (fixed.amount, fixed.pubkey) == (3, fixed_pubkey)
    assert (remainder.amount, remainder.pubkey) == (
        sum(p.amount for p in proofs) - 3,
        remainder_pubkey,
    )
    assert [fixed.quote, remainder.quote] == [c.quote_id for c in change_outputs]


async def _funded(wallet: Wallet, amount: int):
    mint_quote = await wallet.request_mint(amount)
    await pay_if_regtest(mint_quote.request)
    return await wallet.mint(amount, quote_id=mint_quote.quote)


async def _to_change(ledger: Ledger, wallet: Wallet, proofs, change_outputs):
    return await ledger.transaction(
        PostTransactionRequest(
            proof_inputs=wallet._attach_nutroot_witnesses(
                proofs, [], change_quote_outputs=change_outputs
            ),
            change_quote_outputs=change_outputs,
        )
    )


@pytest.mark.asyncio
async def test_change_quote_ids_are_single_use_and_lock_keys_repeat(
    wallet1: Wallet, ledger: Ledger, monkeypatch
):
    proofs = await _funded(wallet1, 8)
    _, change_pubkey = nut20.generate_keypair()
    first = change_output(change_pubkey, amount=3)

    # The same id from two spellings of one preimage.
    upper = first.id_preimage.upper()
    repeated = [first, TransactionChangeOutput(id_preimage=upper, pubkey=change_pubkey)]
    with pytest.raises(TransactionError, match="repeats a change quote id"):
        await _to_change(ledger, wallet1, proofs, repeated)

    same_key = [first, change_output(change_pubkey)]
    result = await _to_change(ledger, wallet1, proofs, same_key)
    assert result.state == "PAID"
    assert [q.pubkey for q in result.change_quotes if q] == [change_pubkey] * 2

    fresh = await _funded(wallet1, 4)
    other = change_output(change_pubkey)
    events = []
    submit = ledger.events.submit

    async def record(event):
        events.append(event)
        await submit(event)

    monkeypatch.setattr(ledger.events, "submit", record)
    with pytest.raises(TransactionError, match="change quote id already claimed"):
        await _to_change(ledger, wallet1, fresh, [other, first])
    # A refused transaction takes none of its ids and reserves none of its inputs.
    rows = await ledger.db.fetchall("SELECT quote_id FROM mint_quote_id_claims")
    assert other.quote_id not in [r["quote_id"] for r in rows]
    assert events == []


@pytest.mark.asyncio
async def test_zero_change_remainder_id_is_claimed(wallet1: Wallet, ledger: Ledger):
    proofs = await _funded(wallet1, 8)
    total = sum(p.amount for p in proofs) - ledger.get_fees_for_proofs(proofs)
    remainder = change_output(nut20.generate_keypair()[1])
    result = await _to_change(
        ledger,
        wallet1,
        proofs,
        [change_output(nut20.generate_keypair()[1], total), remainder],
    )
    assert result.state == "PAID" and result.change_quotes[1] is None
    with pytest.raises(Exception, match="quote not found"):
        await ledger.get_mint_quote(remainder.quote_id)

    fresh = await _funded(wallet1, 4)
    with pytest.raises(TransactionError, match="change quote id already claimed"):
        await _to_change(ledger, wallet1, fresh, [remainder])


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="fake backend pays the quotes")
async def test_concurrent_transactions_naming_one_id(ledger: Ledger):
    """Ids are claimed at acceptance, so of two concurrent transactions naming one id, one runs."""
    shared = change_output(nut20.generate_keypair()[1])

    async def quote_to_change():
        quote, key = await locked_quote(ledger, 8)
        shape = TransactionShape(
            mint_quote_inputs=[
                TranscriptQuote(amount=8, quote_id=quote.quote, pubkey=bytes.fromhex(quote.pubkey))
            ],
            change_quote_outputs=[transcript_change(shared)],
        )
        request = PostTransactionRequest(
            mint_quote_inputs=[
                TransactionQuoteInput(
                    quote=quote.quote, amount=8, witness=quote_witness(key, shape, quote.quote)
                )
            ],
            change_quote_outputs=[shared],
        )
        return quote, request

    (quote_a, request_a), (quote_b, request_b) = (
        await quote_to_change(),
        await quote_to_change(),
    )
    results = await asyncio.gather(
        ledger.transaction(request_a), ledger.transaction(request_b), return_exceptions=True
    )
    errors = [str(r) for r in results if isinstance(r, Exception)]
    assert errors == ["change quote id already claimed."]
    assert [r.state for r in results if not isinstance(r, Exception)] == ["PAID"]
    assert (await ledger.get_mint_quote(shared.quote_id)).amount == 8
    loser = quote_b if isinstance(results[1], Exception) else quote_a
    released = await ledger.get_mint_quote(loser.quote)
    assert released.paid and released.mintable == 8


@pytest.mark.asyncio
async def test_change_mint_quote_subscription_before_the_quote_exists(
    wallet1: Wallet, ledger: Ledger
):
    proofs = await _funded(wallet1, 8)
    change = change_output(nut20.generate_keypair()[1])
    websocket = FakeWebSocket()
    client = ledger.events.add_client(websocket, ledger.db, ledger.crud)  # type: ignore
    try:
        client.add_subscription(
            JSONRPCSubscriptionKinds.CHANGE_MINT_QUOTE, [change.quote_id], "sub-1"
        )
        await asyncio.sleep(0.1)
        assert websocket.sent == []  # no quote yet, so no initial state

        await _to_change(ledger, wallet1, proofs, [change])
        await asyncio.sleep(0.1)
        (message,) = [json.loads(m) for m in websocket.sent]
        payload = message["params"]["payload"]
        assert message["params"]["subId"] == "sub-1"
        assert (payload["quote"], payload["state"]) == (change.quote_id, "PAID")
        assert change.id_preimage not in websocket.sent[0]
    finally:
        ledger.events.remove_client(client)


def test_change_mint_quote_is_advertised(ledger: Ledger):
    entries = ledger.mint_features[WEBSOCKETS_NUT]["supported"]
    assert {"method": "change", "unit": "sat", "commands": ["change_mint_quote"]} in entries


@pytest.mark.asyncio
async def test_transaction_rejects_two_remainder_quotes(
    wallet1: Wallet, ledger: Ledger
):
    mint_quote = await wallet1.request_mint(8)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(8, quote_id=mint_quote.quote)
    change_outputs = [
        change_output(nut20.generate_keypair()[1]),
        change_output(nut20.generate_keypair()[1]),
    ]
    with pytest.raises(TransactionError, match="at most one change quote output"):
        await ledger.transaction(
            PostTransactionRequest(
                proof_inputs=wallet1.proofs, change_quote_outputs=change_outputs
            )
        )
    # A fixed amount must be positive.
    with pytest.raises(ValidationError):
        change_output(change_outputs[0].pubkey, amount=0)


@pytest.mark.parametrize(
    "id_preimage", ["", "00" * 31, "00" * 33, "zz" * 32, " " + "0" * 63, "0" * 63 + "\n"]
)
def test_change_output_id_preimage_is_32_byte_hex(id_preimage):
    with pytest.raises(ValidationError):
        TransactionChangeOutput(id_preimage=id_preimage, pubkey="02" + "11" * 32)


def test_change_output_quote_id_derives_from_preimage():
    preimage = "2caf99f5aef46b625beb02484fc76b467cd9c025c68ce8af02b70b65b6d21f1d"
    c = TransactionChangeOutput(id_preimage=preimage, pubkey="02" + "11" * 32)
    assert c.quote_id == derived_quote_id(bytes.fromhex(preimage))
