import pytest
import pytest_asyncio
from pydantic import ValidationError

from cashu.core.crypto.nutroot import is_nutroot_point_secret
from cashu.core.errors import TransactionError
from cashu.core.models import PostTransactionRequest, TransactionChangeOutput
from cashu.core.nuts import nut20
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT


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
    await wallet1.mint(8, quote_id=mint_quote.quote)
    assert wallet1.balance == 8

    proofs = wallet1.proofs
    assert all(is_nutroot_point_secret(p.secret, p.id) for p in proofs)

    _, change_pubkey = nut20.generate_keypair()
    change_outputs = [TransactionChangeOutput(pubkey=change_pubkey)]
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

    # resubmitting returns the existing record rather than spending again
    again = await ledger.transaction(
        PostTransactionRequest(proof_inputs=proofs, change_quote_outputs=change_outputs)
    )
    assert again.digest == result.digest
    assert again.change_quotes[0].quote == change_quote.quote


@pytest.mark.asyncio
async def test_transaction_proofs_to_fixed_and_remainder_quotes(
    wallet1: Wallet, ledger: Ledger
):
    """A 3-sat change quote plus a remainder quote, in request order
    (the proof_to_two_change transcript vector)."""
    mint_quote = await wallet1.request_mint(8)
    await wallet1.mint(8, quote_id=mint_quote.quote)
    proofs = wallet1.proofs

    _, fixed_pubkey = nut20.generate_keypair()
    _, remainder_pubkey = nut20.generate_keypair()
    change_outputs = [
        TransactionChangeOutput(pubkey=fixed_pubkey, amount=3),
        TransactionChangeOutput(pubkey=remainder_pubkey),
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
    assert fixed.quote != remainder.quote
    fetched = await ledger.get_transaction(result.digest)
    assert [q.quote for q in fetched.change_quotes] == [fixed.quote, remainder.quote]


@pytest.mark.asyncio
async def test_transaction_rejects_two_remainder_quotes(
    wallet1: Wallet, ledger: Ledger
):
    mint_quote = await wallet1.request_mint(8)
    await wallet1.mint(8, quote_id=mint_quote.quote)
    change_outputs = [
        TransactionChangeOutput(pubkey=nut20.generate_keypair()[1]),
        TransactionChangeOutput(pubkey=nut20.generate_keypair()[1]),
    ]
    with pytest.raises(TransactionError, match="at most one change quote output"):
        await ledger.transaction(
            PostTransactionRequest(
                proof_inputs=wallet1.proofs, change_quote_outputs=change_outputs
            )
        )
    # A fixed amount must be positive.
    with pytest.raises(ValidationError):
        TransactionChangeOutput(pubkey=change_outputs[0].pubkey, amount=0)
