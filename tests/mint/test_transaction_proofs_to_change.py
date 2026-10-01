import pytest
import pytest_asyncio

from cashu.core.crypto.nutroot import is_nutroot_point_secret
from cashu.core.models import PostTransactionRequest
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
    proofs = wallet1._attach_nutroot_witnesses(proofs, [], change_pubkey=change_pubkey)

    result = await ledger.transaction(
        PostTransactionRequest(proof_inputs=proofs, change_pubkey=change_pubkey)
    )

    assert result.state == "PAID"
    assert result.signatures == []
    assert result.melt_quotes == []
    assert result.change_quote is not None
    assert result.change_quote.method == "change"
    assert result.change_quote.amount == sum(p.amount for p in proofs)
    assert result.change_quote.pubkey == change_pubkey

    # resubmitting returns the existing record rather than spending again
    again = await ledger.transaction(
        PostTransactionRequest(proof_inputs=proofs, change_pubkey=change_pubkey)
    )
    assert again.digest == result.digest
    assert again.change_quote.quote == result.change_quote.quote
