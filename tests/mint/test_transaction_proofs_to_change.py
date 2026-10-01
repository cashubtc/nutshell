import json

import pytest
import pytest_asyncio

from cashu.core.crypto.nutroot import (
    is_nutroot_point_secret,
    keyset_id_transcript_bytes,
    proof_transcript_y,
)
from cashu.core.crypto.transcript import (
    TransactionShape,
    TranscriptProofInput,
    transaction_inputs,
)
from cashu.core.models import PostTransactionRequest
from cashu.core.nuts import nut20
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT


@pytest_asyncio.fixture(scope="function")
async def wallet1(ledger: Ledger):
    # No use_v2_keyset() here, unlike test_mint_operations.py's wallet1 --
    # we need v3 point-secrets to sign nutroot witnesses.
    wallet1 = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet_transaction_change",
        name="wallet_transaction_change",
    )
    await wallet1.load_mint()
    yield wallet1


def sign_proofs_for_change(wallet: Wallet, proofs, change_pubkey: bytes):
    """Sign each proof's nutroot witness for a transaction with no outputs
    and no melt quote, only a change_pubkey. Wallet._attach_nutroot_witnesses
    doesn't support this shape (it has no change_pubkey parameter), so this
    mirrors its logic directly.
    """
    ys = {p.secret: proof_transcript_y(p.secret, p.id) for p in proofs}
    shape = TransactionShape(
        proof_inputs=[
            TranscriptProofInput(
                amount=p.amount,
                keyset_id=keyset_id_transcript_bytes(p.id),
                Y=ys[p.secret],
                C=bytes.fromhex(p.C),
            )
            for p in proofs
        ],
        change_pubkey=change_pubkey,
    )
    _, proof_contexts, _ = transaction_inputs(shape)
    for proof in proofs:
        secret_key = wallet._resolve_v3_secret_key(proof)
        assert secret_key is not None
        digest = proof_contexts[ys[proof.secret]].digest
        signature = secret_key.sign_schnorr(digest, None)
        proof.witness = json.dumps({"signatures": [signature.hex()]})
    return proofs


@pytest.mark.asyncio
async def test_transaction_proofs_only_to_change_quote(wallet1: Wallet, ledger: Ledger):
    """Proofs in, a change quote out -- no blinded outputs, no melt quote.

    The spec's own transcript vectors (`proof_to_change` in nuts#445) cover
    this shape, but it isn't exercised anywhere in the integration suite:
    test_mint_transaction.py and test_transaction_regressions.py only pair
    change_pubkey with a mint-quote input or a melt quote.
    """
    mint_quote = await wallet1.request_mint(8)
    await wallet1.mint(8, quote_id=mint_quote.quote)
    assert wallet1.balance == 8

    proofs = wallet1.proofs
    assert all(is_nutroot_point_secret(p.secret, p.id) for p in proofs)

    _, change_pubkey = nut20.generate_keypair()
    proofs = sign_proofs_for_change(wallet1, proofs, bytes.fromhex(change_pubkey))

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

    # Resending the same transaction should return the existing record,
    # not attempt to spend the (already spent) proofs again.
    again = await ledger.transaction(
        PostTransactionRequest(proof_inputs=proofs, change_pubkey=change_pubkey)
    )
    assert again.digest == result.digest
    assert again.change_quote.quote == result.change_quote.quote
