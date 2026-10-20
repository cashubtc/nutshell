import hashlib
from unittest.mock import AsyncMock

import pytest

from cashu.core.base import BlindedMessage, NutrootOption, Proof, ProofSpentState
from cashu.core.crypto import bls_dhke
from cashu.core.crypto.bls import PublicKey as BlsPublicKey
from cashu.core.crypto.nutroot import NUTROOT_NUMS, NutrootLeaf, serialize_nutroot_leaf
from cashu.core.crypto.secp import PrivateKey
from cashu.core.models import PostMintQuoteRequest
from cashu.core.nutroot import (
    create_nutroot_witness,
    create_requested_nutroot_output,
    resolve_nutroot_ownership,
)
from cashu.core.nuts import nut20
from cashu.core.settings import settings


@pytest.mark.asyncio
@pytest.mark.parametrize("disclosed", [False, True])
async def test_pending_and_spent_states_and_events_preserve_original_witnesses(
    ledger, monkeypatch, disclosed
):
    monkeypatch.setattr(settings, "fakewallet_delay_incoming_payment", 0)
    key = PrivateKey((3).to_bytes(32, "big"))
    leaf = serialize_nutroot_leaf(
        NutrootLeaf(
            type="threshold",
            n=1,
            keys=[key.public_key],
            disclosure=1 if disclosed else None,
        )
    )
    secret, info = create_requested_nutroot_output(
        NutrootOption(k=NUTROOT_NUMS.format().hex(), l=[leaf.hex()])
    )
    blinded, factor = bls_dhke.step1_alice(secret)
    output = BlindedMessage(amount=8, id=ledger.keyset.id, B_=blinded.format().hex())
    quote = await ledger.mint_quote(
        PostMintQuoteRequest(unit="sat", amount=8, pubkey=key.public_key.format().hex())
    )
    signatures = await ledger.mint(
        outputs=[output],
        quote_id=quote.quote,
        signature=nut20.sign_mint_quote_v3(quote.quote, 8, [output], key.to_hex(), 0),
    )
    signature = bls_dhke.step3_alice(
        BlsPublicKey(bytes.fromhex(signatures[0].C_)),
        factor,
        ledger.keyset.public_keys[8],
    )
    proof = Proof(
        id=ledger.keyset.id,
        amount=8,
        secret=secret,
        C=signature.format().hex(),
        spend_info=info,
    )
    digest = hashlib.sha256(b"pending disclosure").digest()
    proof.witness = create_nutroot_witness(
        proof, digest, resolve_nutroot_ownership(proof, [key])
    )
    proof.witness = " \n" + proof.witness + "  "
    proof.digest = digest.hex()
    events = AsyncMock()
    monkeypatch.setattr(ledger.events, "submit", events)
    try:
        await ledger.db_write._verify_spent_proofs_and_set_pending(
            [proof], ledger.keysets
        )
        state = (await ledger.db_read.get_proofs_states([proof.Y]))[0]
        assert state.state == ProofSpentState.pending
        assert state.commitment is None
        assert state.witness == proof.witness
        assert state.input_digest == proof.digest
        assert "commitment" not in state.model_dump()
        assert events.await_args.args[0] == state
        await ledger.db_write.finalize_pending_proofs([proof], ledger.keysets)
        state = (await ledger.db_read.get_proofs_states([proof.Y]))[0]
        assert state.state == ProofSpentState.spent
        assert state.witness == proof.witness
        assert state.input_digest == proof.digest
        assert "commitment" not in state.model_dump()
        assert events.await_args.args[0] == state
    finally:
        if await ledger.db_read._get_proofs_pending([proof.Y]):
            await ledger.db_write._unset_proofs_pending(
                [proof], ledger.keysets, spent=False
            )
