from hashlib import sha256
from unittest.mock import AsyncMock, patch

import pytest

from cashu.core.crypto.secp import PrivateKey
from cashu.core.errors import InvalidProofsError
from cashu.core.p2pk import schnorr_sign
from cashu.core.secret import SecretKind
from cashu.mint.ledger import Ledger
from tests.mint.spending_conditions_test_helpers import proof, secret_str


@pytest.mark.asyncio
async def test_verify_inputs_and_outputs_p2pk_custom_sigflag_fails_without_outputs(
    ledger: Ledger,
):
    kid = next(iter(ledger.keysets.keys()))
    signer = PrivateKey()
    pub = signer.public_key.format().hex()
    raw_secret = secret_str(
        kind=SecretKind.P2PK, data=pub, extra_tags=[["sigflag", "CUSTOM"]]
    )
    sig = schnorr_sign(raw_secret.encode("utf-8"), signer).hex()
    p = proof(raw_secret, signatures=[sig])
    p.id = kid

    with (
        patch.object(ledger, "_verify_proof_bdhke", return_value=True),
        patch.object(
            ledger.db_read, "_verify_proofs_spendable", AsyncMock(return_value=True)
        ),
    ):
        with pytest.raises(InvalidProofsError):
            ledger._verify_input_spending_conditions(p)


@pytest.mark.asyncio
async def test_verify_inputs_and_outputs_htlc_custom_sigflag_fails_without_outputs(
    ledger: Ledger,
):
    kid = next(iter(ledger.keysets.keys()))
    preimage = "22" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    raw_secret = secret_str(
        kind=SecretKind.HTLC, data=digest, extra_tags=[["sigflag", "CUSTOM"]]
    )
    p = proof(raw_secret, htlc_preimage=preimage)
    p.id = kid

    with (
        patch.object(ledger, "_verify_proof_bdhke", return_value=True),
        patch.object(
            ledger.db_read, "_verify_proofs_spendable", AsyncMock(return_value=True)
        ),
    ):
        with pytest.raises(InvalidProofsError):
            ledger._verify_input_spending_conditions(p)
