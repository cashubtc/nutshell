
import pytest
from cashu.core.errors import CashuError
from cashu.core.nuts.nut14 import verify_htlc_spending_conditions
from cashu.core.htlc import HTLCSecret
from cashu.core.base import Proof, HTLCWitness
from ..helpers import assert_err

def test_htlc():    
    proof = Proof.from_dict({
        "amount": 0,
        "secret": "[\"HTLC\",{\"nonce\":\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"data\":\"4884fdaafea47c29fea7159d0daddd9c085d6200e1359e85bb81736af6b7c837\"}]",
        "C": "02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904",
        "id": "009a1f293253e41e",
        "witness": "{\"preimage\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}"
    })

    htlc_preimage = proof.htlcpreimage
    assert htlc_preimage

    verify_htlc_spending_conditions(proof, preimage=htlc_preimage)

def test_htlc_case_insensitive():
    proof = Proof.from_dict({
        "amount": 0,
        "secret": "[\"HTLC\",{\"nonce\":\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"data\":\"4884fdaafea47c29fea7159d0daddd9c085d6200e1359e85bb81736af6b7c837\"}]",
        "C": "02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904",
        "id": "009a1f293253e41e",
        "witness": "{\"preimage\":\"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF\"}"
    })

    htlc_preimage = proof.htlcpreimage
    assert htlc_preimage

    verify_htlc_spending_conditions(proof, preimage=htlc_preimage)


async def test_htlc_preimage_too_large():
    proof = Proof.from_dict({
        "amount": 0,
        "secret": "[\"HTLC\",{\"nonce\":\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"data\":\"c2f480d4dda9f4522b9f6d590011636d904accfe59f12f9d66a0221c2558e3a2\"}]",
        "C": "02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904",
        "id": "009a1f293253e41e",
        "witness": "{\"preimage\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"}"
    })

    htlc_preimage = proof.htlcpreimage
    assert htlc_preimage

    assert_err(verify_htlc_spending_conditions(proof, preimage=htlc_preimage), "HTLC preimage must be 64 characters hex.")

