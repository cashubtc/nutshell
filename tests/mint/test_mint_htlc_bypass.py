import time
from hashlib import sha256

import pytest

from cashu.core.crypto.secp import PrivateKey
from cashu.core.errors import TransactionError
from cashu.core.p2pk import schnorr_sign
from cashu.core.secret import SecretKind
from cashu.mint.conditions import LedgerSpendingConditions
from tests.mint.test_mint_conditions import _proof, _secret


def test_htlc_preimage_bypass_after_locktime():
    cond = LedgerSpendingConditions()
    preimage = "11" * 32
    digest = sha256(bytes.fromhex(preimage)).hexdigest()
    
    priv_recv = PrivateKey()
    pk_recv = priv_recv.public_key.format().hex()
    
    priv_send = PrivateKey()
    pk_send = priv_send.public_key.format().hex()
    
    locktime = int(time.time()) - 1000
    tags = [["locktime", str(locktime)], ["pubkeys", pk_recv], ["refund", pk_send], ["sigflag", "SIG_INPUTS"]]
    secret_str = _secret(kind=SecretKind.HTLC, data=digest, extra_tags=tags)
    
    sig_recv = schnorr_sign(secret_str.encode("utf-8"), priv_recv).hex()
    proof = _proof(secret_str, signatures=[sig_recv])
    
    with pytest.raises(TransactionError, match="signature threshold not met"):
        cond._verify_input_spending_conditions(proof)

