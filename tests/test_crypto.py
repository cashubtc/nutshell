from cashu.core.crypto.b_dhke import (
    step1_alice,
    step2_bob,
    step3_alice,
    verify,
    verify_signature,
)
from cashu.core.crypto.bls import PrivateKey


def test_bdhke_flow():
    # 1. Setup Mint Keys
    mint_privkey = PrivateKey()
    mint_pubkey_g2 = mint_privkey.public_key

    # 2. Alice blinds
    secret_msg = "test_message"
    B_, r = step1_alice(secret_msg)

    # 3. Bob signs
    C_, _, _ = step2_bob(B_, mint_privkey)

    # 4. Alice unblinds
    C = step3_alice(C_, r, None) # A is unused

    # 5. Mint verifies
    assert verify(mint_privkey, C, secret_msg)

    # 6. Wallet verifies signature natively via pairing
    assert verify_signature(mint_pubkey_g2, C, secret_msg)
