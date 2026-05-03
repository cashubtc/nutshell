from cashu.core.crypto.b_dhke import (
    batch_pairing_verification,
    keyed_verification,
    pairing_verification,
    step1_alice,
    step2_bob,
    step3_alice,
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
    assert keyed_verification(mint_privkey, C, secret_msg)

    # 6. Wallet verifies signature natively via pairing
    assert pairing_verification(mint_pubkey_g2, C, secret_msg)


def test_bdhke_batch_verification():
    # Setup Mint Keys for different amounts
    mint_privkeys = [PrivateKey(), PrivateKey(), PrivateKey()]
    mint_pubkeys_g2 = [k.public_key for k in mint_privkeys]

    messages = ["msg1", "msg2", "msg3"]
    Cs = []
    
    # Generate valid signatures
    for msg, privkey in zip(messages, mint_privkeys):
        B_, r = step1_alice(msg)
        C_, _, _ = step2_bob(B_, privkey)
        C = step3_alice(C_, r, None)
        Cs.append(C)
        
    # Batch verify should pass
    assert batch_pairing_verification(mint_pubkeys_g2, Cs, messages)
    
    # Corrupt one signature (simulate forgery or mint cheating)
    # We corrupt by multiplying the first C by 2
    corrupted_C = Cs[0] * 2
    invalid_Cs = [corrupted_C, Cs[1], Cs[2]]
    
    # Batch verify should fail
    assert not batch_pairing_verification(mint_pubkeys_g2, invalid_Cs, messages)
    
    # Empty batch should pass
    assert batch_pairing_verification([], [], [])
