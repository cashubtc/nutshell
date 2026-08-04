import pytest

from cashu.core.base import DLEQWallet, Proof, WalletKeyset
from cashu.core.crypto import bls_dhke
from cashu.core.crypto.bls import PrivateKey as BlsPrivateKey
from cashu.wallet.secrets import WalletSecrets
from cashu.wallet.wallet import Wallet


@pytest.mark.asyncio
async def test_nut13_v3_secret_derivation():
    """
    Test vector for V3 secret derivation (HMAC-SHA256 with BLS_FR_ORDER reduction) from NUT-13.
    """
    class MockWalletSecrets(WalletSecrets):
        def __init__(self, seed: bytes):
            self.seed = seed
    
    seed = b"nut13 v3 test seed"
    ms = MockWalletSecrets(seed)
    
    keyset_id = "02abd02ebc1ff44652153375162407deaf0b30e590844cca0b6e4894a08a8828dd"
    counter = 3
    
    secret_bytes, r_bytes, _ = await ms._derive_secret_hmac_sha256_v3(counter, keyset_id)

    # Taproot secrets (spec 2.4.2): the 0x00 branch derives the internal key k with the
    # attempt-counter retry; the secret is K = k*G compressed. Pinned by the shared vectors
    # in tests/taproot_v3_vectors.json (nut13_v3, counter 3).
    assert secret_bytes.hex() == "03c687c9ed32e92b1a6301c07e30b433b2c810d0185b3c14f9c2c0851503da0932"

    r = BlsPrivateKey(r_bytes)
    assert r.to_hex() == "236dbcb12fc064ceeae6c5e2de7f79258374dccbf23ac0afdf72cf9eb53540c9"


@pytest.mark.asyncio
async def test_wallet_bls_signature_verification():
    keyset_id = "02abd02ebc1ff44652153375162407deaf0b30e590844cca0b6e4894a08a8828dd"
    amount = 1
    
    priv_key = BlsPrivateKey()
    pub_key = priv_key.get_g2_public_key()
    
    wallet_keyset = WalletKeyset(
        id=keyset_id,
        public_keys={amount: pub_key},
        mint_url="mock-url",
        unit="sat"
    )
    
    class MockWallet(Wallet):
        def __init__(self):
            self.keysets = {keyset_id: wallet_keyset}
            
    wallet = MockWallet()
    
    # v3 keysets take point secrets, and Y hashes the raw 33 bytes.
    secret_msg = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    Y = bls_dhke.hash_to_curve(bytes.fromhex(secret_msg))
    C = Y * priv_key
    
    valid_proof = Proof(
        id=keyset_id,
        amount=amount,
        C=C.serialize().hex(),
        secret=secret_msg,
        dleq=DLEQWallet(e="1", s="1", r="1")
    )
    
    wallet.verify_proofs_dleq([valid_proof])
    
    bad_priv_key = BlsPrivateKey()
    bad_C = Y * bad_priv_key
    
    invalid_proof = Proof(
        id=keyset_id,
        amount=amount,
        C=bad_C.serialize().hex(),
        secret=secret_msg,
        dleq=DLEQWallet(e="1", s="1", r="1")
    )
    
    with pytest.raises(Exception) as exc_info:
        wallet.verify_proofs_dleq([invalid_proof])
        
    assert "BLS pairing verification invalid" in str(exc_info.value) 

