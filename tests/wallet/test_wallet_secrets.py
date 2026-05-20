import pytest

from cashu.core.crypto.bls import PrivateKey as BlsPrivateKey
from cashu.wallet.secrets import WalletSecrets


@pytest.mark.asyncio
async def test_nut13_v3_secret_derivation():
    """
    Test vector for V3 secret derivation (HMAC-SHA256 with BLS_FR_ORDER reduction) from NUT-13.
    """
    class MockWalletSecrets(WalletSecrets):
        def __init__(self, seed: bytes):
            self.seed = seed
    
    seed = b"test seed v3 reduction"
    ms = MockWalletSecrets(seed)
    
    keyset_id = "02ce4c47836fd0e64f37a08254777b7fd0dedb95fc1ddd0acadf5600674c743c5d"
    counter = 2
    
    secret_bytes, r_bytes, _ = await ms._derive_secret_hmac_sha256(counter, keyset_id)
    
    assert secret_bytes.hex() == "4729fe85ab3886ce03259ac658735ff534c9cd41b2b364d202ff497e4ee48809"
    
    r = BlsPrivateKey(r_bytes)
    assert r.to_hex() == "08bb237d625b73022cd50f6fedfb660c6125b676a4819474241c264903259d2f"

