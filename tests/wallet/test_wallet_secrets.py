import pytest

from cashu.core.crypto.bls import PrivateKey as BlsPrivateKey
from cashu.wallet.secrets import WalletSecrets


@pytest.mark.asyncio
async def test_nut13_v3_secret_derivation():
    """
    NUT-13 V3 test vector. Source: nuts/tests/13-tests.md "Version 3: Secret derivation".

    The (seed, keyset_id, counter) tuple is chosen so attempt=0 produces x >= BLS_FR_ORDER
    and is rejected; attempt=1 is accepted. Implementations that skip the rejection loop
    will compute a different blinding_factor and fail this vector.
    """

    class MockWalletSecrets(WalletSecrets):
        def __init__(self, seed: bytes):
            self.seed = seed

    seed = b"nut13 v3 test seed"
    ms = MockWalletSecrets(seed)

    keyset_id = "02abd02ebc1ff44652153375162407deaf0b30e590844cca0b6e4894a08a8828dd"
    counter = 3

    secret_bytes, r_bytes, _ = await ms._derive_secret_hmac_sha256_v3(counter, keyset_id)

    assert (
        secret_bytes.hex()
        == "7a45e04943504b25273e9569ab7019ab62f814dade23998c12f5f4cb1bb7978a"
    )

    r = BlsPrivateKey(r_bytes)
    assert (
        r.to_hex()
        == "236dbcb12fc064ceeae6c5e2de7f79258374dccbf23ac0afdf72cf9eb53540c9"
    )

