import pytest

from cashu.core.base import MintKeyset
from cashu.core.settings import settings
from tests.test_mint_init import DECRYPTON_KEY, DERIVATION_PATH, ENCRYPTED_SEED, SEED


async def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        if msg not in str(exc.args[0]):
            raise Exception(f"Expected error: {msg}, got: {exc.args[0]}")
        return
    raise Exception(f"Expected error: {msg}, got no error")


@pytest.mark.asyncio
async def test_keyset_0_15_0():
    keyset = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.15.0")
    assert len(keyset.public_keys_hex) == settings.max_order
    assert keyset.seed == "TEST_PRIVATE_KEY"
    assert keyset.derivation_path == "m/0'/0'/0'"
    assert (
        keyset.public_keys_hex[1]
        == "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
    )
    assert keyset.id == "009a1f293253e41e"


@pytest.mark.asyncio
async def test_keyset_0_14_0():
    keyset = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.14.0")
    assert len(keyset.public_keys_hex) == settings.max_order
    assert keyset.seed == "TEST_PRIVATE_KEY"
    assert keyset.derivation_path == "m/0'/0'/0'"
    assert (
        keyset.public_keys_hex[1]
        == "036d6f3adf897e88e16ece3bffb2ce57a0b635fa76f2e46dbe7c636a937cd3c2f2"
    )
    assert keyset.id == "xnI+Y0j7cT1/"


@pytest.mark.asyncio
async def test_keyset_0_11_0():
    keyset = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.11.0")
    assert len(keyset.public_keys_hex) == settings.max_order
    assert keyset.seed == "TEST_PRIVATE_KEY"
    assert keyset.derivation_path == "m/0'/0'/0'"
    assert (
        keyset.public_keys_hex[1]
        == "026b714529f157d4c3de5a93e3a67618475711889b6434a497ae6ad8ace6682120"
    )
    assert keyset.id == "Zkdws9zWxNc4"


@pytest.mark.asyncio
async def test_keyset_0_15_0_encrypted():
    settings.mint_seed_decryption_key = DECRYPTON_KEY
    keyset = MintKeyset(
        encrypted_seed=ENCRYPTED_SEED,
        derivation_path=DERIVATION_PATH,
        version="0.15.0",
    )
    assert len(keyset.public_keys_hex) == settings.max_order
    assert keyset.seed == "TEST_PRIVATE_KEY"
    assert keyset.derivation_path == "m/0'/0'/0'"
    assert (
        keyset.public_keys_hex[1]
        == "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
    )
    assert keyset.id == "009a1f293253e41e"
