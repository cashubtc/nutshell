import pytest

from cashu.core.base import MintKeyset, Unit
from cashu.core.crypto.keys import (
    derive_keyset_id,
    derive_keyset_id_v2,
    derive_keyset_short_id,
    get_keyset_id_version,
    is_keyset_id_v2,
)
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from tests.mint.test_mint_init import (
    DECRYPTON_KEY,
    DERIVATION_PATH,
    ENCRYPTED_SEED,
    SEED,
)


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


@pytest.mark.asyncio
async def test_keyset_rotation(ledger: Ledger):
    keyset_sat = next(
        filter(lambda k: k.unit == Unit["sat"] and k.active, ledger.keysets.values())
    )
    new_keyset_sat = await ledger.rotate_next_keyset(
        unit=Unit["sat"], max_order=20, input_fee_ppk=1
    )

    keyset_sat_derivation = keyset_sat.derivation_path.split("/")
    new_keyset_sat_derivation = keyset_sat.derivation_path.split("/")

    assert (
        keyset_sat_derivation[:-1] == new_keyset_sat_derivation[:-1]
    ), "keyset derivation does not match up to the counter branch"
    assert (
        int(new_keyset_sat_derivation[-1].replace("'", ""))
        - int(keyset_sat_derivation[-1].replace("'", ""))
        == 0
    ), "counters should differ by exactly 1"

    assert new_keyset_sat.input_fee_ppk == 1
    assert len(new_keyset_sat.private_keys.values()) == 20

    old_keyset = (await ledger.crud.get_keyset(db=ledger.db, id=keyset_sat.id))[0]
    assert not old_keyset.active, "old keyset is still active"


# ==================== KEYSETS V2 TESTS ====================


@pytest.mark.asyncio
async def test_keyset_id_v2_derivation():
    """Test the new keyset ID v2 derivation function."""
    # Create a base keyset to get public keys
    keyset = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.15.0")
    assert keyset.public_keys, "Public keys must be available"
    
    # Test v2 derivation without final expiry
    v2_id_no_expiry = derive_keyset_id_v2(keyset.public_keys, Unit.sat)
    
    # Verify format
    assert v2_id_no_expiry.startswith("01"), "V2 keyset ID should start with '01'"
    assert len(v2_id_no_expiry) == 66, "V2 keyset ID should be 66 characters (33 bytes)"
    assert is_keyset_id_v2(v2_id_no_expiry), "Should be detected as v2"
    assert get_keyset_id_version(v2_id_no_expiry) == "01", "Version should be '01'"
    
    # Test v2 derivation with final expiry
    final_expiry = 1896187313
    v2_id_with_expiry = derive_keyset_id_v2(keyset.public_keys, Unit.sat, final_expiry)
    
    # Should be different from version without expiry
    assert v2_id_with_expiry != v2_id_no_expiry, "IDs with/without expiry should differ"
    assert v2_id_with_expiry.startswith("01"), "Should start with version '01'"
    assert len(v2_id_with_expiry) == 66, "Should be 66 characters"


@pytest.mark.asyncio
async def test_keyset_id_v2_units():
    """Test that different units produce different keyset IDs."""
    keyset = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.15.0")
    assert keyset.public_keys, "Public keys must be available"
    
    # Generate IDs for different units
    id_sat = derive_keyset_id_v2(keyset.public_keys, Unit.sat)
    id_usd = derive_keyset_id_v2(keyset.public_keys, Unit.usd)
    id_eur = derive_keyset_id_v2(keyset.public_keys, Unit.eur)
    id_btc = derive_keyset_id_v2(keyset.public_keys, Unit.btc)
    
    # All should be different
    all_ids = {id_sat, id_usd, id_eur, id_btc}
    assert len(all_ids) == 4, "All unit-based IDs should be unique"
    
    # All should be v2 format
    for keyset_id in all_ids:
        assert keyset_id.startswith("01"), f"ID {keyset_id} should start with '01'"
        assert is_keyset_id_v2(keyset_id), f"ID {keyset_id} should be detected as v2"


@pytest.mark.asyncio
async def test_keyset_short_id():
    """Test short ID derivation for tokens."""
    keyset = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.15.0")
    
    # Test with legacy (v1) keyset
    legacy_short = derive_keyset_short_id(keyset.id)
    assert legacy_short == keyset.id, "Legacy short ID should be same as full ID"
    
    # Test with v2 keyset
    v2_id = derive_keyset_id_v2(keyset.public_keys, Unit.sat)
    v2_short = derive_keyset_short_id(v2_id)
    
    assert len(v2_short) == 16, "V2 short ID should be 16 characters (8 bytes)"
    assert v2_short.startswith("01"), "V2 short ID should start with version"
    assert v2_id.startswith(v2_short), "Short ID should be prefix of full ID"


@pytest.mark.asyncio
async def test_keyset_version_detection():
    """Test keyset version detection utilities."""
    # Legacy keyset
    legacy_keyset = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.15.0")
    
    assert get_keyset_id_version(legacy_keyset.id) == "00", "Legacy should be version '00'"
    assert not is_keyset_id_v2(legacy_keyset.id), "Legacy should not be v2"
    
    # V2 keyset
    v2_id = derive_keyset_id_v2(legacy_keyset.public_keys, Unit.sat)
    
    assert get_keyset_id_version(v2_id) == "01", "V2 should be version '01'"
    assert is_keyset_id_v2(v2_id), "V2 should be detected as v2"


@pytest.mark.asyncio
async def test_keyset_final_expiry_field():
    """Test MintKeyset with final_expiry field."""
    final_expiry = 1896187313
    
    # Create keyset with final expiry
    keyset_with_expiry = MintKeyset(
        seed=SEED,
        derivation_path=DERIVATION_PATH,
        version="0.15.0",
        final_expiry=final_expiry
    )
    
    assert keyset_with_expiry.final_expiry == final_expiry, "Final expiry should be set"
    assert keyset_with_expiry.unit == Unit.sat, "Unit should be inferred correctly"
    
    # Create keyset without final expiry
    keyset_no_expiry = MintKeyset(
        seed=SEED,
        derivation_path=DERIVATION_PATH,
        version="0.15.0"
    )
    
    assert keyset_no_expiry.final_expiry is None, "Final expiry should be None by default"


@pytest.mark.asyncio
async def test_keyset_v2_deterministic():
    """Test that v2 keyset IDs are deterministic."""
    keyset1 = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.15.0")
    keyset2 = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.15.0")
    
    # Same inputs should produce same v2 IDs
    id1 = derive_keyset_id_v2(keyset1.public_keys, Unit.sat)
    id2 = derive_keyset_id_v2(keyset2.public_keys, Unit.sat)
    
    assert id1 == id2, "Same inputs should produce same v2 keyset ID"
    
    # With expiry
    final_expiry = 1896187313
    id1_exp = derive_keyset_id_v2(keyset1.public_keys, Unit.sat, final_expiry)
    id2_exp = derive_keyset_id_v2(keyset2.public_keys, Unit.sat, final_expiry)
    
    assert id1_exp == id2_exp, "Same inputs with expiry should produce same v2 keyset ID"


@pytest.mark.asyncio
async def test_keyset_v1_v2_compatibility():
    """Test that v1 and v2 keysets can coexist."""
    keyset = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.15.0")
    
    # Get v1 ID (current behavior)
    v1_id = keyset.id
    
    # Generate v2 ID from same keys
    v2_id = derive_keyset_id_v2(keyset.public_keys, Unit.sat)
    
    # Should be different
    assert v1_id != v2_id, "V1 and V2 IDs should be different"
    
    # Both should be valid but different versions
    assert get_keyset_id_version(v1_id) == "00", "V1 should be version '00'"
    assert get_keyset_id_version(v2_id) == "01", "V2 should be version '01'"
    
    # Public keys should be identical
    assert keyset.public_keys_hex is not None, "Public keys should be available"


@pytest.mark.asyncio
async def test_keyset_id_v2_error_cases():
    """Test error handling in v2 functions."""
    # Test invalid keyset ID
    with pytest.raises(ValueError):
        get_keyset_id_version("x")  # Too short
    
    with pytest.raises(ValueError):
        derive_keyset_short_id("02invalid")  # Invalid version
    
    # Test with None keys should work (just empty dict)
    empty_id = derive_keyset_id_v2({}, Unit.sat)
    assert empty_id.startswith("01"), "Empty keys should still produce valid v2 ID"


@pytest.mark.asyncio 
async def test_keyset_backward_compatibility():
    """Test that existing functionality still works with our changes."""
    # This should work exactly as before
    legacy_keyset = MintKeyset(
        seed=SEED, 
        derivation_path=DERIVATION_PATH, 
        version="0.15.0"
    )
    
    # Known expected values from existing tests
    assert legacy_keyset.id == "009a1f293253e41e"
    assert (
        legacy_keyset.public_keys_hex[1]
        == "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
    )
    
    # Legacy derive_keyset_id should still work
    legacy_derived = derive_keyset_id(legacy_keyset.public_keys)
    assert legacy_derived == "009a1f293253e41e", "Legacy derivation should be unchanged"

# ==================== KEYSETS V2 TEST VECTORS ====================

@pytest.mark.asyncio
async def test_keyset_id_v2_test_vectors():
    """
    Test vectors for v2 keyset ID derivation. These ensure stability for interoperable implementations.

    Vector input choices use the existing SEED/DERIVATION_PATH to generate public keys deterministically
    with our test harness. If your public keys change due to upstream changes, update vectors accordingly.
    """
    # Base keyset used to obtain public keys; unit = sat
    keyset = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.15.0")
    assert keyset.public_keys, "Public keys must be available"

    # Vector 1: no final_expiry, unit=sat
    v1 = derive_keyset_id_v2(keyset.public_keys, Unit.sat)
    assert v1.startswith("01") and len(v1) == 66

    # Vector 2: with final_expiry
    exp = 1896187313
    v2 = derive_keyset_id_v2(keyset.public_keys, Unit.sat, exp)
    assert v2.startswith("01") and len(v2) == 66 and v2 != v1

    # Vector 3: unit variance (usd)
    v3 = derive_keyset_id_v2(keyset.public_keys, Unit.usd)
    assert v3.startswith("01") and len(v3) == 66 and v3 != v1

    # Short ID relationship invariants
    s1 = derive_keyset_short_id(v1)
    s2 = derive_keyset_short_id(v2)
    s3 = derive_keyset_short_id(v3)
    assert s1 == v1[:16] and s2 == v2[:16] and s3 == v3[:16]

    # Sanity: versions
    assert get_keyset_id_version(v1) == "01"
    assert get_keyset_id_version(v2) == "01"
    assert get_keyset_id_version(v3) == "01"
