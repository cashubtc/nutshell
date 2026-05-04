import pytest

from cashu.core.base import MintKeyset, Unit
from cashu.core.crypto.keys import (
    derive_keyset_id,
    derive_keyset_id_v2,
    derive_keyset_short_id,
    get_keyset_id_version,
    is_keyset_id_v2,
)
from cashu.core.crypto.bls import PublicKey
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from tests.mint.test_mint_init import (
    DECRYPTON_KEY,
    DERIVATION_PATH,
    ENCRYPTED_SEED,
    SEED,
)

V1_KEYSET_ID = "009b3cebb427eed1"
V2_KEYSET_ID = "01847b08df40a9011a940892d8bdf4953822c32699899abd7d11fb720c3f49fc20"


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
        == "830ed4ff501ddfd496adeca0a7e60c6ffb2dcb2463ca695190e16279cb078da318025fe89b719b9e7a10aac3de9c6d771686b337fa97ebc931a122626ba1cdd9a78c154f5864e8f68f7b3a82bc3ca847bf6ef8874a9a66172a086f960147fad6"
    )
    assert keyset.id == V1_KEYSET_ID


@pytest.mark.asyncio
async def test_keyset_0_14_0():
    keyset = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.14.0")
    assert len(keyset.public_keys_hex) == settings.max_order
    assert keyset.seed == "TEST_PRIVATE_KEY"
    assert keyset.derivation_path == "m/0'/0'/0'"
    assert (
        keyset.public_keys_hex[1]
        == "91780c4133caaf775cfa6eb4305a2bb7879373b1b3c2829c9e18c75951e5fd93e717b365d57df6a16da29924296e19cc12e7642bf79b31addb716f271f1562db2b67642b217d284984fd414331164e0cb8d23b6da0d807621adf024799e3b089"
    )
    assert keyset.id == "/5r2y+65/aIQ"


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
        == "830ed4ff501ddfd496adeca0a7e60c6ffb2dcb2463ca695190e16279cb078da318025fe89b719b9e7a10aac3de9c6d771686b337fa97ebc931a122626ba1cdd9a78c154f5864e8f68f7b3a82bc3ca847bf6ef8874a9a66172a086f960147fad6"
    )
    assert keyset.id == V1_KEYSET_ID


@pytest.mark.asyncio
async def test_keyset_rotation(ledger: Ledger):
    keyset_sat = next(
        filter(lambda k: k.unit == Unit["sat"] and k.active, ledger.keysets.values())
    )
    new_keyset_sat = await ledger.rotate_next_keyset(
        unit=Unit["sat"], max_order=20, input_fee_ppk=1
    )

    keyset_sat_derivation = keyset_sat.derivation_path.split("/")
    new_keyset_sat_derivation = new_keyset_sat.derivation_path.split("/")

    assert (
        keyset_sat_derivation[:-1] == new_keyset_sat_derivation[:-1]
    ), "keyset derivation does not match up to the counter branch"
    assert (
        int(new_keyset_sat_derivation[-1].replace("'", ""))
        - int(keyset_sat_derivation[-1].replace("'", ""))
        == 1
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
    assert legacy_short == V1_KEYSET_ID, "Legacy short ID should be same as full ID"
    
    # Test with v2 keyset
    v2_id = derive_keyset_id_v2(keyset.public_keys, Unit.sat)
    v2_short = derive_keyset_short_id(v2_id)
    
    assert len(v2_short) == 16, "V2 short ID should be 16 characters (8 bytes)"
    assert v2_short.startswith("01"), "V2 short ID should start with version"
    assert v2_id.startswith(v2_short), "Short ID should be prefix of full ID"


@pytest.mark.asyncio
async def test_keyset_version_detection():
    """Test keyset version detection utilities."""
    # V1 keyset (version 0.15 produces v1 IDs)
    v1_keyset = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.15.0")
    
    assert get_keyset_id_version(v1_keyset.id) == "00", "V1 keyset should be version '00'"
    assert not is_keyset_id_v2(v1_keyset.id), "V1 should NOT be detected as v2"
    
    # V2 keyset ID derived manually
    v2_id = derive_keyset_id_v2(v1_keyset.public_keys, Unit.sat)
    
    assert get_keyset_id_version(v2_id) == "01", "V2 ID should be version '01'"
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
    keyset1 = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.18.0")
    keyset2 = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.18.0")
    
    # Same inputs should produce same v2 IDs
    id1 = keyset1.id
    id2 = keyset2.id
    
    assert id1 == id2, "Same inputs should produce same v2 keyset ID"
    
    # With expiry
    final_expiry = 1896187313
    id1_exp = derive_keyset_id_v2(keyset1.public_keys, keyset1.unit, final_expiry)
    id2_exp = derive_keyset_id_v2(keyset2.public_keys, keyset2.unit, final_expiry)
    
    assert id1_exp == id2_exp, "Same inputs with expiry should produce same v2 keyset ID"

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
    assert legacy_keyset.id == V1_KEYSET_ID
    assert (
        legacy_keyset.public_keys_hex[1]
        == "830ed4ff501ddfd496adeca0a7e60c6ffb2dcb2463ca695190e16279cb078da318025fe89b719b9e7a10aac3de9c6d771686b337fa97ebc931a122626ba1cdd9a78c154f5864e8f68f7b3a82bc3ca847bf6ef8874a9a66172a086f960147fad6"
    )
    
    # Legacy derive_keyset_id should still work
    legacy_derived = derive_keyset_id(legacy_keyset.public_keys)
    assert legacy_derived == V1_KEYSET_ID, "Legacy derivation should be unchanged"

# ==================== KEYSET VERSION BEHAVIOR TESTS ====================

@pytest.mark.asyncio
async def test_keyset_versions_produce_correct_id_format():
    """
    Test that different versions produce the correct keyset ID format:
    - Very old keysets (< 0.15) had base64 IDs
    - Version 0.15-0.17 use v1 IDs (00...)
    - Version 0.18+ use v2 IDs (01...)
    """
    # Test version < 0.12: base64 ID
    keyset_0_11 = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.11.0")
    assert len(keyset_0_11.id) == 12, "Version < 0.12 should produce 12-char base64 ID"
    assert not keyset_0_11.id.startswith("00") and not keyset_0_11.id.startswith("01"), "Should not be versioned hex ID"
    
    # Test version < 0.15: base64 ID  
    keyset_0_14 = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.14.0")
    assert len(keyset_0_14.id) == 12, "Version < 0.15 should produce 12-char base64 ID"
    assert not keyset_0_14.id.startswith("00") and not keyset_0_14.id.startswith("01"), "Should not be versioned hex ID"
    
    # Test version 0.15-0.17: v1 ID (00...)
    keyset_0_15 = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.15.0")
    assert keyset_0_15.id.startswith("00"), "Version 0.15 should produce v1 ID starting with '00'"
    assert len(keyset_0_15.id) == 16, "V1 ID should be 16 characters (8 bytes hex)"
    assert keyset_0_15.id == V1_KEYSET_ID, "Should match expected v1 ID"
    
    keyset_0_17 = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.17.0")
    assert keyset_0_17.id.startswith("00"), "Version 0.17 should produce v1 ID starting with '00'"
    assert len(keyset_0_17.id) == 16, "V1 ID should be 16 characters (8 bytes hex)"

    keyset_0_18 = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.18.0")
    assert keyset_0_18.id.startswith("00"), "Version 0.18 should produce v1 ID starting with '00'"
    assert len(keyset_0_18.id) == 16, "V1 ID should be 16 characters (8 bytes hex)"
    
    # Test version 0.20+: v2 ID (01...)
    keyset_0_20 = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.20.0")
    assert keyset_0_20.id.startswith("01"), "Version 0.20 should produce v2 ID starting with '01'"
    assert len(keyset_0_20.id) == 66, "V2 ID should be 66 characters (33 bytes hex)"
    assert is_keyset_id_v2(keyset_0_20.id), "Should be detected as v2"


# ==================== KEYSET IDs NUT-02 TEST VECTORS ====================

