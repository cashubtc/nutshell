import pytest

from cashu.core.base import MintKeyset, Unit
from cashu.core.crypto.keys import (
    derive_keyset_id,
    derive_keyset_id_v2,
    derive_keyset_short_id,
    get_keyset_id_version,
    is_keyset_id_v2,
)
from cashu.core.crypto.secp import PublicKey
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from tests.mint.test_mint_init import (
    DECRYPTON_KEY,
    DERIVATION_PATH,
    ENCRYPTED_SEED,
    SEED,
)

V1_KEYSET_ID = "009a1f293253e41e"
V2_KEYSET_ID = "016d1ce32977b2d8a340479336a77dc18db8da3e782c5083a6f33d70bc158056d1"


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
    assert keyset.id == V1_KEYSET_ID


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
        == "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
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
    
    # Test version 0.19+: v2 ID (01...)
    keyset_0_19 = MintKeyset(seed=SEED, derivation_path=DERIVATION_PATH, version="0.19.0")
    assert keyset_0_19.id.startswith("01"), "Version 0.19 should produce v2 ID starting with '01'"
    assert len(keyset_0_19.id) == 66, "V2 ID should be 66 characters (33 bytes hex)"
    assert is_keyset_id_v2(keyset_0_19.id), "Should be detected as v2"


# ==================== KEYSET IDs NUT-02 TEST VECTORS ====================

@pytest.mark.asyncio
async def test_keyset_id_v1_test_vectors():
    """
    Test vectors for v1 keyset ID derivation from NUT-02.
    Source: https://github.com/cashubtc/nuts/blob/master/tests/02-tests.md
    """
    # Vector 1: Small keyset
    keys_v1_vec1 = {
        1: PublicKey(bytes.fromhex("03a40f20667ed53513075dc51e715ff2046cad64eb68960632269ba7f0210e38bc")),
        2: PublicKey(bytes.fromhex("03fd4ce5a16b65576145949e6f99f445f8249fee17c606b688b504a849cdc452de")),
        4: PublicKey(bytes.fromhex("02648eccfa4c026960966276fa5a4cae46ce0fd432211a4f449bf84f13aa5f8303")),
        8: PublicKey(bytes.fromhex("02fdfd6796bfeac490cbee12f778f867f0a2c68f6508d17c649759ea0dc3547528")),
    }
    keyset_id_v1_vec1 = derive_keyset_id(keys_v1_vec1)
    assert keyset_id_v1_vec1 == "00456a94ab4e1c46", "V1 vector 1 keyset ID mismatch"
    
    # Vector 2: Large keyset (all max_order amounts)
    keys_v1_vec2 = {
        1: PublicKey(bytes.fromhex("03ba786a2c0745f8c30e490288acd7a72dd53d65afd292ddefa326a4a3fa14c566")),
        2: PublicKey(bytes.fromhex("03361cd8bd1329fea797a6add1cf1990ffcf2270ceb9fc81eeee0e8e9c1bd0cdf5")),
        4: PublicKey(bytes.fromhex("036e378bcf78738ddf68859293c69778035740e41138ab183c94f8fee7572214c7")),
        8: PublicKey(bytes.fromhex("03909d73beaf28edfb283dbeb8da321afd40651e8902fcf5454ecc7d69788626c0")),
        16: PublicKey(bytes.fromhex("028a36f0e6638ea7466665fe174d958212723019ec08f9ce6898d897f88e68aa5d")),
        32: PublicKey(bytes.fromhex("03a97a40e146adee2687ac60c2ba2586a90f970de92a9d0e6cae5a4b9965f54612")),
        64: PublicKey(bytes.fromhex("03ce86f0c197aab181ddba0cfc5c5576e11dfd5164d9f3d4a3fc3ffbbf2e069664")),
        128: PublicKey(bytes.fromhex("0284f2c06d938a6f78794814c687560a0aabab19fe5e6f30ede38e113b132a3cb9")),
        256: PublicKey(bytes.fromhex("03b99f475b68e5b4c0ba809cdecaae64eade2d9787aa123206f91cd61f76c01459")),
        512: PublicKey(bytes.fromhex("03d4db82ea19a44d35274de51f78af0a710925fe7d9e03620b84e3e9976e3ac2eb")),
        1024: PublicKey(bytes.fromhex("031fbd4ba801870871d46cf62228a1b748905ebc07d3b210daf48de229e683f2dc")),
        2048: PublicKey(bytes.fromhex("0276cedb9a3b160db6a158ad4e468d2437f021293204b3cd4bf6247970d8aff54b")),
        4096: PublicKey(bytes.fromhex("02fc6b89b403ee9eb8a7ed457cd3973638080d6e04ca8af7307c965c166b555ea2")),
        8192: PublicKey(bytes.fromhex("0320265583e916d3a305f0d2687fcf2cd4e3cd03a16ea8261fda309c3ec5721e21")),
        16384: PublicKey(bytes.fromhex("036e41de58fdff3cb1d8d713f48c63bc61fa3b3e1631495a444d178363c0d2ed50")),
        32768: PublicKey(bytes.fromhex("0365438f613f19696264300b069d1dad93f0c60a37536b72a8ab7c7366a5ee6c04")),
        65536: PublicKey(bytes.fromhex("02408426cfb6fc86341bac79624ba8708a4376b2d92debdf4134813f866eb57a8d")),
        131072: PublicKey(bytes.fromhex("031063e9f11c94dc778c473e968966eac0e70b7145213fbaff5f7a007e71c65f41")),
        262144: PublicKey(bytes.fromhex("02f2a3e808f9cd168ec71b7f328258d0c1dda250659c1aced14c7f5cf05aab4328")),
        524288: PublicKey(bytes.fromhex("038ac10de9f1ff9395903bb73077e94dbf91e9ef98fd77d9a2debc5f74c575bc86")),
        1048576: PublicKey(bytes.fromhex("0203eaee4db749b0fc7c49870d082024b2c31d889f9bc3b32473d4f1dfa3625788")),
        2097152: PublicKey(bytes.fromhex("033cdb9d36e1e82ae652b7b6a08e0204569ec7ff9ebf85d80a02786dc7fe00b04c")),
        4194304: PublicKey(bytes.fromhex("02c8b73f4e3a470ae05e5f2fe39984d41e9f6ae7be9f3b09c9ac31292e403ac512")),
        8388608: PublicKey(bytes.fromhex("025bbe0cfce8a1f4fbd7f3a0d4a09cb6badd73ef61829dc827aa8a98c270bc25b0")),
        16777216: PublicKey(bytes.fromhex("037eec3d1651a30a90182d9287a5c51386fe35d4a96839cf7969c6e2a03db1fc21")),
        33554432: PublicKey(bytes.fromhex("03280576b81a04e6abd7197f305506476f5751356b7643988495ca5c3e14e5c262")),
        67108864: PublicKey(bytes.fromhex("03268bfb05be1dbb33ab6e7e00e438373ca2c9b9abc018fdb452d0e1a0935e10d3")),
        134217728: PublicKey(bytes.fromhex("02573b68784ceba9617bbcc7c9487836d296aa7c628c3199173a841e7a19798020")),
        268435456: PublicKey(bytes.fromhex("0234076b6e70f7fbf755d2227ecc8d8169d662518ee3a1401f729e2a12ccb2b276")),
        536870912: PublicKey(bytes.fromhex("03015bd88961e2a466a2163bd4248d1d2b42c7c58a157e594785e7eb34d880efc9")),
        1073741824: PublicKey(bytes.fromhex("02c9b076d08f9020ebee49ac8ba2610b404d4e553a4f800150ceb539e9421aaeee")),
        2147483648: PublicKey(bytes.fromhex("034d592f4c366afddc919a509600af81b489a03caf4f7517c2b3f4f2b558f9a41a")),
        4294967296: PublicKey(bytes.fromhex("037c09ecb66da082981e4cbdb1ac65c0eb631fc75d85bed13efb2c6364148879b5")),
        8589934592: PublicKey(bytes.fromhex("02b4ebb0dda3b9ad83b39e2e31024b777cc0ac205a96b9a6cfab3edea2912ed1b3")),
        17179869184: PublicKey(bytes.fromhex("026cc4dacdced45e63f6e4f62edbc5779ccd802e7fabb82d5123db879b636176e9")),
        34359738368: PublicKey(bytes.fromhex("02b2cee01b7d8e90180254459b8f09bbea9aad34c3a2fd98c85517ecfc9805af75")),
        68719476736: PublicKey(bytes.fromhex("037a0c0d564540fc574b8bfa0253cca987b75466e44b295ed59f6f8bd41aace754")),
        137438953472: PublicKey(bytes.fromhex("021df6585cae9b9ca431318a713fd73dbb76b3ef5667957e8633bca8aaa7214fb6")),
        274877906944: PublicKey(bytes.fromhex("02b8f53dde126f8c85fa5bb6061c0be5aca90984ce9b902966941caf963648d53a")),
        549755813888: PublicKey(bytes.fromhex("029cc8af2840d59f1d8761779b2496623c82c64be8e15f9ab577c657c6dd453785")),
        1099511627776: PublicKey(bytes.fromhex("03e446fdb84fad492ff3a25fc1046fb9a93a5b262ebcd0151caa442ea28959a38a")),
        2199023255552: PublicKey(bytes.fromhex("02d6b25bd4ab599dd0818c55f75702fde603c93f259222001246569018842d3258")),
        4398046511104: PublicKey(bytes.fromhex("03397b522bb4e156ec3952d3f048e5a986c20a00718e5e52cd5718466bf494156a")),
        8796093022208: PublicKey(bytes.fromhex("02d1fb9e78262b5d7d74028073075b80bb5ab281edcfc3191061962c1346340f1e")),
        17592186044416: PublicKey(bytes.fromhex("030d3f2ad7a4ca115712ff7f140434f802b19a4c9b2dd1c76f3e8e80c05c6a9310")),
        35184372088832: PublicKey(bytes.fromhex("03e325b691f292e1dfb151c3fb7cad440b225795583c32e24e10635a80e4221c06")),
        70368744177664: PublicKey(bytes.fromhex("03bee8f64d88de3dee21d61f89efa32933da51152ddbd67466bef815e9f93f8fd1")),
        140737488355328: PublicKey(bytes.fromhex("0327244c9019a4892e1f04ba3bf95fe43b327479e2d57c25979446cc508cd379ed")),
        281474976710656: PublicKey(bytes.fromhex("02fb58522cd662f2f8b042f8161caae6e45de98283f74d4e99f19b0ea85e08a56d")),
        562949953421312: PublicKey(bytes.fromhex("02adde4b466a9d7e59386b6a701a39717c53f30c4810613c1b55e6b6da43b7bc9a")),
        1125899906842624: PublicKey(bytes.fromhex("038eeda11f78ce05c774f30e393cda075192b890d68590813ff46362548528dca9")),
        2251799813685248: PublicKey(bytes.fromhex("02ec13e0058b196db80f7079d329333b330dc30c000dbdd7397cbbc5a37a664c4f")),
        4503599627370496: PublicKey(bytes.fromhex("02d2d162db63675bd04f7d56df04508840f41e2ad87312a3c93041b494efe80a73")),
        9007199254740992: PublicKey(bytes.fromhex("0356969d6aef2bb40121dbd07c68b6102339f4ea8e674a9008bb69506795998f49")),
        18014398509481984: PublicKey(bytes.fromhex("02f4e667567ebb9f4e6e180a4113bb071c48855f657766bb5e9c776a880335d1d6")),
        36028797018963968: PublicKey(bytes.fromhex("0385b4fe35e41703d7a657d957c67bb536629de57b7e6ee6fe2130728ef0fc90b0")),
        72057594037927936: PublicKey(bytes.fromhex("02b2bc1968a6fddbcc78fb9903940524824b5f5bed329c6ad48a19b56068c144fd")),
        144115188075855872: PublicKey(bytes.fromhex("02e0dbb24f1d288a693e8a49bc14264d1276be16972131520cf9e055ae92fba19a")),
        288230376151711744: PublicKey(bytes.fromhex("03efe75c106f931a525dc2d653ebedddc413a2c7d8cb9da410893ae7d2fa7d19cc")),
        576460752303423488: PublicKey(bytes.fromhex("02c7ec2bd9508a7fc03f73c7565dc600b30fd86f3d305f8f139c45c404a52d958a")),
        1152921504606846976: PublicKey(bytes.fromhex("035a6679c6b25e68ff4e29d1c7ef87f21e0a8fc574f6a08c1aa45ff352c1d59f06")),
        2305843009213693952: PublicKey(bytes.fromhex("033cdc225962c052d485f7cfbf55a5b2367d200fe1fe4373a347deb4cc99e9a099")),
        4611686018427387904: PublicKey(bytes.fromhex("024a4b806cf413d14b294719090a9da36ba75209c7657135ad09bc65328fba9e6f")),
        9223372036854775808: PublicKey(bytes.fromhex("0377a6fe114e291a8d8e991627c38001c8305b23b9e98b1c7b1893f5cd0dda6cad")),
    }
    keyset_id_v1_vec2 = derive_keyset_id(keys_v1_vec2)
    assert keyset_id_v1_vec2 == "000f01df73ea149a", "V1 vector 2 keyset ID mismatch"


@pytest.mark.asyncio
async def test_keyset_id_v2_test_vectors():
    """
    Test vectors for v2 keyset ID derivation from NUT-02.
    Source: https://github.com/cashubtc/nuts/blob/master/tests/02-tests.md
    
    V2 uses the v2 derivation which includes unit and optional final_expiry.
    """
    # V2 Vector 1: Small keyset (4 keys)
    keys_v2_vec1 = {
        1: PublicKey(bytes.fromhex("03a40f20667ed53513075dc51e715ff2046cad64eb68960632269ba7f0210e38bc")),
        2: PublicKey(bytes.fromhex("03fd4ce5a16b65576145949e6f99f445f8249fee17c606b688b504a849cdc452de")),
        4: PublicKey(bytes.fromhex("02648eccfa4c026960966276fa5a4cae46ce0fd432211a4f449bf84f13aa5f8303")),
        8: PublicKey(bytes.fromhex("02fdfd6796bfeac490cbee12f778f867f0a2c68f6508d17c649759ea0dc3547528")),
    }
    keyset_id_v2_vec1 = derive_keyset_id_v2(keys_v2_vec1, Unit.sat, 2059210353, 100)
    assert keyset_id_v2_vec1 == "015ba18a8adcd02e715a58358eb618da4a4b3791151a4bee5e968bb88406ccf76a", \
        "V2 vector 1 keyset ID mismatch"
    
    # V2 Vectors 2 and 3: Large keyset (all max_order amounts)
    keys_v2_vec23 = {
        1: PublicKey(bytes.fromhex("03ba786a2c0745f8c30e490288acd7a72dd53d65afd292ddefa326a4a3fa14c566")),
        2: PublicKey(bytes.fromhex("03361cd8bd1329fea797a6add1cf1990ffcf2270ceb9fc81eeee0e8e9c1bd0cdf5")),
        4: PublicKey(bytes.fromhex("036e378bcf78738ddf68859293c69778035740e41138ab183c94f8fee7572214c7")),
        8: PublicKey(bytes.fromhex("03909d73beaf28edfb283dbeb8da321afd40651e8902fcf5454ecc7d69788626c0")),
        16: PublicKey(bytes.fromhex("028a36f0e6638ea7466665fe174d958212723019ec08f9ce6898d897f88e68aa5d")),
        32: PublicKey(bytes.fromhex("03a97a40e146adee2687ac60c2ba2586a90f970de92a9d0e6cae5a4b9965f54612")),
        64: PublicKey(bytes.fromhex("03ce86f0c197aab181ddba0cfc5c5576e11dfd5164d9f3d4a3fc3ffbbf2e069664")),
        128: PublicKey(bytes.fromhex("0284f2c06d938a6f78794814c687560a0aabab19fe5e6f30ede38e113b132a3cb9")),
        256: PublicKey(bytes.fromhex("03b99f475b68e5b4c0ba809cdecaae64eade2d9787aa123206f91cd61f76c01459")),
        512: PublicKey(bytes.fromhex("03d4db82ea19a44d35274de51f78af0a710925fe7d9e03620b84e3e9976e3ac2eb")),
        1024: PublicKey(bytes.fromhex("031fbd4ba801870871d46cf62228a1b748905ebc07d3b210daf48de229e683f2dc")),
        2048: PublicKey(bytes.fromhex("0276cedb9a3b160db6a158ad4e468d2437f021293204b3cd4bf6247970d8aff54b")),
        4096: PublicKey(bytes.fromhex("02fc6b89b403ee9eb8a7ed457cd3973638080d6e04ca8af7307c965c166b555ea2")),
        8192: PublicKey(bytes.fromhex("0320265583e916d3a305f0d2687fcf2cd4e3cd03a16ea8261fda309c3ec5721e21")),
        16384: PublicKey(bytes.fromhex("036e41de58fdff3cb1d8d713f48c63bc61fa3b3e1631495a444d178363c0d2ed50")),
        32768: PublicKey(bytes.fromhex("0365438f613f19696264300b069d1dad93f0c60a37536b72a8ab7c7366a5ee6c04")),
        65536: PublicKey(bytes.fromhex("02408426cfb6fc86341bac79624ba8708a4376b2d92debdf4134813f866eb57a8d")),
        131072: PublicKey(bytes.fromhex("031063e9f11c94dc778c473e968966eac0e70b7145213fbaff5f7a007e71c65f41")),
        262144: PublicKey(bytes.fromhex("02f2a3e808f9cd168ec71b7f328258d0c1dda250659c1aced14c7f5cf05aab4328")),
        524288: PublicKey(bytes.fromhex("038ac10de9f1ff9395903bb73077e94dbf91e9ef98fd77d9a2debc5f74c575bc86")),
        1048576: PublicKey(bytes.fromhex("0203eaee4db749b0fc7c49870d082024b2c31d889f9bc3b32473d4f1dfa3625788")),
        2097152: PublicKey(bytes.fromhex("033cdb9d36e1e82ae652b7b6a08e0204569ec7ff9ebf85d80a02786dc7fe00b04c")),
        4194304: PublicKey(bytes.fromhex("02c8b73f4e3a470ae05e5f2fe39984d41e9f6ae7be9f3b09c9ac31292e403ac512")),
        8388608: PublicKey(bytes.fromhex("025bbe0cfce8a1f4fbd7f3a0d4a09cb6badd73ef61829dc827aa8a98c270bc25b0")),
        16777216: PublicKey(bytes.fromhex("037eec3d1651a30a90182d9287a5c51386fe35d4a96839cf7969c6e2a03db1fc21")),
        33554432: PublicKey(bytes.fromhex("03280576b81a04e6abd7197f305506476f5751356b7643988495ca5c3e14e5c262")),
        67108864: PublicKey(bytes.fromhex("03268bfb05be1dbb33ab6e7e00e438373ca2c9b9abc018fdb452d0e1a0935e10d3")),
        134217728: PublicKey(bytes.fromhex("02573b68784ceba9617bbcc7c9487836d296aa7c628c3199173a841e7a19798020")),
        268435456: PublicKey(bytes.fromhex("0234076b6e70f7fbf755d2227ecc8d8169d662518ee3a1401f729e2a12ccb2b276")),
        536870912: PublicKey(bytes.fromhex("03015bd88961e2a466a2163bd4248d1d2b42c7c58a157e594785e7eb34d880efc9")),
        1073741824: PublicKey(bytes.fromhex("02c9b076d08f9020ebee49ac8ba2610b404d4e553a4f800150ceb539e9421aaeee")),
        2147483648: PublicKey(bytes.fromhex("034d592f4c366afddc919a509600af81b489a03caf4f7517c2b3f4f2b558f9a41a")),
        4294967296: PublicKey(bytes.fromhex("037c09ecb66da082981e4cbdb1ac65c0eb631fc75d85bed13efb2c6364148879b5")),
        8589934592: PublicKey(bytes.fromhex("02b4ebb0dda3b9ad83b39e2e31024b777cc0ac205a96b9a6cfab3edea2912ed1b3")),
        17179869184: PublicKey(bytes.fromhex("026cc4dacdced45e63f6e4f62edbc5779ccd802e7fabb82d5123db879b636176e9")),
        34359738368: PublicKey(bytes.fromhex("02b2cee01b7d8e90180254459b8f09bbea9aad34c3a2fd98c85517ecfc9805af75")),
        68719476736: PublicKey(bytes.fromhex("037a0c0d564540fc574b8bfa0253cca987b75466e44b295ed59f6f8bd41aace754")),
        137438953472: PublicKey(bytes.fromhex("021df6585cae9b9ca431318a713fd73dbb76b3ef5667957e8633bca8aaa7214fb6")),
        274877906944: PublicKey(bytes.fromhex("02b8f53dde126f8c85fa5bb6061c0be5aca90984ce9b902966941caf963648d53a")),
        549755813888: PublicKey(bytes.fromhex("029cc8af2840d59f1d8761779b2496623c82c64be8e15f9ab577c657c6dd453785")),
        1099511627776: PublicKey(bytes.fromhex("03e446fdb84fad492ff3a25fc1046fb9a93a5b262ebcd0151caa442ea28959a38a")),
        2199023255552: PublicKey(bytes.fromhex("02d6b25bd4ab599dd0818c55f75702fde603c93f259222001246569018842d3258")),
        4398046511104: PublicKey(bytes.fromhex("03397b522bb4e156ec3952d3f048e5a986c20a00718e5e52cd5718466bf494156a")),
        8796093022208: PublicKey(bytes.fromhex("02d1fb9e78262b5d7d74028073075b80bb5ab281edcfc3191061962c1346340f1e")),
        17592186044416: PublicKey(bytes.fromhex("030d3f2ad7a4ca115712ff7f140434f802b19a4c9b2dd1c76f3e8e80c05c6a9310")),
        35184372088832: PublicKey(bytes.fromhex("03e325b691f292e1dfb151c3fb7cad440b225795583c32e24e10635a80e4221c06")),
        70368744177664: PublicKey(bytes.fromhex("03bee8f64d88de3dee21d61f89efa32933da51152ddbd67466bef815e9f93f8fd1")),
        140737488355328: PublicKey(bytes.fromhex("0327244c9019a4892e1f04ba3bf95fe43b327479e2d57c25979446cc508cd379ed")),
        281474976710656: PublicKey(bytes.fromhex("02fb58522cd662f2f8b042f8161caae6e45de98283f74d4e99f19b0ea85e08a56d")),
        562949953421312: PublicKey(bytes.fromhex("02adde4b466a9d7e59386b6a701a39717c53f30c4810613c1b55e6b6da43b7bc9a")),
        1125899906842624: PublicKey(bytes.fromhex("038eeda11f78ce05c774f30e393cda075192b890d68590813ff46362548528dca9")),
        2251799813685248: PublicKey(bytes.fromhex("02ec13e0058b196db80f7079d329333b330dc30c000dbdd7397cbbc5a37a664c4f")),
        4503599627370496: PublicKey(bytes.fromhex("02d2d162db63675bd04f7d56df04508840f41e2ad87312a3c93041b494efe80a73")),
        9007199254740992: PublicKey(bytes.fromhex("0356969d6aef2bb40121dbd07c68b6102339f4ea8e674a9008bb69506795998f49")),
        18014398509481984: PublicKey(bytes.fromhex("02f4e667567ebb9f4e6e180a4113bb071c48855f657766bb5e9c776a880335d1d6")),
        36028797018963968: PublicKey(bytes.fromhex("0385b4fe35e41703d7a657d957c67bb536629de57b7e6ee6fe2130728ef0fc90b0")),
        72057594037927936: PublicKey(bytes.fromhex("02b2bc1968a6fddbcc78fb9903940524824b5f5bed329c6ad48a19b56068c144fd")),
        144115188075855872: PublicKey(bytes.fromhex("02e0dbb24f1d288a693e8a49bc14264d1276be16972131520cf9e055ae92fba19a")),
        288230376151711744: PublicKey(bytes.fromhex("03efe75c106f931a525dc2d653ebedddc413a2c7d8cb9da410893ae7d2fa7d19cc")),
        576460752303423488: PublicKey(bytes.fromhex("02c7ec2bd9508a7fc03f73c7565dc600b30fd86f3d305f8f139c45c404a52d958a")),
        1152921504606846976: PublicKey(bytes.fromhex("035a6679c6b25e68ff4e29d1c7ef87f21e0a8fc574f6a08c1aa45ff352c1d59f06")),
        2305843009213693952: PublicKey(bytes.fromhex("033cdc225962c052d485f7cfbf55a5b2367d200fe1fe4373a347deb4cc99e9a099")),
        4611686018427387904: PublicKey(bytes.fromhex("024a4b806cf413d14b294719090a9da36ba75209c7657135ad09bc65328fba9e6f")),
        9223372036854775808: PublicKey(bytes.fromhex("0377a6fe114e291a8d8e991627c38001c8305b23b9e98b1c7b1893f5cd0dda6cad")),
    }
    
    # V2 Vector 2: Unit=sat, final_expiry=2059210353 (with large keyset)
    keyset_id_v2_vec2 = derive_keyset_id_v2(keys_v2_vec23, Unit.sat, 2059210353)
    assert keyset_id_v2_vec2 == "01ab6aa4ff30390da34986d84be5274b48ad7a74265d791095bfc39f4098d9764f", \
        "V2 vector 2 keyset ID mismatch"
    
    # V2 Vector 3: Unit=sat, no final_expiry (with large keyset)
    keyset_id_v2_vec3 = derive_keyset_id_v2(keys_v2_vec23, Unit.sat)
    assert keyset_id_v2_vec3 == "012fbb01a4e200c76df911eeba3b8fe1831202914b24664f4bccbd25852a6708f8", \
        "V2 vector 3 keyset ID mismatch"
    
    # Verify all are v2 format
    assert is_keyset_id_v2(keyset_id_v2_vec1), "Vector 1 should be v2"
    assert is_keyset_id_v2(keyset_id_v2_vec2), "Vector 2 should be v2"
    assert is_keyset_id_v2(keyset_id_v2_vec3), "Vector 3 should be v2"
    
    # Verify version byte
    assert get_keyset_id_version(keyset_id_v2_vec1) == "01", "Vector 1 should be version 01"
    assert get_keyset_id_version(keyset_id_v2_vec2) == "01", "Vector 2 should be version 01"
    assert get_keyset_id_version(keyset_id_v2_vec3) == "01", "Vector 3 should be version 01"
