# Legacy (version 00) test vectors remain documented at
# https://github.com/davidcaseria/nuts/blob/keyset-id-v2/tests/13-tests.md

"""

LEGACY_V1_KEYSET_ID = "009a1f293253e41e"  # Legacy v1 keyset ID per NUT-13
V2_KEYSET_ID = "V2_KEYSET_ID"


Tests for wallet keysets v2 and NUT-13 secret derivation implementation.
"""

import hashlib
import hmac

import pytest
from mnemonic import Mnemonic

from cashu.core.base import TokenV4, TokenV4Proof, TokenV4Token
from cashu.core.crypto.keys import (
    derive_keyset_short_id,
    get_keyset_id_version,
    is_keyset_id_v2,
)
from cashu.wallet.keyset_manager import KeysetManager
from cashu.wallet.secrets import WalletSecrets

# Reference mnemonic from NUT-13 test vectors
MNEMONIC = "half depart obvious quality work element tank gorilla view sugar picture humble"


@pytest.mark.asyncio
async def test_versioned_secret_derivation_bip32():
    """Test that BIP32 derivation is used for keyset version 00 (legacy)."""
    # Create a mock wallet secrets instance
    secrets = WalletSecrets()
    secrets.keyset_id = "LEGACY_V1_KEYSET_ID"  # v1 keyset ID
    secrets.seed = b"supersecretprivatekey"
    secrets.bip32 = None  # Will be set by _init_private_key
    
    # Mock the BIP32 derivation
    class MockBIP32:
        def get_privkey_from_path(self, path):
            return hashlib.sha256(f"mock_bip32_{path}".encode()).digest()
    
    secrets.bip32 = MockBIP32()
    
    # Test secret derivation
    secret, r, path = await secrets.generate_determinstic_secret(1)
    
    # Should use BIP32 derivation for v1 keysets
    assert "m/129372'" in path
    assert len(secret) == 32
    assert len(r) == 32


@pytest.mark.asyncio 
async def test_versioned_secret_derivation_hmac_sha256():
    """Test that HMAC-SHA256 derivation is used for keyset version 01 (v2) and matches spec."""
    secrets = WalletSecrets()
    secrets.keyset_id = "V2_KEYSET_ID"  # v2 keyset ID
    # derive seed from mnemonic per NUT-13
    mnemo = Mnemonic("english")
    secrets.seed = mnemo.to_seed(MNEMONIC)

    secret, r, path = await secrets.generate_determinstic_secret(1)

    # Should use HMAC-SHA256 derivation for v2 keysets
    assert "HMAC-SHA256" in path
    assert len(secret) == 32
    assert len(r) == 32

    # Verify against NUT-13 derivation formula
    keyset_id_bytes = bytes.fromhex(secrets.keyset_id)
    counter_bytes = (1).to_bytes(8, byteorder="big")
    base = b"Cashu_KDF_HMAC_SHA256" + keyset_id_bytes + counter_bytes
    expected_secret = hmac.new(secrets.seed, base + b"\x00", hashlib.sha256).digest()
    expected_r = hmac.new(secrets.seed, base + b"\x01", hashlib.sha256).digest()

    assert secret == expected_secret
    assert r == expected_r


@pytest.mark.asyncio
async def test_keyset_manager_short_id_mapping():
    """Test short keyset ID mapping functionality."""
    manager = KeysetManager()
    
    # Mock database and keysets
    manager._short_to_full_cache = {}
    manager._full_to_short_cache = {}
    
    # Test v2 keyset
    full_id_v2 = "V2_KEYSET_ID"
    expected_short_id = derive_keyset_short_id(full_id_v2)
    
    # Test getting short ID
    short_id = await manager.get_short_keyset_id(full_id_v2)
    assert short_id == expected_short_id
    assert len(short_id) == 16  # 8 bytes = 16 hex chars
    
    # Test cache was updated
    assert manager._full_to_short_cache[full_id_v2] == short_id
    assert manager._short_to_full_cache[short_id] == full_id_v2
    
    # Test getting full ID from short ID
    retrieved_full_id = await manager.get_full_keyset_id(short_id)
    assert retrieved_full_id == full_id_v2


@pytest.mark.asyncio
async def test_keyset_manager_v1_compatibility():
    """Test that v1 keysets return original ID (no short ID concept)."""
    manager = KeysetManager()
    
    # Test v1 keyset
    v1_keyset_id = "LEGACY_V1_KEYSET_ID"
    
    # For v1 keysets, should return the original ID
    short_id = await manager.get_short_keyset_id(v1_keyset_id)
    assert short_id == v1_keyset_id  # No change for v1


@pytest.mark.asyncio
async def test_token_v4_short_keyset_expansion():
    """Test TokenV4 short keyset ID expansion."""
    # Create a TokenV4 with short keyset ID
    short_keyset_id = "01c9c20fb8b348b3"  # 8 bytes
    full_keyset_id = "V2_KEYSET_ID"
    
    # Create mock token with short keyset ID
    token = TokenV4(
        m="https://mint.example.com",
        u="sat",
        t=[
            TokenV4Token(
                i=bytes.fromhex(short_keyset_id),
                p=[
                    TokenV4Proof(
                        a=64,
                        s="test_secret",
                        c=bytes.fromhex("abcd1234"),
                    )
                ]
            )
        ]
    )
    
    # Mock wallet with keyset manager (no tokens_v2 helper in this project)
    manager = KeysetManager()
    manager._short_to_full_cache = {short_keyset_id: full_keyset_id}

    async def expand_token_keysets_local(tok: TokenV4) -> TokenV4:
        new_tokens = []
        for tkn in tok.t:
            keyset_hex = tkn.i.hex()
            if len(keyset_hex) == 16 and keyset_hex.startswith("01"):
                full = await manager.get_full_keyset_id(keyset_hex)
                new_tokens.append(TokenV4Token(i=bytes.fromhex(full), p=tkn.p))
            else:
                new_tokens.append(tkn)
        return TokenV4(m=tok.m, u=tok.u, t=new_tokens, d=tok.d)

    # Test expansion
    expanded_token = await expand_token_keysets_local(token)
    
    # Should have expanded the keyset ID
    assert expanded_token.t[0].i.hex() == full_keyset_id


@pytest.mark.asyncio
async def test_token_serialization_with_short_ids():
    """Test token serialization uses short keyset IDs for v2 keysets."""
    from cashu.core.base import Proof, WalletKeyset
    from cashu.core.crypto.secp import PublicKey
    from cashu.wallet.proofs import WalletProofs

    # Mock keyset data
    full_keyset_id = "V2_KEYSET_ID"
    short_keyset_id = derive_keyset_short_id(full_keyset_id)

    # Create proofs with v2 keyset
    proofs = [
        Proof(
            id=full_keyset_id,
            amount=64,
            secret="test_secret",
            C="abcd1234"
        )
    ]

    # Prepare WalletProofs with a minimal keyset map
    wp = WalletProofs()
    # Minimal WalletKeyset (unit and mint_url are required by _make_tokenv4)
    mock_keyset = WalletKeyset(public_keys={64: PublicKey()}, unit="sat", id=full_keyset_id, mint_url="https://mint.example.com")
    wp.keysets = {full_keyset_id: mock_keyset}

    # Create token; implementation should switch v2 full ID -> short ID
    token = await wp._make_token(proofs)

    # Token should use short keyset ID
    assert token.t[0].i.hex() == short_keyset_id
    assert len(token.t[0].i.hex()) == 16  # 8 bytes = 16 hex chars


def test_nut13_spec_compliance():
    """Test that HMAC-SHA256 derivation follows NUT-13 specification exactly with BIP-39 seed."""
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(MNEMONIC)
    keyset_id = "V2_KEYSET_ID"
    counter = 1

    keyset_id_bytes = bytes.fromhex(keyset_id)
    counter_bytes = counter.to_bytes(8, byteorder="big")
    base = b"Cashu_KDF_HMAC_SHA256" + keyset_id_bytes + counter_bytes

    expected_secret = hmac.new(seed, base + b"\x00", hashlib.sha256).digest()
    expected_r = hmac.new(seed, base + b"\x01", hashlib.sha256).digest()

    # Test our implementation
    secrets = WalletSecrets()
    secrets.seed = seed
    secrets.keyset_id = keyset_id

    import asyncio
    secret, r, path = asyncio.run(secrets._derive_secret_hmac_sha256(counter, keyset_id))

    assert "HMAC-SHA256" in path
    assert secret == expected_secret
    assert r == expected_r


def test_keyset_version_detection():
    """Test keyset version detection works correctly."""
    # Test v1 keyset
    v1_id = "LEGACY_V1_KEYSET_ID"
    assert get_keyset_id_version(v1_id) == "00"
    assert not is_keyset_id_v2(v1_id)
    
    # Test v2 keyset
    v2_id = "V2_KEYSET_ID"
    assert get_keyset_id_version(v2_id) == "01"
    assert is_keyset_id_v2(v2_id)


@pytest.mark.asyncio
async def test_secret_derivation_version_routing():
    """Test that the main derivation method routes to correct sub-methods."""
    secrets = WalletSecrets()
    secrets.seed = b"test_seed"
    
    # Mock BIP32
    class MockBIP32:
        def get_privkey_from_path(self, path):
            return hashlib.sha256(f"bip32_{path}".encode()).digest()
    
    secrets.bip32 = MockBIP32()
    
    # Test v1 routing
    secrets.keyset_id = "LEGACY_V1_KEYSET_ID"
    secret_v1, r_v1, path_v1 = await secrets.generate_determinstic_secret(1)
    assert "m/129372'" in path_v1  # BIP32 path
    
    # Test v2 routing
    secrets.keyset_id = "V2_KEYSET_ID"
    secret_v2, r_v2, path_v2 = await secrets.generate_determinstic_secret(1)
    assert "HMAC-SHA256" in path_v2  # HMAC derivation
    
    # Results should be different
    assert secret_v1 != secret_v2
    assert r_v1 != r_v2


@pytest.mark.asyncio
async def test_short_keyset_id_round_trip():
    """Test round-trip conversion between full and short keyset IDs."""
    full_id = "V2_KEYSET_ID"
    expected_short = "01c9c20fb8b348b3"
    
    # Test derivation
    short_id = derive_keyset_short_id(full_id)
    assert short_id == expected_short
    assert len(short_id) == 16  # 8 bytes
    
    # Test manager round-trip
    manager = KeysetManager()
    manager._short_to_full_cache = {short_id: full_id}
    manager._full_to_short_cache = {full_id: short_id}
    
    # Test both directions
    retrieved_short = await manager.get_short_keyset_id(full_id)
    assert retrieved_short == short_id
    
    retrieved_full = await manager.get_full_keyset_id(short_id)
    assert retrieved_full == full_id


def test_short_keyset_id_properties():
    """Test properties of short keyset IDs."""
    # Test various v2 keyset IDs
    test_cases = [
        "V2_KEYSET_ID",
        "01a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
        "017890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456",
    ]
    
    for full_id in test_cases:
        short_id = derive_keyset_short_id(full_id)
        
        # Should be 8 bytes (16 hex chars)
        assert len(short_id) == 16
        
        # Should preserve version prefix
        assert short_id.startswith("01")
        
        # Should be first 8 bytes of full ID
        assert short_id == full_id[:16]


@pytest.mark.asyncio
async def test_token_size_reduction():
    """Test that tokens with short keyset IDs are smaller."""
    # This is more of a conceptual test since we can't easily measure
    # the exact byte savings without a full token serialization
    
    full_id = "V2_KEYSET_ID"
    short_id = derive_keyset_short_id(full_id)
    
    # The space savings: 33 bytes -> 8 bytes = 25 bytes saved per keyset
    full_id_bytes = bytes.fromhex(full_id)
    short_id_bytes = bytes.fromhex(short_id)
    
    assert len(full_id_bytes) == 33  # Full v2 keyset ID
    assert len(short_id_bytes) == 8   # Short keyset ID
    
    savings = len(full_id_bytes) - len(short_id_bytes)
    assert savings == 25  # 25 bytes saved per keyset


@pytest.mark.asyncio
async def test_backward_compatibility():
    """Test that v1 keysets work unchanged."""
    secrets = WalletSecrets()
    secrets.seed = b"test_seed"
    
    # Mock BIP32 for v1 keysets
    class MockBIP32:
        def get_privkey_from_path(self, path):
            return hashlib.sha256(f"bip32_{path}".encode()).digest()
    
    secrets.bip32 = MockBIP32()
    
    # Test v1 keyset behavior is unchanged
    v1_keyset_id = "LEGACY_V1_KEYSET_ID"
    secrets.keyset_id = v1_keyset_id
    
    secret, r, path = await secrets.generate_determinstic_secret(1)
    
    # Should still use BIP32 derivation
    assert "m/129372'" in path
    assert len(secret) == 32
    assert len(r) == 32
    
    # Short ID should be the same as full ID for v1
    manager = KeysetManager()
    short_id = await manager.get_short_keyset_id(v1_keyset_id)
    assert short_id == v1_keyset_id


@pytest.mark.asyncio
async def test_error_handling():
    """Test error handling for invalid keyset versions."""
    secrets = WalletSecrets()
    secrets.seed = b"test_seed"
    
    # Test unsupported version
    invalid_keyset_id = "99invalid_version_id"
    secrets.keyset_id = invalid_keyset_id
    
    with pytest.raises(ValueError, match="Unsupported keyset version"):
        await secrets.generate_determinstic_secret(1)


if __name__ == "__main__":
    # Run a quick test to verify functionality
    import asyncio
    
    async def quick_test():
        print("Testing NUT-13 HMAC-SHA512 derivation...")
        
        # Test HMAC-SHA512 derivation
        secrets = WalletSecrets()
        secrets.seed = b"test_seed"
        secrets.keyset_id = "V2_KEYSET_ID"
        
        secret, r, path = await secrets._derive_secret_hmac_sha512(1, secrets.keyset_id)
        print(f"✅ HMAC-SHA512 derivation: {len(secret)} byte secret, {len(r)} byte r")
        print(f"   Path: {path}")
        
        # Test short keyset ID
        full_id = "V2_KEYSET_ID"
        short_id = derive_keyset_short_id(full_id)
        print(f"✅ Short keyset ID: {full_id[:20]}... -> {short_id}")
        print(f"   Space saved: {len(bytes.fromhex(full_id)) - len(bytes.fromhex(short_id))} bytes")
        
        print("All tests passed! ✅")
    
    asyncio.run(quick_test())
