# Legacy (version 00) test vectors remain documented at
# https://github.com/davidcaseria/nuts/blob/keyset-id-v2/tests/13-tests.md

"""
Tests for wallet keysets v2 and NUT-13 secret derivation implementation.
"""

import hashlib
import hmac

import pytest
from bip32 import BIP32
from mnemonic import Mnemonic

from cashu.core.base import Proof, TokenV4, TokenV4Proof, TokenV4Token, WalletKeyset
from cashu.core.crypto.keys import (
    derive_keyset_short_id,
    get_keyset_id_version,
    is_base64_keyset_id,
    is_keyset_id_v2,
)
from cashu.core.crypto.secp import PrivateKey
from cashu.wallet.keyset_manager import KeysetManager
from cashu.wallet.proofs import WalletProofs
from cashu.wallet.secrets import WalletSecrets

# Reference mnemonic from NUT-13 test vectors
MNEMONIC = "half depart obvious quality work element tank gorilla view sugar picture humble"
LEGACY_V1_KEYSET_ID = "009a1f293253e41e"
V2_KEYSET_ID = "01d8a63077d0a51f9855f066409782ffcb322dc8a2265291865221ed06c039f6bc"
BASE64_KEYSET_ID = "yjzQhxghPdrr"


@pytest.mark.asyncio
async def test_versioned_secret_derivation_bip32():
    """Test that BIP32 derivation is used for keyset version 00 (legacy)."""
    # Create a mock wallet secrets instance
    secrets = WalletSecrets()
    secrets.keyset_id = LEGACY_V1_KEYSET_ID  # v1 keyset ID
    secrets.seed = b"supersecretprivatekey"
    secrets.bip32 = BIP32.from_seed(secrets.seed)
    
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
    secrets.keyset_id = V2_KEYSET_ID  # v2 keyset ID
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
    full_id_v2 = V2_KEYSET_ID
    expected_short_id = derive_keyset_short_id(full_id_v2)
    
    # Test getting short ID
    short_id = manager.get_short_keyset_id(full_id_v2)
    assert short_id == expected_short_id
    assert len(short_id) == 16  # 8 bytes = 16 hex chars
    
    # Test cache was updated
    assert manager._full_to_short_cache[full_id_v2] == short_id
    assert manager._short_to_full_cache[short_id] == full_id_v2
    
    # Test getting full ID from short ID
    retrieved_full_id = manager.get_full_keyset_id(short_id)
    assert retrieved_full_id == full_id_v2


@pytest.mark.asyncio
async def test_keyset_manager_v1_compatibility():
    """Test that v1 keysets return original ID (no short ID concept)."""
    manager = KeysetManager()
    
    # Test v1 keyset
    v1_keyset_id = LEGACY_V1_KEYSET_ID
    
    # For v1 keysets, should return the original ID
    short_id = manager.get_short_keyset_id(v1_keyset_id)
    assert short_id == v1_keyset_id  # No change for v1


@pytest.mark.asyncio
async def test_token_v4_short_keyset_expansion():
    """Test TokenV4 short keyset ID expansion."""
    # Create v2 full and short keyset IDs
    full_keyset_id = V2_KEYSET_ID
    short_keyset_id = derive_keyset_short_id(full_keyset_id)
    assert len(short_keyset_id) == 16, "Short ID should be 16 chars"
    assert short_keyset_id.startswith("01"), "Short ID should start with version 01"
    
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
    
    # Mock wallet with keyset manager
    manager = KeysetManager()
    manager._short_to_full_cache = {short_keyset_id: full_keyset_id}

    async def expand_token_keysets_local(tok: TokenV4) -> TokenV4:
        new_tokens = []
        for tkn in tok.t:
            keyset_hex = tkn.i.hex()
            if len(keyset_hex) == 16 and keyset_hex.startswith("01"):
                full = manager.get_full_keyset_id(keyset_hex)
                new_tokens.append(TokenV4Token(i=bytes.fromhex(full), p=tkn.p))
            else:
                new_tokens.append(tkn)
        return TokenV4(m=tok.m, u=tok.u, t=new_tokens, d=tok.d)

    # Test expansion
    expanded_token = await expand_token_keysets_local(token)
    
    # Should have expanded the keyset ID from short to full
    assert expanded_token.t[0].i.hex() == full_keyset_id


@pytest.mark.asyncio
async def test_token_serialization_with_short_ids():
    """Test token serialization uses short keyset IDs for v2 keysets."""
    from cashu.core.base import Proof, WalletKeyset
    from cashu.wallet.proofs import WalletProofs

    # Mock keyset data - use the actual constant
    full_keyset_id = V2_KEYSET_ID
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
    mock_keyset = WalletKeyset(public_keys={64: PrivateKey(b"\x00" * 31 + b"\x02").public_key}, unit="sat", id=full_keyset_id, mint_url="https://mint.example.com")
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
    keyset_id = V2_KEYSET_ID  # Use the actual constant instead of string literal
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
    v1_id = LEGACY_V1_KEYSET_ID
    assert get_keyset_id_version(v1_id) == "00"
    assert not is_keyset_id_v2(v1_id)
    
    # Test v2 keyset
    v2_id = V2_KEYSET_ID
    assert get_keyset_id_version(v2_id) == "01"
    assert is_keyset_id_v2(v2_id)


@pytest.mark.asyncio
async def test_secret_derivation_version_routing():
    """Test that the main derivation method routes to correct sub-methods."""
    secrets = WalletSecrets()
    secrets.seed = b"test_seed"    
    secrets.bip32 = BIP32.from_seed(secrets.seed)
    
    # Test v1 routing
    secrets.keyset_id = LEGACY_V1_KEYSET_ID
    secret_v1, r_v1, path_v1 = await secrets.generate_determinstic_secret(1)
    assert "m/129372'" in path_v1  # BIP32 path
    
    # Test v2 routing
    secrets.keyset_id = V2_KEYSET_ID
    secret_v2, r_v2, path_v2 = await secrets.generate_determinstic_secret(1)
    assert "HMAC-SHA256" in path_v2  # HMAC derivation
    
    # Results should be different
    assert secret_v1 != secret_v2
    assert r_v1 != r_v2


@pytest.mark.asyncio
async def test_short_keyset_id_round_trip():
    """Test round-trip conversion between full and short keyset IDs."""
    full_id = V2_KEYSET_ID
    expected_short = "01d8a63077d0a51f"
    
    # Test derivation
    short_id = derive_keyset_short_id(full_id)
    assert short_id == expected_short
    assert len(short_id) == 16  # 8 bytes
    
    # Test manager round-trip
    manager = KeysetManager()
    manager._short_to_full_cache = {short_id: full_id}
    manager._full_to_short_cache = {full_id: short_id}
    
    # Test both directions
    retrieved_short = manager.get_short_keyset_id(full_id)
    assert retrieved_short == short_id
    
    retrieved_full = manager.get_full_keyset_id(short_id)
    assert retrieved_full == full_id


@pytest.mark.asyncio
async def test_backward_compatibility():
    """Test that v1 keysets work unchanged."""
    secrets = WalletSecrets()
    secrets.seed = b"test_seed"
    secrets.bip32 = BIP32.from_seed(secrets.seed)
    
    # Test v1 keyset behavior is unchanged
    v1_keyset_id = LEGACY_V1_KEYSET_ID
    secrets.keyset_id = v1_keyset_id
    
    secret, r, path = await secrets.generate_determinstic_secret(1)
    
    # Should still use BIP32 derivation
    assert "m/129372'" in path
    assert len(secret) == 32
    assert len(r) == 32
    
    # Short ID should be the same as full ID for v1
    manager = KeysetManager()
    short_id = manager.get_short_keyset_id(v1_keyset_id)
    assert short_id == v1_keyset_id


@pytest.mark.asyncio
async def test_proof_short_id_expansion():
    """Test that short keyset IDs in proofs are expanded to full IDs."""
    
    # Create a mock WalletProofs instance
    class MockWallet(WalletProofs):
        def __init__(self):
            self.keysets = {}
    
    wallet = MockWallet()
    
    # Create a v2 full keyset ID and its short version
    full_keyset_id = V2_KEYSET_ID
    short_keyset_id = derive_keyset_short_id(full_keyset_id)
    assert len(short_keyset_id) == 16, "Short ID should be 16 chars"
    assert short_keyset_id == "01d8a63077d0a51f", "Short ID mismatch"
    
    # Mock a keyset in the wallet
    mock_keyset = WalletKeyset(
        id=full_keyset_id,
        unit="sat",
        public_keys={},
        mint_url="https://mint.example.com"
    )
    wallet.keysets = {full_keyset_id: mock_keyset}
    
    # Create proofs with short keyset IDs
    proofs = [
        Proof(
            id=short_keyset_id,
            amount=64,
            secret="test_secret_1",
            C="abcd1234" * 8
        ),
        Proof(
            id=short_keyset_id,
            amount=32,
            secret="test_secret_2",
            C="efab5678" * 8
        )
    ]
    
    # Expand short IDs
    await wallet._expand_short_keyset_ids(proofs)
    
    # All proof IDs should now be expanded to full IDs
    for proof in proofs:
        assert proof.id == full_keyset_id, f"Expected full ID {full_keyset_id}, got {proof.id}"
        assert len(proof.id) == 66, "Expanded ID should be 66 chars"


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


def test_base64_keyset_id_detection():
    """Test detection of base64 keyset IDs (ancient API v0 format)."""
    # Test base64 keyset ID is detected correctly
    assert is_base64_keyset_id(BASE64_KEYSET_ID)
    assert get_keyset_id_version(BASE64_KEYSET_ID) == "base64"
    
    # Test v1 keyset is not detected as base64
    assert not is_base64_keyset_id(LEGACY_V1_KEYSET_ID)
    assert get_keyset_id_version(LEGACY_V1_KEYSET_ID) == "00"
    
    # Test v2 keyset is not detected as base64
    assert not is_base64_keyset_id(V2_KEYSET_ID)
    assert get_keyset_id_version(V2_KEYSET_ID) == "01"
    
    # Test that base64 ID is not considered v2
    assert not is_keyset_id_v2(BASE64_KEYSET_ID)


@pytest.mark.asyncio
async def test_base64_keyset_secret_derivation():
    """Test that base64 keyset IDs use BIP32 derivation (legacy method)."""
    secrets = WalletSecrets()
    secrets.keyset_id = BASE64_KEYSET_ID
    secrets.seed = b"test_seed_for_base64"
    secrets.bip32 = BIP32.from_seed(secrets.seed)
    
    # Test secret derivation
    secret, r, path = await secrets.generate_determinstic_secret(1)
    
    # Should use BIP32 derivation for base64 keysets
    assert "m/129372'" in path
    assert len(secret) == 32
    assert len(r) == 32
    
    # Verify the base64 keyset ID gets converted to integer correctly
    import base64
    keyset_id_int = int.from_bytes(base64.b64decode(BASE64_KEYSET_ID), "big") % (2**31 - 1)
    expected_path = f"m/129372'/0'/{keyset_id_int}'/1'"
    assert expected_path in path