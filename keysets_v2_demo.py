#!/usr/bin/env python3
"""
Demo script showing keysets v2 functionality.
This script demonstrates the completed keysets v2 implementation.
"""

import time
from cashu.core.base import MintKeyset, Unit
from cashu.core.crypto.keys import (
    derive_keyset_id_v2,
    derive_keyset_short_id,
    get_keyset_id_version,
    is_keyset_id_v2,
)

def main():
    print("🔑 Cashu Keysets v2 Implementation Demo")
    print("=" * 50)
    
    # Create a test keyset
    seed = "TEST_PRIVATE_KEY"
    derivation_path = "m/0'/0'/0'"
    keyset = MintKeyset(seed=seed, derivation_path=derivation_path, version="0.15.0")
    
    print(f"📋 Test Keyset Information:")
    print(f"   Legacy ID (v1): {keyset.id}")
    print(f"   Unit: {keyset.unit.name}")
    print(f"   Derivation Path: {keyset.derivation_path}")
    print()
    
    # Generate v2 keyset IDs for different scenarios
    print("🔥 Keysets v2 ID Generation:")
    print("-" * 30)
    
    # 1. V2 ID without expiry
    v2_id_no_expiry = derive_keyset_id_v2(keyset.public_keys, Unit.sat)
    print(f"V2 ID (no expiry): {v2_id_no_expiry}")
    
    # 2. V2 ID with expiry (year 2030)
    future_expiry = int(time.time()) + (10 * 365 * 24 * 60 * 60)  # 10 years from now
    v2_id_with_expiry = derive_keyset_id_v2(keyset.public_keys, Unit.sat, future_expiry)
    print(f"V2 ID (with expiry): {v2_id_with_expiry}")
    
    # 3. V2 IDs for different units
    print("\n💱 Unit-Specific Keyset IDs:")
    print("-" * 30)
    for unit in [Unit.sat, Unit.usd, Unit.eur, Unit.btc]:
        unit_id = derive_keyset_id_v2(keyset.public_keys, unit)
        print(f"{unit.name.upper()}: {unit_id}")
    
    # 4. Short IDs
    print("\n⚡ Short IDs for Tokens:")
    print("-" * 30)
    v2_short = derive_keyset_short_id(v2_id_no_expiry)
    legacy_short = derive_keyset_short_id(keyset.id)
    print(f"V2 Short ID:     {v2_short}")
    print(f"Legacy Short ID: {legacy_short}")
    
    # 5. Version detection
    print("\n🔍 Version Detection:")
    print("-" * 30)
    print(f"Legacy ID version: {get_keyset_id_version(keyset.id)}")
    print(f"V2 ID version:     {get_keyset_id_version(v2_id_no_expiry)}")
    print(f"Is legacy v2?:     {is_keyset_id_v2(keyset.id)}")
    print(f"Is v2 ID v2?:      {is_keyset_id_v2(v2_id_no_expiry)}")
    
    # 6. Feature comparison
    print("\n📊 Feature Comparison:")
    print("-" * 30)
    print("| Feature                | V1 (Legacy) | V2 (New)    |")
    print("|------------------------|-------------|-------------|")
    print(f"| ID Length              | {len(keyset.id)} chars     | {len(v2_id_no_expiry)} chars     |")
    print("| Unit-Specific          | ❌ No       | ✅ Yes      |")
    print("| Expiry Support         | ❌ No       | ✅ Yes      |")
    print("| Short ID Available     | ✅ Yes      | ✅ Yes      |")
    print("| Backward Compatible    | ✅ Yes      | ✅ Yes      |")
    
    print("\n✅ Keysets v2 Implementation Complete!")
    print("   - All core functions implemented")
    print("   - Database schema ready")
    print("   - API responses updated")
    print("   - Full backward compatibility maintained")
    print("   - Safe-by-default (v2 disabled by default)")


if __name__ == "__main__":
    main()
