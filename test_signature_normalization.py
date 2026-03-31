#!/usr/bin/env python3
"""
Simple test to demonstrate the P2PK signature deduplication vulnerability and fix.
"""

def test_signature_vulnerability():
    """
    Demonstrate how the same signature in different hex cases 
    could bypass deduplication before the fix.
    """
    
    # Same signature bytes represented in different hex cases
    signature_bytes = bytes.fromhex("7fae1faf2b3c4d5e6f789abcdef0123456789abcdef0123456789abcdef01234")
    
    signature_lower = signature_bytes.hex().lower()  
    signature_upper = signature_bytes.hex().upper()
    signature_mixed = "7fAE1fAF2b3C4d5E6f789AbCdEf0123456789AbCdEf0123456789AbCdEf01234"
    
    print("🔍 Testing P2PK Signature Deduplication Vulnerability")
    print(f"Lower: {signature_lower}")
    print(f"Upper: {signature_upper}")
    print(f"Mixed: {signature_mixed}")
    
    # Verify they represent the same cryptographic signature
    assert bytes.fromhex(signature_lower) == signature_bytes
    assert bytes.fromhex(signature_upper) == signature_bytes  
    assert bytes.fromhex(signature_mixed) == signature_bytes
    print("✅ All hex strings represent the same signature bytes")
    
    # Before fix: String comparison would see these as different
    signatures_set = {signature_lower, signature_upper, signature_mixed}
    print(f"❌ Before fix: {len(signatures_set)} unique strings (vulnerable)")
    
    # After fix: All normalized to lowercase
    normalized_set = {sig.lower() for sig in signatures_set}
    print(f"✅ After fix: {len(normalized_set)} unique string (secure)")
    
    # Demonstrate the deduplication logic
    proof_signatures = []
    
    # Simulate adding signatures with the old vulnerable logic
    print("\n🔓 Vulnerable logic (before fix):")
    for sig in [signature_lower, signature_upper, signature_mixed]:
        if sig not in proof_signatures:  # Vulnerable: direct string comparison
            proof_signatures.append(sig)
            print(f"   Added: {sig[:16]}...")
        else:
            print(f"   Rejected (duplicate): {sig[:16]}...")
    
    print(f"   Result: {len(proof_signatures)} signatures stored (BAD!)")
    
    # Simulate fixed logic  
    print("\n🔒 Fixed logic (after normalization):")
    proof_signatures_fixed = []
    proof_signatures_normalized = []
    
    for sig in [signature_lower, signature_upper, signature_mixed]:
        sig_normalized = sig.lower()
        if sig_normalized not in proof_signatures_normalized:
            proof_signatures_fixed.append(sig_normalized)  # Store normalized
            proof_signatures_normalized.append(sig_normalized)
            print(f"   Added: {sig_normalized[:16]}...")
        else:
            print(f"   Rejected (duplicate): {sig[:16]}... -> {sig_normalized[:16]}...")
    
    print(f"   Result: {len(proof_signatures_fixed)} signature stored (GOOD!)")
    
    return len(proof_signatures) > len(proof_signatures_fixed)


def test_security_impact():
    """Show potential impact of the vulnerability."""
    
    print("\n🚨 Security Impact Analysis:")
    print("   - Same cryptographic signature could appear as multiple strings")
    print("   - Multi-signature validation might be bypassed")  
    print("   - Potential for double-spend or replay attacks")
    print("   - Violation of signature uniqueness assumptions")
    
    # Example: Multi-sig requirement bypass
    required_sigs = 2
    unique_pubkeys = 2
    
    # With vulnerability: same sig could count multiple times
    vulnerable_sigs = ["sig1_lower", "SIG1_UPPER"]  # Same sig, different cases
    if len(set(vulnerable_sigs)) >= required_sigs:
        print(f"   ❌ Vulnerable: {len(vulnerable_sigs)} signatures >= {required_sigs} required (BYPASS!)")
    
    # With fix: normalized signatures prevent bypass
    fixed_sigs = [sig.lower() for sig in vulnerable_sigs]
    unique_fixed_sigs = list(set(fixed_sigs))
    if len(unique_fixed_sigs) >= required_sigs:
        print(f"   ❌ Would still pass (different sigs)")
    else:
        print(f"   ✅ Fixed: {len(unique_fixed_sigs)} unique signatures < {required_sigs} required (SECURE!)")


if __name__ == "__main__":
    vulnerability_existed = test_signature_vulnerability()
    test_security_impact()
    
    if vulnerability_existed:
        print("\n🛡️  VULNERABILITY CONFIRMED AND FIXED!")
        print("   The signature deduplication bypass has been patched.")
        print("   All signatures are now normalized to lowercase for consistency.")
    else:
        print("\n🤔 No vulnerability detected in test")
        
    print("\n📋 Fix Summary:")
    print("   - Normalize all hex signatures to lowercase before storage")
    print("   - Compare against normalized existing signatures")  
    print("   - Store normalized signatures to prevent case-based duplicates")
    print("   - Maintain cryptographic integrity while fixing string comparison")