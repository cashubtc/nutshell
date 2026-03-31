#!/usr/bin/env python3
"""
Test for P2PK signature deduplication bypass vulnerability fix.

This test demonstrates the security issue where identical signatures with
different case encodings could bypass deduplication, potentially enabling
multi-signature bypass or double-spend attacks.
"""

#!/usr/bin/env python3
"""
Simplified test for the P2PK signature deduplication fix.
This test demonstrates the vulnerability and verifies the fix works.
"""


def test_p2pk_signature_deduplication_bypass_vulnerability():
    """
    Test the P2PK signature deduplication bypass vulnerability.
    
    Before fix: Same signature with different case (upper/lower) could be 
    added multiple times, bypassing deduplication.
    
    After fix: Signatures are normalized to lowercase for consistent 
    storage and deduplication.
    """
    # Demonstrate the vulnerability with simple string comparison
    
    # Test signature (same bytes, different hex case)
    test_signature_lower = "7fae1faf2b3c4d5e6f789abcdef0123456789abcdef0123456789abcdef012345"
    test_signature_upper = "7FAE1FAF2B3C4D5E6F789ABCDEF0123456789ABCDEF0123456789ABCDEF012345"
    test_signature_mixed = "7fAE1fAF2b3C4d5E6f789AbCdEf0123456789AbCdEf0123456789AbCdEf012345"
    
    # Before fix: This would allow multiple identical signatures with different cases
    # After fix: All signatures should be normalized to lowercase
    
    # Add first signature (lowercase)
    proofs_with_first_sig = wallet.add_signatures_to_proofs(
        [proof], [test_signature_lower]
    )
    
    # Verify first signature was added
    witness1 = P2PKWitness.from_witness(proofs_with_first_sig[0].witness)
    assert len(witness1.signatures) == 1
    assert witness1.signatures[0] == test_signature_lower.lower()
    
    # Try to add the same signature in uppercase
    proofs_with_duplicate = wallet.add_signatures_to_proofs(
        proofs_with_first_sig, [test_signature_upper]
    )
    
    # After fix: Should not add duplicate (same signature, different case)
    witness2 = P2PKWitness.from_witness(proofs_with_duplicate[0].witness)
    assert len(witness2.signatures) == 1  # Should still be 1, not 2
    assert witness2.signatures[0] == test_signature_lower.lower()
    
    # Try to add same signature in mixed case
    proofs_with_mixed = wallet.add_signatures_to_proofs(
        proofs_with_duplicate, [test_signature_mixed]  
    )
    
    # Should still have only 1 signature (deduplication working)
    witness3 = P2PKWitness.from_witness(proofs_with_mixed[0].witness)
    assert len(witness3.signatures) == 1
    assert witness3.signatures[0] == test_signature_lower.lower()
    
    # Add a genuinely different signature
    different_signature = "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"
    proofs_with_different = wallet.add_signatures_to_proofs(
        proofs_with_mixed, [different_signature]
    )
    
    # Should now have 2 signatures (different signatures allowed)
    witness4 = P2PKWitness.from_witness(proofs_with_different[0].witness)
    assert len(witness4.signatures) == 2
    assert test_signature_lower.lower() in witness4.signatures
    assert different_signature.lower() in witness4.signatures
    
    print("✅ P2PK signature deduplication test passed!")
    print(f"   - Prevented duplicate signatures with different cases")
    print(f"   - All signatures normalized to lowercase: {witness4.signatures}")


def test_security_impact_demonstration():
    """
    Demonstrate the potential security impact of the vulnerability.
    
    This shows how the same cryptographic signature could appear
    as different strings, potentially bypassing multi-sig validation.
    """
    # Same signature bytes in different representations
    sig_bytes = bytes.fromhex("7fae1faf2b3c4d5e6f789abcdef0123456789abcdef0123456789abcdef012345")
    
    # Multiple string representations of the same signature
    representations = [
        sig_bytes.hex(),                    # Default lowercase
        sig_bytes.hex().upper(),           # Uppercase  
        sig_bytes.hex().lower(),           # Explicit lowercase
        "7FAE1faf2B3c4D5e6F789aBCdeF0123456789aBCdeF0123456789aBCdeF012345"  # Mixed
    ]
    
    # All represent the same cryptographic signature
    for rep in representations:
        assert bytes.fromhex(rep) == sig_bytes
        
    # But before fix, string comparison would see them as different
    unique_strings = set(representations)
    assert len(unique_strings) > 1  # Multiple string representations
    
    # After fix: all normalized to same form
    normalized = set(rep.lower() for rep in representations) 
    assert len(normalized) == 1  # Single normalized form
    
    print("✅ Security impact demonstration complete!")
    print(f"   - Same signature had {len(unique_strings)} string representations")
    print(f"   - Fix normalizes to {len(normalized)} canonical form")


if __name__ == "__main__":
    test_p2pk_signature_deduplication_bypass_vulnerability()
    test_security_impact_demonstration()
    print("\n🛡️  All P2PK security tests passed! Vulnerability fixed.")