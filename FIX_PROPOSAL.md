To fix the string comparison vulnerability for signature deduplication, you can use the following code:

```python
# Normalize to lowercase before comparison
signature_normalized = signature.lower()
proof_sigs_normalized = [sig.lower() for sig in signature_list]

if signature_normalized not in proof_sigs_normalized:
    signature_list.append(signature)
```

However, a more efficient and Pythonic way to achieve this is by using a case-insensitive data structure, such as a set of normalized signatures:

```python
# Create a set to store normalized signatures
normalized_signatures = set()

# ...

# Normalize signature before adding
signature_normalized = signature.lower()

if signature_normalized not in normalized_signatures:
    normalized_signatures.add(signature_normalized)
    signature_list.append(signature)
```

This approach eliminates the need for explicit list iteration and provides faster lookup times, especially for large lists of signatures.

**Commit Message:**
```
Fix string comparison vulnerability for signature deduplication

* Normalize signatures to lowercase before comparison
* Use a set for efficient case-insensitive lookup
```