To fix the string comparison vulnerability for signature deduplication, you can use the following code:

```python
# Normalize to lowercase before comparison
signature_normalized = signature.lower()
proof_sigs_normalized = [sig.lower() for sig in signature_list]

if signature_normalized not in proof_sigs_normalized:
    signature_list.append(signature)
```

However, a more efficient and Pythonic way to achieve this would be to use a `set` for storing unique signatures. Since `set` lookups are O(1) on average, this approach is more efficient than the original list-based approach:

```python
# Initialize an empty set to store unique signatures
signature_set = set()

# ...

# Normalize to lowercase before comparison and add to set
signature_normalized = signature.lower()

if signature_normalized not in signature_set:
    signature_set.add(signature_normalized)
    # You can also append the original signature to a list if needed
    signature_list.append(signature)
```

This approach ensures that duplicate signatures are not added, regardless of their case. 

**Commit Message:**
```
Fix string comparison vulnerability for signature deduplication

* Normalize signatures to lowercase before comparison
* Use a set to store unique signatures for efficient lookups
```