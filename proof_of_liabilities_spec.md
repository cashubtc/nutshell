# Independent Wallet-Side Proof of Liabilities (PoL) for Cashu

**Abstract:** This document specifies a decentralized, privacy-preserving, and independent wallet-side Proof of Liabilities (PoL) auditing scheme for Cashu mints. The mint issues a cryptographically signed **PoL Receipt** for each blinded message it signs (outputs) and each ecash note it marks as spent (inputs). Every wallet can independently request compact, bitmasked inclusion proofs after the target epoch passes, and challenge the mint publicly with a mathematically indisputable **Fraud Challenge** if the proofs fail. The threat of random wallet audits forces the mint to stay honest, and the Merkle-Sum Sparse Merkle Tree (MS-SMT) ensures that outstanding liabilities cannot be hidden or manipulated.

---

## 1. Motivation: Independent Wallet Auditing

To prove solvency, a custodian must prove that its outstanding liabilities (total issued ecash minus total spent/redeemed ecash) are fully backed by its reserves, and that no individual users' balances are hidden, excluded, or manipulated.

In this independent wallet-side auditing model:
1. **No Central Watchdog:** Every individual wallet acts as an independent watchdog of its own active and spent tokens on-demand, removing the need for third-party auditing coordinators.
2. **Accountability via Receipts:** The mint is held accountable to include every input and output in the next epoch via signed, transactional **PoL Receipts**.
3. **Stateless Verification:** Resource-constrained mobile wallets only need to request and verify a few small, compact inclusion proofs for their own tokens, eliminating the need to download entire trees.
4. **Honesty Through Random Audits:** Because any wallet can independently audit any token at any time, the mint cannot predict which leaves will be verified. This forces 100% honesty across the entire leaf space.
5. **Solvency Closure:** The resulting outstanding PoL balance committed to by the mint is verified to match the difference between the issued and spent trees, and only needs to be matched by a Proof of Reserves (PoR) on-chain, via Ark ASP outpoints, or Spark state channels to close the solvency loop.

---

## 2. Cryptographic Structure & Merkle Sum Trees (MS-SMT)

The mint maintains two distinct, synchronized Sparse Merkle Sum Trees (MS-SMT) of depth 256 for each active keyset:
1. **Issued Tree (Promises):** Tracks all blinded messages `B'` signed by the mint.
2. **Spent Tree (Proofs Used):** Tracks all spent proof secrets `Y` (where `Y = hash_to_curve(secret)`) redeemed or swapped.

### 2.1 Leaf Index Calculation

Leaf indices are calculated deterministically to prevent the mint from using different positions or duplicate entries:

* **Issued Leaf Index (I_issued):**
  1. Compute `h_B` as the `SHA256` hash of the hex-encoded string of the blinded message `B'`.
  2. Parse `h_B` as a big-endian integer to obtain the leaf index.
  
* **Spent Leaf Index (I_spent):**
  1. Compute `Y = hash_to_curve(secret)`.
  2. Compute `h_Y` as the `SHA256` hash of the compressed hex-encoded representation of the curve point `Y`.
  3. Parse `h_Y` as a big-endian integer to obtain the leaf index.

### 2.2 Merkle Sum Node & Hashing Specifications

Each tree node consists of a pair `(hash, sum_value)` where:
* `hash` is a 32-byte binary digest.
* `sum_value` is an 8-byte big-endian integer representing the satoshi amount.

```
                                [ Root ]
                         Hash: abc... Sum: 150
                              /        \
                            /            \
             [ Node 0 ]                        [ Node 1 ]
        Hash: def... Sum: 50              Hash: ghi... Sum: 100
             /        \                        /        \
           /            \                    /            \
      [ Leaf 0 ]    [ Leaf 1 ]          [ Leaf 2 ]    [ Leaf 3 ]
      Hash: H(A)    Hash: H(B)          Hash: empty   Hash: H(C)
      Sum: 50       Sum: 0              Sum: 0        Sum: 100
      (Valid)       (Omitted)           (Empty)       (Valid)
```

#### Precomputed Default Empty Nodes
To handle a `2^256` leaf space without storing empty nodes, default values are precomputed for level `d` (from `0` to `256`):
* **At level 0 (leaf):**
  * `hash_0 = SHA256(b"")`
  * `sum_0 = 0`
* **At level d (where d >= 1):**
  * `sum_d = 0`
  * `hash_d = SHA256(hash_{d-1} || hash_{d-1} || bytes_8(sum_{d-1}) || bytes_8(sum_{d-1}))`
  where `bytes_8(x)` is the 8-byte big-endian representation of integer `x`.

#### Parent Node Computation
When neighboring nodes `L = (hash_L, sum_L)` and `R = (hash_R, sum_R)` at level `d` are aggregated into parent `P = (hash_P, sum_P)` at level `d+1`:
* `sum_P = sum_L + sum_R`
* `hash_P = SHA256(hash_L || hash_R || bytes_8(sum_L) || bytes_8(sum_R))`

---

## 3. Epoch-Based Synchronization & On-Chain Commitments

To prevent split-view attacks, the mint commits to states at discrete boundaries called **Epochs** (e.g., 24 hours):

1. **Sort Keysets:** Retrieve all unexpired keyset IDs and sort them alphabetically.
2. **Global Commitment:** Concatenate the data of each sorted keyset sequentially:
   `commitment_data = (keyset_id_1 || root_issued_hash_1 || root_spent_hash_1 || keyset_id_2 || ...)`
3. **OpenTimestamps Attestation:** The mint computes the `SHA256` hash of this global commitment and submits it to public OpenTimestamps (OTS) calendar servers to obtain an immutable blockchain anchoring proof.
4. **Manifest Publication:** For each keyset, the mint constructs and signs the **Epoch PoL Manifest** string:
   `"{keyset_id}:{epoch_index}:{timestamp}:{root_issued_hash}:{root_issued_sum}:{root_spent_hash}:{root_spent_sum}:{outstanding_balance}:{ots_receipt}"`
   The signature is a BIP-340 Schnorr signature produced using the mint's master NUT-06 private key signing the SHA256 digest of this serialized manifest string.

---

## 4. Transactional PoL Receipts (Leverage)

To prevent the mint from delaying or denying inclusion of wallet transactions, the mint **MUST** return a cryptographically signed **PoL Receipt** for *every single output (blind signature) issued* and *every input (ecash note) spent* during `mint`, `melt`, and `swap` operations.

### 4.1 Receipt JSON Schema
Every returned blind signature and spent input in the responses contains a nested receipt:
```json
{
  "target_epoch": 12,
  "signature": "<hex_encoded_signature>"
}
```

### 4.2 Message Format & Key Rules
Each receipt is signed with a BIP-340 Schnorr signature (specifically signing the SHA256 digest of the formatted message) using the keyset-specific private key of the corresponding amount:

* **Outputs (Blinded Messages):**
  * **Message Format:** `{B_hex}:{target_epoch}`
  * **Signing Key:** `keyset.private_keys[amount]`
  * **Verification:** Wallets verify against the keyset public key for that specific amount.

* **Spent Inputs (Ecash Proofs):**
  * **Message Format:** `{Y_hex}:{target_epoch}`
  * **Signing Key:** `keyset.private_keys[amount]`
  * **Verification:** Wallets verify against the keyset public key for that specific amount.

### 4.3 Game-Theoretic Dynamics of Spent Receipt Refusal

A critical question arises: *What if the mint processes a transaction (e.g., a swap) but refuses to provide a `pol_receipt` for the spent ecash inputs?*

This scenario creates a self-enforcing game-theoretic trap for the mint:

1. **The Double-Spend / Re-spend Option:**
   If the mint marks the input ecash as spent in its internal database but refuses to issue a `pol_receipt` to the wallet, the wallet does not have a confirmation of spend. The wallet is therefore entitled to treat the ecash as still active and attempt to spend it again (either at the same mint or in a swap).
   - If the mint accepts the ecash again to avoid conflict, it enables a double-spend against itself, resulting in direct financial loss for the mint.

2. **The Perjury Trap:**
   If the wallet attempts to spend/swap the ecash again, and the mint rejects it with "already spent" (the token is nullified) but refuses to provide the `pol_receipt` for the initial spend, the mint is caught in flagrant malicious behavior.
   - Because the mint cannot prove *when* or *by whom* the token was spent without producing the corresponding signed `pol_receipt` linked to a specific epoch, the mint's unilateral rejection of a valid token without a receipt constitutes cryptographically verifiable proof of censorship or asset confiscation.

Therefore, the mint is forced into a binary choice: either honestly sign and return the `pol_receipt` for every spent note, or face immediate public exposure of malicious behavior and/or double-spend losses.

---

## 5. API & Sibling Proof Compaction

To ensure lightweight wallet integration, the mint returns **Compact Sibling Proofs** leveraging a 256-bit bitmask:
* If a sibling is a default empty node, it is **omitted** from the payload.
* The `d`-th bit of `compact_mask` is set to `1` if the sibling at level `d` is non-empty, and `0` if empty.

### 5.1 Query Issued Tree Proofs
`POST /v1/pol/{keyset_id}/proofs/issued`
```json
{
  "blinded_messages": ["02b1a..."]
}
```
### 5.2 Query Spent Tree Proofs
`POST /v1/pol/{keyset_id}/proofs/spent`
```json
{
  "ys": ["02b1a..."]
}
```
**Response Format (both):**
```json
{
  "proofs": [
    {
      "item": "02b1a...",
      "index": "8a31...",
      "value": 1000,
      "compact_mask": "0x301a...",
      "siblings": [
        {
          "hash": "b4a1...",
          "sum": 500
        }
      ]
    }
  ]
}
```

---

## 6. The 5-Step Wallet Auditing Protocol

Wallets independently run the following checks on their tokens (typically upon startup or when receiving/spending history has crossed an epoch boundary):

```
Step 1: Verify Manifest Signature against the Mint's Master Pubkey (NUT-06).
Step 2: Programmatically validate the OpenTimestamps receipt block attestation.
Step 3: Walk the Issued Tree (Active Ecash) up to verify inclusion matches `root_issued`.
Step 4: Walk the Spent Tree (Spent Ecash) up to verify inclusion matches `root_spent`.
Step 5: Verify Solvency: outstanding_balance == root_issued_sum - root_spent_sum.
```

If any check fails (e.g., an active token is missing, has an incorrect value, or does not match the signed roots), the wallet generates a public **Cryptographic Fraud Challenge**:

```json
{
  "challenge_type": "pol_fraud_proof",
  "keyset_id": "009a6154b71113b7",
  "epoch_index": 12,
  "manifest": { ... },
  "pol_receipt": {
    "target_epoch": 12,
    "signature": "<hex_encoded_signature>"
  },
  "proof_type": "issued",
  "item": "02b1a...",
  "index": "8a31...",
  "claimed_value": 1000,
  "actual_value": 0,
  "compact_mask": "0x...",
  "siblings": [ ... ]
}
```
This challenge can be broadcast publicly. Anyone can verify the forgery offline, proving the mint's perjury mathematically.
