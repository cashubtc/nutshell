# Notation

Sending user: `Alice`
Receivung user: `Carol`
Mint: `Bob`

## Bob (mint)
- `k` private key of mint (one for each supported amount)
- `K` public key of mint
- `Q` promise (blinded signature)

## Alice (user)
- `x` random string (secret message), corresponds to point `Y` on curve
- `r` private key (blinding factor)
- `T` blinded message
- `Z` proof (unblinded signature)

# Blind Diffie-Hellmann key exchange (BDH)
-   Mint `Bob` publishes `K = kG` 
-   `Alice` picks secret `x` and computes `Y = hash_to_point(x)` 
-   `Alice` sends to `Bob`: `T = Y + rG` with `r` being a random nonce
-   `Bob` sends back to `Alice` blinded key: `Q = kT` (these two steps are the DH key exchange)
-   `Alice` can calculate the unblinded key as `Q - rK = kY + krG - krG = kY = Z`
-   Alice can take the pair `(x, Z)` as a token and can send it to `Carol`.
-   `Carol` can send `(x, Z)` to `Bob` who then checks that `k*hash_to_point(x) == Z`, and if so treats it as a valid spend of a token, adding `x`  to the list of spent secrets.