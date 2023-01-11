# NUT-0 - Notation and Models

Sending user: `Alice`
Receiving user: `Carol`
Mint: `Bob`

## Bob (mint)
- `k` private key of mint (one for each amount)
- `K` public key of mint
- `Q` promise (blinded signature)

## Alice (user)
- `x` random string (secret message), corresponds to point `Y` on curve
- `r` private key (blinding factor)
- `T` blinded message
- `Z` proof (unblinded signature)

# Blind Diffie-Hellmann key exchange (BDHKE)
-   Mint `Bob` publishes `K = kG` 
-   `Alice` picks secret `x` and computes `Y = hash_to_curve(x)` 
-   `Alice` sends to `Bob`: `T = Y + rG` with `r` being a random nonce
-   `Bob` sends back to `Alice` blinded key: `Q = kT` (these two steps are the DH key exchange)
-   `Alice` can calculate the unblinded key as `Q - rK = kY + krG - krG = kY = Z`
-   Alice can take the pair `(x, Z)` as a token and can send it to `Carol`.
-   `Carol` can send `(x, Z)` to `Bob` who then checks that `k*hash_to_curve(x) == Z`, and if so treats it as a valid spend of a token, adding `x`  to the list of spent secrets.

## 0.1 - Models

### `BlindedMessage`
A encrypted ("blinded") secret and an amount sent from `Alice` to `Bob`.

```json
{
	"amount": int,
	"B_": str
}
```

### `BlindedSignature`
A signature on the `BlindedMessage` sent from `Bob` to `Alice`.

```json
{
	"amount": int,
	"C_": str,
	"id": str | None
}
```

### `Proof`
A `Proof` is also called a `Token` and has the following form: 

```json
{
	"amount": int, 
	"secret": str,
	"C": str,
	"id": None | str,
	"script": P2SHScript | None,
}
```

### `Proofs`
A list of `Proof`'s. In general, this will be used for most operations instead of a single `Proof`. `Proofs` can be serialized (see Methods/Serialization [TODO: Link Serialization])

## 0.2 - Methods

### Serialization of `Proofs`
To send and receive `Proofs`, wallets serialize them in a `base64_urlsafe` format. 

Example:

```json
[
  {
    "id": "DSAl9nvvyfva",
    "amount": 8,
    "secret": "DbRKIya0etdwI5sFAN0AXQ",
    "C": "02df7f2fc29631b71a1db11c163b0b1cb40444aa2b3d253d43b68d77a72ed2d625"
  },
  {
    "id": "DSAl9nvvyfva",
    "amount": 16,
    "secret": "d_PPc5KpuAB2M60WYAW5-Q",
    "C": "0270e0a37f7a0b21eab43af751dd3c03f61f04c626c0448f603f1d1f5ae5a7d7e6"
  }
```

becomes

```
W3siaWQiOiAiRFNBbDludnZ5ZnZhIiwgImFtb3VudCI6IDgsICJzZWNyZXQiOiAiRGJSS0l5YTBldGR3STVzRkFOMEFYUSIsICJDIjogIjAyZGY3ZjJmYzI5NjMxYjcxYTFkYjExYzE2M2IwYjFjYjQwNDQ0YWEyYjNkMjUzZDQzYjY4ZDc3YTcyZWQyZDYyNSJ9LCB7ImlkIjogIkRTQWw5bnZ2eWZ2YSIsICJhbW91bnQiOiAxNiwgInNlY3JldCI6ICJkX1BQYzVLcHVBQjJNNjBXWUFXNS1RIiwgIkMiOiAiMDI3MGUwYTM3ZjdhMGIyMWVhYjQzYWY3NTFkZDNjMDNmNjFmMDRjNjI2YzA0NDhmNjAzZjFkMWY1YWU1YTdkN2U2In1d
```