
`Alice` receives public keys from mint `Bob` via `GET /keys` and stores them in a key-value store like a dictionary. 

`Bob` responds with his **active** keyset [TODO: Link #2]. Note that a mint can support multiple keysets at the same time but will only respond with the active keyset. See [TODO: Link #2] for how a wallet deals with multiple keysets.

Keysets are received as a JSON of the form `{<amount_1> : <mint_pubkey_1>, <amount_2> : ...}` for each `<amount_i>` of the amounts the mint `Bob` supports and the corresponding public key `<mint_pubkey_1>`, that is `K_i` (see #0). 

## Example

Request of `Alice`:

```http
GET https://mint.host:3338/keys
```

With curl:

```bash
curl -X GET https://mint.host:3338/keys
```

Response of `Bob`:

```json
{
  "1": "03a40f20667ed53513075dc51e715ff2046cad64eb68960632269ba7f0210e38bc",
  "2": "03fd4ce5a16b65576145949e6f99f445f8249fee17c606b688b504a849cdc452de",
  "4": "02648eccfa4c026960966276fa5a4cae46ce0fd432211a4f449bf84f13aa5f8303",
  "8": "02fdfd6796bfeac490cbee12f778f867f0a2c68f6508d17c649759ea0dc3547528",
  ...
}
```