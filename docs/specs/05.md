# NUT-5 - Melting tokens

Melting tokens is the opposite of minting them (see #4): the wallet `Alice` sends `Proofs` to the mint `Bob` together with a bolt11 Lightning invoice that `Alice` wants to be paid. To melt tokens, `Alice` sends a `POST /melt` request with a JSON body to the mint. The `Proofs` included in the request will be burned by the mint and the mint will pay the invoice in exchange.

`Alice`'s request **MUST** include a `MeltRequest` ([TODO: Link MeltRequest]) JSON body with `Proofs` that have at least the amount of the invoice to be paid.

## Example

**Request** of `Alice`:

```http
POST https://mint.host:3338/melt
```

With the data being of the form `MeltRequest`:

```json
{
	"proofs": 
		[
			Proof,
			...
		],
	"invoice": str
}
```


With curl:

```bash
curl -X POST https://mint.host:3338/mint&payment_hash=67d1d9ea6ada225c115418671b64a -d \
{
"proofs" : 
	[
		{
		"id": "DSAl9nvvyfva",
		"amount": 2,
		"secret": "S+tDfc1Lfsrb06zaRdVTed6Izg",
		"C": "0242b0fb43804d8ba9a64ceef249ad7a60f42c15fe6d4907238b05e857527832a3"
		},
		{
		...
		}
	],
"invoice": "lnbc100n1p3kdrv5sp5lpdxzghe5j67q..."
}
```

**Response** `PostMeltResponse` from `Bob`:

```json
{
"paid": true,
"preimage": "da225c115418671b64a67d1d9ea6a..."
}
```

Only if the `paid==true`, the wallet `Alice` **MUST** delete the `Proofs` from her database (or move them to a history). If `paid==false`, `Alice` **CAN** repeat the same multiple times until the payment is successful.