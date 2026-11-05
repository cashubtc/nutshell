# Payment backends

Nutshell supports three kinds of mint payment backend:

1. Built-in Lightning backends such as `FakeWallet`, LND, and CLN.
2. Python payment-method plugins installed in the mint's Python environment.
3. External processes implementing CDK's `CdkPaymentProcessor` gRPC protocol.

Python plugins and external gRPC processors can be used alongside each other.
Each `(method, unit)` pair must be configured exactly once.

## External CDK gRPC payment processors

The built-in adapter is named `GrpcPaymentProcessor`. The external processor
runs as a separate process; no Python plugin needs to be installed for its
payment methods.

Add one `MINT_PAYMENT_BACKENDS` object for every method and unit that Nutshell
should expose. Methods advertised by the processor are not registered
automatically.

For example, one processor serving Bolt11, on-chain, and Arkoor payments on the
same endpoint is configured as:

```env
MINT_PAYMENT_BACKENDS='[{"type":"GrpcPaymentProcessor","method":"bolt11","unit":"sat","endpoint":"127.0.0.1:50051","allow_insecure":true},{"type":"GrpcPaymentProcessor","method":"onchain","unit":"sat","endpoint":"127.0.0.1:50051","allow_insecure":true},{"type":"GrpcPaymentProcessor","method":"arkoor","unit":"sat","endpoint":"127.0.0.1:50051","allow_insecure":true}]'
```

Keep the JSON on one line when putting it in `.env`. If setting it in a shell,
validate it before starting the mint:

```bash
export MINT_PAYMENT_BACKENDS='[{"type":"GrpcPaymentProcessor","method":"bolt11","unit":"sat","endpoint":"127.0.0.1:50051","allow_insecure":true}]'
python -m json.tool <<< "$MINT_PAYMENT_BACKENDS"
```

`endpoint` and `address` are aliases. A separate `port` can be supplied when
the address does not include one.

### Transport security

Mutual TLS is required by default. A TLS directory uses the same filenames as
CDK mintd:

- `ca.pem` verifies the payment processor.
- `client.pem` identifies the mint.
- `client.key` is the mint's client private key.

```env
MINT_PAYMENT_BACKENDS='[{"type":"GrpcPaymentProcessor","method":"examplepay","unit":"sat","endpoint":"processor.internal:8090","tls_dir":"/run/secrets/payment-processor"}]'
```

Individual `tls_ca`, `tls_cert`, and `tls_key` paths can be used instead.
`tls_server_name` overrides the certificate server name when it differs from
the network endpoint.

For a local or separately protected connection, plaintext must be enabled
explicitly with `"allow_insecure":true`. Plaintext provides neither transport
authentication nor encryption and must not be used over an untrusted network.

### CDK protocol compatibility

The adapter implements CDK payment-processor protocol version `4.0.0` and
sends the required `x-cdk-protocol-version` metadata. The processor rejects a
protocol-version mismatch.

The CDK protocol does not expose a backend balance. Nutshell therefore skips
the balance watchdog for every unit served by a gRPC backend, including legacy
backends sharing that unit. Other units remain monitored. Monitor the
processor's wallet and the affected unit's total backing independently.

To serve `bolt11` through gRPC, remove the corresponding legacy
`MINT_BACKEND_BOLT11_<UNIT>` setting. A method/unit pair cannot be supplied by
both a legacy backend and a gRPC processor.

gRPC mint capabilities are explicit per-backend configuration booleans, all
`false` by default. Enable only the capabilities supported by that method:

- `allows_amountless_mint`: accept mint requests without a fixed amount.
- `allows_partial_mint`: issue less than the available paid balance.
- `allows_repeated_payments`: refresh and credit payments after earlier issuance.

For a reusable BOLT12 offer or onchain address supporting all three, add all
three keys with `true` values to its `MINT_PAYMENT_BACKENDS` entry. A method that disallows
partial issuance can still accept amountless or repeated payments; each mint
operation must consume its full available balance. These capabilities are
independent and are never inferred from an unfamiliar method name.

Each canonical incoming payment request and checking ID must belong to one
mint quote per payment method, across all units and quote states. Reusable
offers or addresses receive further payments on that quote; a backend must
not assign them to another quote. Upgrades stop if legacy quotes already
share either identity, leaving those records intact for operator review.

Only BOLT11 uses the fixed-amount internal settlement shortcut. Other methods
are quoted and paid through their processor even when the destination belongs
to this mint. Onchain melt quotes require an `amount`. BOLT12 amountless melts
accept `options.amountless.amount_msat` (or top-level `amount` in the quote's
unit); the exact millisatoshi amount is retained for payment execution.

When `MINT_REQUIRE_AUTH` is enabled, the default blind-auth paths protect all
`POST /v1/mint/*` and `POST /v1/melt/*` operations, including quote creation and
batch operations, as well as `POST /v1/swap`. Explicitly configured
`MINT_REQUIRE_BLIND_AUTH_PATHS` replace these defaults; include the payment
methods you intend to protect.

### Bark example

The Bark processor can advertise `bolt11`, `onchain`, and `arkoor`. Configure
the processor itself according to its documentation. For example:

```bash
export BARK_PAYMENT_METHODS='bolt11,onchain,arkoor'
export BARK_SERVER_ADDRESS='https://ark.second.tech'
export BARK_ESPLORA_ADDRESS='https://mempool.second.tech/api'
export BARK_NETWORK='mainnet'
export BARK_DATA_DIR="$PWD/.data/bark"
export BARK_MNEMONIC='<processor wallet mnemonic>'
RUST_LOG=info cargo run --release --manifest-path crates/bark/Cargo.toml
```

Then use the three-entry `MINT_PAYMENT_BACKENDS` example above and start
Nutshell:

```bash
poetry run mint
```

The processor's advertised methods and Nutshell's configured methods should
agree. Restricting `BARK_PAYMENT_METHODS` does not change Nutshell's
configuration, and adding a Nutshell backend entry does not enable that method
in Bark.

### Confirming activation

At startup, Nutshell logs one line for each configured pair:

```text
Using GrpcPaymentProcessor backend for method: 'bolt11' and unit: 'sat'
Using GrpcPaymentProcessor backend for method: 'onchain' and unit: 'sat'
Using GrpcPaymentProcessor backend for method: 'arkoor' and unit: 'sat'
```

Also check `GET /v1/info`; its NUT-04 and NUT-05 settings should advertise the
expected methods and units.

## Python payment-method plugins

A Python plugin runs inside the mint process and implements
`cashu.payment.PaymentMethodPlugin`. Only install code you trust: a plugin has
the same filesystem, network, database, and process access as the mint.

### Package entry point

Publish the plugin through the `cashu.payment_methods` Python entry-point
group. A minimal `pyproject.toml` contains:

```toml
[project]
name = "nutshell-examplepay"
version = "0.1.0"
dependencies = ["cashu"]

[project.entry-points."cashu.payment_methods"]
examplepay = "nutshell_examplepay:ExamplePayPlugin"
```

`ExamplePayPlugin` may be either a `PaymentMethodPlugin` instance or a class
with a no-argument constructor. Its `method` should match the entry-point name
and must contain only lowercase letters, digits, `_`, or `-`.

Implement the hooks defined by `cashu.payment.PaymentMethodPlugin`, including:

- `create_backend` to construct a backend from its configuration object.
- Incoming quote creation and status lookup.
- Outgoing quote creation, execution, and status lookup.
- `settings_for` to advertise the method's NUT-04/NUT-05 capabilities.

Optional hooks cover request models, canonicalization, quote expiry, event
streams, MPP, descriptions, lifecycle startup/shutdown, and balance support.
`validate_payment_request` validates a request locally and returns its absolute
expiry before quote creation. `get_payment_checking_id` derives the outgoing
attempt's tracking identifier before sending. Both hooks must avoid network I/O.
The watchdog sums balances by unit and `funding_source_id`. Plugins whose
backend instances report the same reserves must return the same funding source
ID to avoid counting that balance twice. If any method for a unit cannot report
its balance, the watchdog skips comparisons for the entire unit. A failed
balance lookup also skips that check without changing its previous baseline.
Plugins opt into amountless minting, partial issuance, and repeated payments
independently with `allows_amountless_mint`, `allows_partial_mint`, and
`allows_repeated_payments`. Override the corresponding `supports_*` hooks when
these capabilities vary by backend or unit. Internal settlement is also opt-in;
only BOLT11 enables the fixed-amount shortcut by default.
Use `cashu/payment/base.py` as the authoritative interface for the installed
Nutshell version.

Melt quote requests preserve custom fields both at the top level and inside
`options`. A Python plugin can extend `PostMeltRequestOptions` and assign a
custom `melt_quote_request_model` to validate these fields, including rejecting
unsupported options. The gRPC adapter forwards custom nested options under
`extra_json.options` for the processor to validate. Standard `mpp` and
`amountless` options retain their shared validation and dedicated protobuf fields.

Wallet `method_options` add custom top-level fields. Standard request fields
must be supplied through the wallet arguments or quote request model; colliding
option keys raise `ValueError` before the quote or payment request is sent.
`Wallet.melt_quote_for_method` accepts standard `amount` and typed `options` as
keyword arguments. For example, use
`wallet.melt_quote_for_method("onchain", address, amount=10)` or
`cashu pay <address> 10 --method onchain` for an onchain payment quote.

### Install and enable

Install the package into the same environment that runs the mint. During local
development:

```bash
poetry run pip install -e /path/to/nutshell-examplepay
```

Explicitly allowlist its entry point and configure every unit it should serve:

```env
MINT_PAYMENT_METHOD_PLUGINS='["examplepay"]'
MINT_PAYMENT_BACKENDS='[{"method":"examplepay","unit":"sat","api_url":"https://example.test"}]'
```

The complete backend object is passed to the plugin's `create_backend` hook,
so fields such as `api_url` are plugin-defined. Do not put secrets directly in
documentation or source-controlled `.env` files.

Restart the mint after installing or changing a plugin. Startup fails if an
allowlisted entry point is not installed, does not provide a
`PaymentMethodPlugin`, or collides with another provider for the same method
and unit.

## Combining backends

All configured backends share the `MINT_PAYMENT_BACKENDS` JSON array:

```env
MINT_PAYMENT_METHOD_PLUGINS='["examplepay"]'
MINT_PAYMENT_BACKENDS='[{"method":"examplepay","unit":"sat","api_url":"https://example.test"},{"type":"GrpcPaymentProcessor","method":"onchain","unit":"sat","endpoint":"processor.internal:8090","tls_dir":"/run/secrets/payment-processor"}]'
```

Keep exactly one provider for each `(method, unit)`. In particular, do not
configure `MINT_BACKEND_BOLT11_SAT` when a plugin or gRPC processor already
serves `bolt11/sat`.

## Troubleshooting

### Settings fail to parse

`MINT_PAYMENT_BACKENDS` and `MINT_PAYMENT_METHOD_PLUGINS` must be valid JSON,
including double quotes around keys and strings. Validate shell values with
`python -m json.tool` as shown above. A newline inside a quoted JSON string,
such as one accidentally inserted in an endpoint, is invalid.

### Unsupported payment method

Check that the method has a backend entry, the plugin entry point is
allowlisted when applicable, and the external processor advertises the same
method. Confirm the corresponding `Using ... backend` startup log exists.

### gRPC connection fails at startup

Check the endpoint and processor process first. Then verify that either all
three mTLS files are readable or `allow_insecure` is explicitly enabled for a
trusted development connection. Inspect the processor logs for the underlying
error; CDK's gRPC server intentionally returns generic errors for some backend
failures.

### Payments remain pending

Do not retry an ambiguous outgoing payment with new proofs until its status is
known. Check both the mint and processor logs using the quote ID. Preserve the
processor's data directory across restarts because it contains the durable
payment state needed for reconciliation.

## Upgrading payment backends

Back up the mint database and stop all workers before running migrations or the
identity repair tool. First-time upgrades keep historical accounting unchanged:
zero-fee payments alone do not establish whether a settlement was internal.
Databases that already ran an earlier version of this PR should have their
`amount_paid_internal` records checked against their original backend records.
The upgrade does not automatically rewrite these credits or merge funded quotes.

Quote identities are unique per payment method. Bounded SHA-256 identity indexes
support long requests without serializing unrelated quote creation. If an upgrade
reports conflicting identities, run the offline audit:

```sh
poetry run python -m cashu.mint.payment_audit --database "$MINT_DATABASE"
```

The report lists conflicting quote IDs and internal credits to verify. For an
unfunded, unissued quote whose stored identity is incorrect, obtain the correct
identity from its original backend and validate a correction:

```sh
poetry run python -m cashu.mint.payment_audit --database "$MINT_DATABASE" \
  --quote QUOTE_ID --field checking_id --expected OLD_ID --replacement CORRECT_ID
```

This is a dry run. Add `--apply` to make that specific correction. Funded quotes,
quotes with issuance records, and ambiguous histories require reconciliation
with the original backend; the tool refuses to delete or rewrite their balances.

When switching BOLT11 backends, reconcile pending melts and outstanding mint
quotes first. The gRPC adapter accepts legacy 64-character Lightning payment
hashes when the new processor uses the same underlying Lightning wallet. Other
backend-specific identifiers cannot be safely transferred to a different wallet.
Keep the original backend available until those records are reconciled.

## Processor units and availability

The configured unit is the ecash unit. A Lightning processor may report `msat`
while the mint issues `sat`. The adapter converts requests, receipts and fees;
fees round up to the ecash unit and incoming receipts are summed before rounding.
A processor using `sat` cannot represent fractional-sat requests. Unrelated
currency conversions and fiat amountless BOLT12 payments are rejected. An `msat`
ecash configuration also needs an `msat` keyset, for example a derivation path
`m/0'/1'/0'` in `MINT_DERIVATION_PATH_LIST`.

`allow_insecure` accepts JSON booleans only; use `true` exclusively for a trusted
local transport. The default requires mutual TLS. Unary calls have configurable
positive finite deadlines: `rpc_timeout` defaults to 30 seconds and
`payment_timeout` to 120 seconds. Channels use keepalive, and interrupted event
streams reconnect. A payment timeout does not authorize an automatic second send;
its state remains subject to backend reconciliation.

## Amounts, recovery and capabilities

BOLT11 quotes remain single-use. Reusable receiving methods explicitly enable
`allows_repeated_payments`; reusable outgoing offers and addresses use independent
quote and execution identities. `allows_partial_mint` controls partial issuance.
For methods other than BOLT11, observed receipts are retained even when they
exceed a requested amount. A method without partial issuance waits until its
requested amount is covered and then issues the available balance. Partial or
repeated methods can claim subsequent available credit according to their flags.

A non-BOLT11 quote deadline expires the original payment terms, not already
verified receipts: funded credit can still be claimed afterwards. Underpaid
quotes without partial issuance need additional funding or operator-assisted
recovery with the original backend. Use partial issuance for deposit addresses
that need independent recovery of arbitrary deposits. Issuance remains subject
to the configured method limits and mint balance ceiling.

Plugins can supply separate `mint_options` and `melt_options`, directional
`mint_min_amount`, `mint_max_amount`, `melt_min_amount`, `melt_max_amount`, and
enable switches. Shared `min_amount`/`max_amount` remain compatibility defaults.
The mint advertises and enforces the same policy. Legacy BOLT11 sat limits apply
to sat/msat with unit conversion; other currencies use their explicit policy.
Management state changes preserve cumulative receipt and issuance counters.

The CLI accepts `cashu invoice --amountless --method bolt12` (or an omitted/zero
amount for a method allowing it), and polls the quote's available paid balance.
NUT-17 notifications use the standardized BOLT11 and BOLT12 subscription kinds.
Custom methods currently use polling; custom websocket kinds require a separate
protocol extension and are not advertised as supported.

## Authentication compatibility

The default blind-auth patterns include `POST /v1/mint/*` and
`POST /v1/melt/*`, including quote and batch endpoints. Existing explicit operator
lists are retained: update them to cover each newly enabled payment method.
Older wallets that do not send blind-auth tokens to these endpoints need an
upgrade or an explicitly chosen compatible endpoint policy. Review the mint's
advertised authentication settings before enabling additional methods.

Processor extension keys beginning with `_` are reserved for internal persisted
method state and are excluded from public melt quote responses.

Non-reusable methods keep an issued quote terminal. Later receipts remain
recorded for reconciliation with the original backend; only methods explicitly
allowing repeated payments can reopen a fully issued quote.

Python plugins can override `supports_reusable_requests` for outgoing request
reuse independently of incoming accounting. Its default follows the repeated
payment capability for methods other than BOLT11. Earlier development schemas
with overlapping migration numbers are reconciled during the upgrade.
