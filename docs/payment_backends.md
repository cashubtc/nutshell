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
the balance watchdog for these backends. Monitor the processor's wallet and
balance independently.

To serve `bolt11` through gRPC, remove the corresponding legacy
`MINT_BACKEND_BOLT11_<UNIT>` setting. A method/unit pair cannot be supplied by
both a legacy backend and a gRPC processor.

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
Use `cashu/payment/base.py` as the authoritative interface for the installed
Nutshell version.

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
