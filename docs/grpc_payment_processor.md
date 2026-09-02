# External gRPC payment processors

Nutshell can use payment processors implementing CDK's
`CdkPaymentProcessor` gRPC protocol. The built-in adapter is named
`GrpcPaymentProcessor`; no Python payment plugin needs to be installed on the
mint host.

Configure one backend for each payment method and unit:

```env
MINT_PAYMENT_BACKENDS='[
  {
    "type": "GrpcPaymentProcessor",
    "method": "examplepay",
    "unit": "sat",
    "endpoint": "processor.internal:8090",
    "tls_dir": "/run/secrets/payment-processor"
  }
]'
```

The TLS directory uses the same file names as CDK mintd:

- `ca.pem` verifies the payment processor.
- `client.pem` identifies the mint.
- `client.key` is the mint's client private key.

Individual `tls_ca`, `tls_cert`, and `tls_key` paths can be used instead.
`tls_server_name` is available when the certificate name differs from the
network endpoint.

For a local or otherwise separately protected connection, plaintext must be
enabled explicitly:

```env
MINT_PAYMENT_BACKENDS='[{"type":"GrpcPaymentProcessor","method":"examplepay","unit":"sat","endpoint":"127.0.0.1:8090","allow_insecure":true}]'
```

Plaintext has no transport authentication or encryption and should not be used
over an untrusted network.

The adapter implements CDK payment-processor protocol version `4.0.0` and sends
the required `x-cdk-protocol-version` metadata. A protocol version mismatch is
rejected by the CDK server.

CDK's payment-processor protocol does not expose a backend balance. Nutshell
therefore skips the balance watchdog for `GrpcPaymentProcessor` backends while
continuing to run it for backends that report balances.

To serve `bolt11` through gRPC, remove all legacy
`MINT_BACKEND_BOLT11_<UNIT>` settings. A payment method cannot currently mix
in-process and gRPC transports across units. Nutshell rejects ambiguous
configurations instead of silently replacing an in-process backend.

Python entry-point payment plugins remain supported. A given method/unit pair
must be supplied by exactly one in-process plugin or gRPC processor.
