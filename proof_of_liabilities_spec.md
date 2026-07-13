# Proof of Liabilities implementation note

Nutshell's experimental Proof of Liabilities (PoL) implementation tracks the
current draft specification in
[cashubtc/nuts#388](https://github.com/cashubtc/nuts/pull/388).

The authoritative protocol text and test vectors live in that pull request.
This repository implements:

- append-only issued and spent Merkle Mountain Ranges with uint64 sums;
- right-to-left peak bagging and sequential leaf indexes;
- synchronized epoch manifests whose global commitment includes both MMR sizes;
- BIP-340 manifest signatures under the mint's NUT-06 master key;
- domain-separated, per-denomination transactional receipts for mint, melt, and
  swap operations;
- sum-MMR inclusion proof endpoints and wallet-side verification; and
- OpenTimestamps submission, upgrade attempts, and the 24-hour pending timeout.

PoL remains experimental while the upstream NUT is a draft. Changes to this
implementation are protocol-sensitive and require maintainer review.
