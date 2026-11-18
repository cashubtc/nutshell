# PostgreSQL proof coordination

PostgreSQL coordinates proof reservations, spending, and release with
transaction-scoped advisory locks derived from each nullifier `Y`. Lock keys
are stable across processes, scoped to the proof table's schema, deduplicated,
and acquired in sorted order. Requests using unrelated proofs can acquire their
proof locks concurrently, including when no pending row exists yet.

The locks follow the existing timeout/retry behavior and are released when the
database transaction commits or rolls back. Pending rows retain reservations
while a payment is in progress; database locks are not held while waiting for
the payment backend. Quote execution leases and database uniqueness constraints
continue to apply. SQLite and CockroachDB retain their existing lock behavior.

Stop all mint and auth workers before upgrading or downgrading this locking
protocol so every worker uses the same coordination mechanism. No database
migration is required.
