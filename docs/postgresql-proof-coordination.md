# PostgreSQL proof coordination

PostgreSQL coordinates proof reservations, spending, and release with
transaction-scoped advisory locks derived from each nullifier `Y`. Lock keys
are stable across processes, scoped to the proof table's schema, deduplicated,
and acquired in sorted order. Each transaction requests its proof keys in one
SQL statement per attempt. Nested operations skip keys the transaction already
holds. Requests using unrelated proofs can acquire their proof locks concurrently,
including when no pending row exists yet.

When a proof key is busy, a new transaction rolls back before retrying. A melt
finalizer that already holds the quote lock keeps its transaction open and
retries the remaining proof keys within the proof-lock timeout. Commit or
rollback releases the locks. Pending rows retain reservations while the mint
waits for the payment backend. Quote execution leases and database uniqueness
constraints continue to apply. SQLite and CockroachDB retain their existing
lock behavior.

Stop all mint and auth workers before upgrading or downgrading this locking
protocol so every worker uses the same coordination mechanism. No database
migration is required.
