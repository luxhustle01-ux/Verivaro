# P0-B — Actual 63-file PostgreSQL migration ledger (CI reference)

**21 November 2026 · Synthetic verification only · release approval DENIED**

## Implemented safety contract

The PostgreSQL CI gate applies all 63 existing, byte-locked SQL migrations through `scripts/ci-migration-ledger.mjs apply`, retaining each interleaved application/tenant isolation test. Before touching SQL, the existing repository preflight still validates the exact contents and sequence of all 63 SQL files, their registered Git blob hashes, and the CI commands.

A separate bootstrap creates `verivaro_migration.history` with no privileges granted to service roles or PUBLIC. Each application uses one PostgreSQL transaction and an advisory transaction lock. A SQL guard verifies *all previously recorded rows* against independently recomputed, source-derived SHA-256 file digests and chained SHA-256 record hashes, confirms no missing numbered versions, and rejects an out-of-order or changed migration. An already-applied version is skipped under the same lock. The migration's single leading BEGIN and closing COMMIT are replaced in the transient psql stream so schema changes and the history INSERT commit atomically. The locked source files and hashes themselves are unchanged. Any SQL without exactly one supported transaction envelope or containing psql meta commands is rejected.

After migration 0063, the workflow verifies the 63 persisted rows, exact source digests and chain heads before continuing the final security audit and encrypted backup/restore. The new ledger table also enters the existing application schema restore inventory and row-digest comparison.

The CI-only isolated database `verivaro_migration_restart_ci` applies the real migrations 0001 and 0002. It deliberately kills the PostgreSQL backend *after SQL plus ledger insert but before COMMIT*, verifies that function DDL and version 0002 ledger row were both rolled back, retries 0002 from a fresh process, rejects out-of-order 0003, replays 0001 without duplicating its row, and modifies a committed record to prove that the next application detects checksum-chain tampering. The earlier separate fixture-based rollback rehearsal remains intact.

## Explicit exclusions

This is an **integrated CI database migration ledger**, not a tested production migration executor. The guard deliberately refuses any remote DB, non-test database name or credentials, and cannot apply to a production environment. A privileged PostgreSQL owner can rewrite both the ledger and data or restore an earlier database image; this is a *tamper-detectable check against the reviewed repository baseline*, **not** independent anti-rollback proof or tamper-proof storage. The baseline itself is unsigned. An externally governed, append-only history witness or signed approval would be needed for independent detection of coordinated ledger-and-source rewrites, as would a protected production migrator identity and immutable signed SHA-256 release manifests.

Production migration history/backfill reconciliation, recovery of pre-existing databases, genuine backup/restore and HA crash rehearsals, dual-version application compatibility, real TLS/IdP/key custody, independently scoped least-privilege audit, third-party penetration testing, reviewer and operator approval, and buyer commercial diligence remain **NOT VERIFIED**. All synthetic checks and the 63-row database ledger are necessary but not sufficient for a release. PR #4 stays draft and unmerged; no production credentials or customer datasets are used.

**Release gate:** `G1_TENANCY=PARTIAL_CI`; `productReleaseApproved=false`; no automatic merge, deployment or expenditure.
