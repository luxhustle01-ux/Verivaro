# G1 recovery evidence consistency — journal, signed receipt and trusted floor

Engineering-only, 21 November 2026. This is a read-only forensic inspection, not an independent recovery authority, certification, or authorization to restart.

The reference recovery inspector requires separate private witness and publisher directories, issuer/audience, trusted Ed25519 verification key, and an exact monotonic count/head hash floor obtained independently. The code cannot obtain or publish that floor.

It verifies the entire canonical hash-chained journal against the independently supplied head, verifies the signed publisher receipt, and requires matching count, head and checkpoint. Both journal and receipt are inspected twice for detectable concurrent changes. Invalid signatures, stale heads, differing checkpoints, truncated or rolled-back journal records and unexpected journal directory artifacts deny inspection.

A successful comparison always returns MANUAL_REVIEW_REQUIRED, with automaticRecoveryPermitted false. It inventories publisher pending files and both writer locks without changing them. A lock may indicate an active writer, not necessarily an abandoned lock.

Acceptance tests cover matching genesis and advanced states, refusal of stale externally supplied freshness, journal-ahead and publisher-ahead conflicts, signed-but-conflicting checkpoint, forged/wrong-audience receipt, rollback/truncation, locks/pending evidence, unexpected files and invalid configuration.

Important limits: the directory reads are NOT an atomic distributed snapshot. Host-privileged adversaries can race or replace the data; independent signing keys and freshness-floor custody are not implemented. Same-host synthetic tests do not demonstrate power-loss durability or HA fencing. A malicious operator controlling the journal, signing key, receipt and floor can forge apparent consistency. Never automate deletion of locks/pending files, floor advancement or retrying uncertain CAS based on this result.