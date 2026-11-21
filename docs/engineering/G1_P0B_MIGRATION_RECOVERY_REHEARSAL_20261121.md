# P0-B: synthetic PostgreSQL recovery rehearsal

Scope: 21 November 2026; disposable CI only; no production migration authorization.

The PostgreSQL workflow runs `scripts/rehearse-migration-recovery.mjs` after source preflight and before application migrations. It requires an explicit CI marker, fixed loopback PostgreSQL connection, `verivaro_test` and synthetic credentials. Remote connection overrides are refused.

A random synthetic schema exercises a transactional SQL migration with a SHA-256 history row; duplicate replay is skipped. The next migration deliberately fails after creating and inserting a row. CI checks rollback of both its table and history row. A corrected retry succeeds, while a changed digest for an applied version fails closed. The schema is removed after testing.

This does not record production migration history, install the 63 real application migrations through a ledger, simulate process kill/power loss, establish multi-node consensus, or certify operational backups, availability or zero-downtime upgrades. Existing G1 63-file migration and security checks remain unchanged. Migration release requires separate durable ledger integration, approved credentials, backup/recovery tests and independent review. PR stays draft; no merge, deployment or additional spend.
