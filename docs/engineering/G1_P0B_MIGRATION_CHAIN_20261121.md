# P0-B — PostgreSQL migration-chain source preflight

**21 November 2026 · Unsigned repository drift gate · NOT A PRODUCTION MIGRATION APPROVAL**

## Audited gap and implemented control

The CI PostgreSQL integration test applies **63 separately numbered SQL migrations**, including the tenant isolation/RLS foundations and subsequent identity, evidence, contract, financial and OCR subsystems. It previously maintained a manually enumerated sequence with no checked-in content manifest or automated comparison against every file in `db/migrations/`. A missing, duplicated, renamed or reordered migration could silently change the effective schema test coverage.

The `db/migration-lock.json` register now binds **each file 0001–0063** to its exact Git blob object identifier (Git SHA-1 of `blob <size>\\0<bytes>`), its byte length, number and path. It records the checked repository source baseline and deliberately sets `productionMigrationApproved=false` and `independentlySigned=false`.

`src/security/migration-chain-audit.mjs` verifies the entire directory (including unexpected files), strict four-digit increasing numbering without gaps, no symlinked migration files, exact byte length and Git blob identity. It reads `.github/workflows/postgres-g1.yml` and confirms that the SQL application commands appear **exactly once, in the same 0001–0063 order**. It also checks for the final full-security/role audit after the last migration and requires its own preflight command to be present in the workflow before the first SQL migration.

The PostgreSQL job now invokes `node scripts/verify-migration-chain.mjs` and focused negative unit tests in a separate step **before executing SQL**. Tests demonstrate refusal of tampered, missing, extra and reordered migrations, duplicate applications, unrecognised application commands and false approval declarations.

## Operating rules and remaining risks

A revised or appended migration must receive a separate human review, update this register with the correct new hash and number, and preserve full negative integration tests. Existing production-applied migrations must never be rewritten without an explicit reconciliation/repair procedure. The register is **not itself a signed or separately administered trust anchor**: an actor who can alter both a migration and its manifest can defeat this internal check. Git SHA-1 is repository object identity and is **not equivalent to collision-resistant SHA-256 provenance or third-party software attestation**.

This increment does not track an installed production database's migration history, prevent a privileged DBA from executing out-of-band SQL, audit developer/owner roles outside available synthetic fixtures, provide external IdP/key custody, certify least-privilege on a real hosted service, or prove transaction-safe upgrade/downgrade with user data. A buyer-operated production rollout additionally requires signed and approved SHA-256 release attestations, database-recorded migration status/checksums, an independently controlled migrator role, backups/restores, staged zero-downtime rehearsals, and a post-migration privilege review using actual service credentials.

**Disposition:** P0-B tenant and migration readiness remains `PARTIAL_CI`; `productReleaseApproved=false`. No live database was changed; GitHub Actions uses a disposable PostgreSQL 16 service with synthetic data. No deployment, spending or service integration.
