# Verivaro G1 — Neon PG16 staged migrator identity and privilege gate

**21 November 2026 | Reference plan, NOT an executable approval | No migrations authorised**

## Scope and independently observed staging baseline

- Isolated, user-owned **Neon Free** project `verivaro-g1-pg16-staging` in Sydney (`aws-ap-southeast-2`), project ID held in the operator's restricted account configuration; PostgreSQL **16.16**, database `neondb`. The Neon branch happens to be named `production`, but **this is strictly a staging-only project**.
- ChatGPT Neon connector is already pinned to `vv_g1_staging_reader` with single-project, read-only/no-secrets access. A live query confirmed `current_user=session_user=vv_g1_staging_reader`, `NOCREATEROLE`, `NOCREATEDB`, `NOBYPASSRLS`, no memberships, no schema/database CREATE.
- `db/security/g1-neon-staging-preflight.sql` is a standalone **SELECT-only** preflight. Live inspection verified its expected values: 0 collisions with proposed staging migrator roles, 0 Verivaro service roles, 0 application schemas, `pgcrypto` not yet installed, correctly restricted reader and no database/schema CREATE grants. Source/branch identity is verified separately from SQL.
- The database's current administrator `neondb_owner` has `CREATEROLE`, `CREATEDB`, `BYPASSRLS` and `neon_superuser` membership. It must NOT become a Verivaro runtime login or unattended migrator. Neon restricts host-level superuser access.
- No IP allowlist has been configured; project public connections are enabled. A connector-internal `pg_stat_ssl.ssl=false` reading cannot certify the TLS status of the external Neon proxy. An independently verified TLS client and approved network policy are required before production-equivalent staging acceptance.

## Controlled role design (NOT applied)

| Role | Login? | Permissions/relationship |
|---|---|---|
| `vv_g1_staging_reader` | Yes, credential already held by the operator | Existing catalog-inspection role; must retain no role grants, no DB/schema CREATE, no RLS bypass |
| `vv_g1_staging_schema_owner` | No | Owns application objects in dedicated staging DB; explicitly scoped database CREATE only |
| `vv_g1_staging_migration_executor` | No | Can SET ROLE to schema owner, never inherit it; ledger SELECT/INSERT only when separately approved |
| `vv_g1_staging_ledger_custodian` | No | Separately controls ledger schema/table ownership; no membership path from executor or application roles |
| `vv_g1_staging_migration_login` | Yes, initially **without** a password | Short-lived operator-held identity allowed to SET executor only; no direct CREATE, no inherited owner access, no RLS bypass |

All four proposed roles, as well as the 21 frozen Verivaro service NOLOGIN roles, must be inventoried and approved by an independent DBA before provisioning. Role creation affects the PostgreSQL role namespace for the branch; do not assume an isolated app schema makes unrestricted role DDL safe. If existing names collide, **abort**, inventory and reconcile; never silently reuse or change existing roles.

## Reviewable one-time staging bootstrap (reference only)

**Do not paste or run this without a separate, specific staging change approval, operator identity, collision-free preflight, and independently reviewed signed source controls.** This block is a proposal, not a command given to the ChatGPT read-only connector.

```sql
BEGIN;
CREATE ROLE vv_g1_staging_schema_owner
 NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE vv_g1_staging_migration_executor
 NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE vv_g1_staging_ledger_custodian
 NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE vv_g1_staging_migration_login
 LOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
GRANT vv_g1_staging_schema_owner TO vv_g1_staging_migration_executor
 WITH INHERIT FALSE, SET TRUE;
GRANT vv_g1_staging_migration_executor TO vv_g1_staging_migration_login
 WITH INHERIT FALSE, SET TRUE;
GRANT CREATE ON DATABASE neondb TO vv_g1_staging_schema_owner;
COMMIT;
```

This would leave `vv_g1_staging_migration_login` with **no password**, therefore not yet authenticatable. A short-lived secret must be issued through an independently approved secret/custody workflow; do not embed it in source, workflows, ChatGPT, SQL Editor history or issue comments. Any pending credential must be invalidated after the approved test. A migrator must never inherit the owner role. Do not grant the ledger custodian to the executor, login, reader or runtime.

Neon SQL-created roles do not automatically join `neon_superuser`, unlike the default admin mode in its Console/API. However, PG16 role-creation side effects and automatic ADMIN memberships must be **measured**, not assumed. Any creator/operator membership or unforeseen provider-managed grant detected by the post-bootstrap audit is a hard stop requiring reviewer disposition; **do not weaken the validator to make it pass**.

## Independent, read-only privilege checks

1. **Before provisioning**, execute `db/security/g1-neon-staging-preflight.sql` as the currently pinned reader. Pass the single returned row to `assertG1StagingMigrationPreflight` from `src/security/g1-neon-staging-role-policy.mjs`. The validator requires PG16, `neondb`, the restricted observer, no collisions, no migrated objects, and no reader escalation. It returns `migrationAuthorized:false` even when clean.
2. **After separately authorised bootstrap**, execute `db/security/g1-neon-staging-role-audit.sql` as the reader. Pass its returned `roles` and `memberships` arrays to `assertG1StagingMigrationRoleAudit`. Required role attributes: only reader and migration login may LOGIN; all five must be NOSUPERUSER, NOINHERIT, NOCREATEROLE, NOCREATEDB, NOREPLICATION, NOBYPASSRLS, and not members of `neon_superuser`. Database CREATE is restricted to schema owner, never to the reader, executor, custodian or migration login.
3. The **only two permitted role grants** touching the staged identities are `executor SET owner` and `login SET executor`, with `INHERIT FALSE`, `SET TRUE`, `ADMIN FALSE`. Unexpected outbound/inbound grants (including a provisioner retaining membership) or unknown catalog fields fail closed.
4. The reader currently inherits PostgreSQL's database TEMP privilege through PUBLIC. It cannot create permanent objects under the tested grants, but do not call it incapable of temporary writes. Review TEMP hardening separately; do not revoke PUBLIC privileges without impact analysis and independent approval.
5. Test a real short-lived, authenticated migrator session from an approved external TLS client: verify certificate/hostname, operator/DB identity, `SET ROLE` without INHERIT, and independently captured denied `CREATEROLE`, owner membership to reader/runtime, schema CREATE under the login, ledger UPDATE/DELETE/TRUNCATE, and forbidden role membership pathways. Merely querying `has_*_privilege` is not a substitute for denied-action tests.
6. Reconcile the 21 source-locked service roles, `pgcrypto` install boundary, schema ownership and ledger custodian separately. Do not write, sign, backfill or apply any of the 63 migrations until external source signatures, DBA signoff, and a witnessed plan are present.

## Observed owner-side ADMIN membership — strict gate blocker

The actual SELECT-only `pg_auth_members` catalog audit also found an **incoming** edge on the already-created reader:

```text
member_role=neondb_owner
granted_role=vv_g1_staging_reader
inherit_option=false; set_option=false; admin_option=true
```

This does **not** give the reader administrative rights or allow `neondb_owner` to SET the reader role through this edge. It gives the privileged owner a role-management grant. PostgreSQL 16 role creation can assign the creator an ADMIN-option membership; the observed edge is consistent with that model. Previous checks reporting the reader has **zero outbound memberships** remain true, but they did not evaluate inbound role-management grants.

**Policy:** The post-bootstrap audit checks *both inbound and outbound memberships* and currently fails this strict independent-custody requirement. Proposed additional staging roles may similarly accrue operator ADMIN memberships when created. Before approval, the independent DBA must inventory and assess every owner-side ADMIN edge, determine whether explicit member removal is permitted/safe in this managed environment, and document any irreducible administrator override. Never auto-revoke or bypass this gate to force a pass. Even after any permitted cleanup, Neon's overarching account administrator retains an emergency override capability; independent release-signing and external witness custody are separate requirements.

## Explicit release blockers

- No independent human reviewer, signed source baseline, out-of-band Ed25519 trust anchor, separate retained witness/ledger custody, verified remote TLS/network security, or approved production-equivalent recovery drill.
- The default Neon owner remains an administrative override principal. All roles in one managed project cannot by themselves prove independence from its operator; external key and witness custody remain mandatory.
- No temporary write-capable Neon connector access or real migrator login has been authorised by this preparation document. Keep ChatGPT on the scoped read-only reader; explicitly approve **each narrowly scoped external staging operation** later.
- All nine requirements in `G1_INDEPENDENT_SIGNING_ACCEPTANCE_20261121.json` remain `NOT_VERIFIED`, `G1_TENANCY=PARTIAL_CI`, and `productReleaseApproved=false`. No merges, deployments, spending, customer data or migrations.

## References

- `db/security/production-migration-roles.sql` (production reference, never auto-execute)
- `db/security/privileged-service-role-bootstrap.sql` (21 locked source service roles)
- `src/security/legacy-role-reconciliation.mjs` (63-file audited source reconciliation)
- `docs/engineering/G1_PRIVILEGED_BOOTSTRAP_AND_SIGNING_ACCEPTANCE_20261121.md`
- Neon: https://neon.com/docs/manage/roles ; https://neon.com/docs/manage/database-access ; https://neon.com/docs/ai/neon-mcp-server
