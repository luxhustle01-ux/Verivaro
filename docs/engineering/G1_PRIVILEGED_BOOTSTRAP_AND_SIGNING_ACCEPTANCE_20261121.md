# Verivaro G1 — privileged bootstrap, existing-install reconciliation and independent signing

**21 November 2026 | Reference package only | NOT APPROVED for production**

The 63 locked SQL migrations cannot be run unchanged by a no-CREATEROLE executor: **21** exact `CREATE ROLE` statements are embedded in versions 0004, 0006–0008, 0010–0016, 0018–0019, 0021, 0023–0024 and 0031. Version 0003 installs the `pgcrypto` extension into a private schema. The source migrations and their locked SHA-1 Git blob fingerprints are not edited; SHA-256 is separately used for attested source and transformed-byte digests.

## Fresh-install change-control procedure (requires independent DBA authorisation)

1. Freeze an exact Git commit and produce the **unsigned** release source manifest. Independently verify the exact 63 migration source files, the audited source-path order, and SHA-256 ledger head. Generate and independently review the deterministic 63-file role-reconciliation plan from `src/security/legacy-role-reconciliation.mjs`. No arbitrary SQL patch or runtime regex substitution is permitted.
2. A DBA inventories the PostgreSQL 16 **cluster-global** role namespace and confirms **none** of the 21 service roles already exists. A role collision is a hard stop, not permission to reuse or alter it. Verify dedicated database isolation, backups, current ownership, exact PostgreSQL version and compatibility.
3. Under independent two-person approval, the DBA applies the fixed reference `db/security/privileged-service-role-bootstrap.sql` **once** under a dedicated privileged provisioner. All 21 service roles are NOLOGIN, NOSUPERUSER, NOINHERIT, NOCREATEROLE, NOCREATEDB, NOREPLICATION and NOBYPASSRLS.
4. Independently create the three role boundaries in `db/security/production-migration-roles.sql`: NOLOGIN schema owner, NOLOGIN migration executor with **SET-only** membership in the schema owner, and an independently owned NOLOGIN ledger custodian. The application runtime must not be a member. Provision separately approved, short-lived migration login identity outside the repo; never use the application runtime or PostgreSQL superuser as the unattended migrator.
5. A privileged DBA must explicitly scope `CREATE` on **only the dedicated target database** for the schema owner, and attest the PostgreSQL 16 trusted `pgcrypto` extension install policy. Owner membership and database CREATE cannot be granted globally or to application roles. The executor requires only the permissions needed to read/append the restricted ledger; it must not own the ledger or have UPDATE/DELETE/TRUNCATE/role-creation privileges. A pre-existing legacy or extension object must be inventoried, never silently adopted.
6. Apply **transient, deterministic transformations** (replace exactly the 21 pre-approved role-creation statements with inert comments), **only** after independent source and plan attestation. Preserve original migration SHA-256 and separate transformed SHA-256 in the approval bundle. In each transaction, lock, check all ledger history, explicitly SET LOCAL ROLE to the schema owner for SQL DDL, then to executor for a single ledger INSERT, and COMMIT atomically. Any drift, missing role, unexpected SQL, failed statement or version gap must terminate the change; do not mark the version applied.
7. Run the read-only reference `db/security/verify-installed-migration-state.sql` for a supplementary role/version check, and **separately** reconcile all 63 ledger version/path/source SHA-256/previous-hash/entry-hash values against the externally authenticated manifest. A count of 63 alone is NOT a sufficient reconciliation. Compare privileges, live object ownership, verified backup/restore, real application role separation, exact source/transform digests, and externally retained monotonic release witness.
8. Obtain an independently signed acceptance decision before any production rollout or business/customer claims. A private key or signature is never created automatically by CI.

**The above is a procedure, not a runnable approved production command.** A real database, live IdP, secrets, TLS and signing custody are not available to CI. The reference plan deliberately contains no production `apply` command.

## Pre-existing database: non-destructive reconciliation

An existing database must **not** run the role bootstrap, drop roles, rerun old SQL, reconstruct missing history based on current schema, or issue synthetic approvals. Freeze an immutable backup and inventory schema owners, role grants, extensions, database identity, service roles, and complete migration ledger. Require byte-for-byte comparison of all 63 recorded rows against the independently signed, exact source history and chain head; `assertExistingInstallReconciliation` fails on missing/altered rows, unexpected role privileges and missing approval. Its `approvedExistingInstall` argument is **operator input, not cryptographic proof of approval**, and its return always says `productionApproved:false`.

If a ledger was not originally stored, cannot be authenticated, or service-role/object ownership differs, stop and escalate for a separately signed forensic/backfill plan and explicit DBA authorisation. Never retroactively invent migration dates or quietly rewrite legacy history. A dual-signature **release source** approval also does not prove the past database actually ran those sources.

## Independent signing acceptance process

The machine-readable register at `docs/engineering/G1_INDEPENDENT_SIGNING_ACCEPTANCE_20261121.json` begins with **all nine acceptance requirements NOT_VERIFIED**. No external identities, trusted keys, approvals or witness receipts are represented as available.

- An owner and **genuinely independent human reviewer** must hold distinct Ed25519 private keys outside the repository and GitHub Actions; the policy public keys and minimum monotonic release sequence must be authenticated and pinned through a separate channel.
- The release manifest must bind exact Git SHA, 63 original migration files, additional privileged bootstrap and signing control files, SHA-256 byte hashes, and the expected **source** ledger head. Its `productionApproved` flag remains false. Generate it only from a controlled clean checkout.
- For each signature, sign the domain-separated exact canonical manifest bytes using Ed25519, and verify with `scripts/migration-release-cli.mjs verify`. The tool checks out-of-band policy digest, unrevoked owner and independent-reviewer key roles, signatures, sequence floor, files and Git HEAD. Signing alone does not turn on deployment.
- Independently witness the release sequence and DB ledger head in access-controlled, rollback-resistant storage; attach identity/custody records, DBA operator approval, negative test evidence, archive hashes, recovery drill receipts, and separate final reviewer acceptance. Require the reviewer to check actual signer separation, key rotation, role inventory, live credentials/TLS and change-control records.
- Any missing evidence, mistaken key/policy, signer conflict, stale floor, dropped ledger row, unverifiable legacy history, privilege escalation, or database state mismatch **blocks**. There is no fallback to single signer, auto-backfill or superuser migrations.

## Zero-spend synthetic rehearsal

`scripts/rehearse-privileged-migration-reconciliation.mjs` is **CI-locked** to the fixed throwaway PostgreSQL database, creates an independent disposable database, 21 cluster-global service roles and separate schema-owner/executor/ledger-custodian/login principals with an ephemeral password, exercises the exact 63 role-reconciled SQL migrations with an actual non-superuser connection, verifies the full original-source ledger and rejected grants, then drops the isolated database and roles. It must not be used in production.

`scripts/rehearse-migration-signing-acceptance.mjs` uses **only ephemeral in-memory keys**, makes an unsigned manifest from the real checkout, verifies both signatures through the offline API and rejects wrong pin, missing reviewer and duplicated signature. It does not generate a real approval.

**Status:** `G1_TENANCY=PARTIAL_CI`; `productReleaseApproved=false`; no deployment, merge, spending, automatic privileged provisioning or independent signoff. A separately audited deployment implementation and change-control decision remain outside this reference package.


## Additional existing-schema staging upgrade rehearsal

The restricted-login CI fixture now constructs a **second, separate PostgreSQL 16 database** with all original locked migrations 0001–0062 applied under the restricted executor. It seeds a synthetic tenant record, then makes a PostgreSQL physical template clone. Only the clone undergoes the final version-63 migration.

On the clone, a **separate privileged CI test controller** verifies the exact staging database, restricted session login, active backend PID and post-ledger-insert barrier; it then terminates **only that disposable PostgreSQL backend** before COMMIT. The restricted migrator is never granted pg_signal_backend or equivalent privileges. It verifies that the history still contains only 62 records, the version-63 correction table is absent, and the synthetic tenant fingerprint is unchanged. A fresh session safely applies version 63, verifies all 63 source-bound hashes, replays version 63 without creating duplicate history, and confirms that the original version-62 database remains unmodified. Restricted ledger UPDATE and DELETE privileges remain denied. All databases and scratch cluster-global roles are dropped at fixture completion.

This is a **production-shaped, isolated CI upgrade/recovery proof**, not a live production-equivalent environment. It has no real deployment keys, customer dataset, real production topology, multi-node failover, active API workloads, connection pooling stress, backup operator custody, remote witness or independent DBA approval. Actual staging verification must repeat the authorised migration under separately controlled production-like identity and network boundaries, using approved scrubbed or synthetic representative data, real app compatibility checks, monitored lock budgets, rollback decision points and independent change review.

The browser CI now executes browser test files sequentially with an explicit per-file failure watchdog; the previous Chromium run exhausted its five-minute workflow step and did not pass. Browser tests remain blocking and are **not** skipped.

Independent review acceptance cannot be self-attested: all nine externally controlled evidence requirements in the machine-readable register remain NOT_VERIFIED until specific dated, independently authenticated evidence is reviewed.


## Role-bootstrap input hardening

The CI-only bootstrap SQL generator compares every supplied service-role name in order with the independently frozen 21-name audited inventory, checks the fixed G1 ledger baseline, and derives SQL identifiers from its audited constants rather than caller-provided strings. The 63-migration and service-role plan arrays are immutable. Existing-install role snapshots require explicit `unexpectedMembership:false` for each service role; unknown membership states and malformed SHA-256 strings fail closed. Adversarial tests cover fabricated names containing SQL injection, reordered names, forged ledger heads, attempted plan mutation and incomplete inventories. This does not substitute for a real independent DBA approval.


## G1 production role-snapshot policy hardening (draft-only)

The read-only \`validateRoleSnapshot\` policy in \`src/security/migration-role-policy.mjs\` now requires explicit database-catalogue observations for **four distinct principals**: NOLOGIN schema owner, NOLOGIN migration executor, NOLOGIN ledger custodian and NOLOGIN application runtime. For each principal the caller must supply Boolean values for superuser, CREATEROLE, CREATEDB, REPLICATION, BYPASSRLS, INHERIT, LOGIN and database CREATE. The schema owner alone may have CREATE on the dedicated database; missing/null/unknown values reject.

A complete **inbound and outbound** membership inventory is required, rather than a caller-supplied \`canExecutorSetOwner\` Boolean. The only approved principal-to-principal edge is executor **SET-only** membership of schema owner, with \`INHERIT FALSE, SET TRUE, ADMIN FALSE\`. Creator ADMIN grants, runtime memberships, additional ledger-custodian grants, omitted edges or ambiguous grant options reject. This strict static check assumes the operator's inventory covers all edges touching those four protected principals; the validator itself cannot prove the completeness or independent authenticity of the inventory. In PostgreSQL 16/Neon, even a correct NOLOGIN role can have an administrative owner-side membership, so actual catalog queries and a separate DBA judgement remain required.

The policy returns \`productionApproval:false\` and \`independentlyWitnessed:false\` even for compliant synthetic input. This change does not create/change Neon principals, grant privileges, apply migrations, sign releases or replace human security review. Historical tests that asserted only \`canExecutorSetOwner\` must now provide the actual tested grant-options inventory; failure to do so is intentional.
