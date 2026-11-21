# G1 trusted identity — historical defect and implementation contract

**Review status:** Implemented as a candidate and exercised with synthetic real-PostgreSQL CI. Not a production identity certification or independent security assessment.

## Historical finding

The original RLS implementation accepted caller-supplied `verivaro.tenant_id` and `verivaro.actor_id` custom GUCs as identity. This could let arbitrary runtime SQL impersonate another tenant; the failing historical spoof test demonstrated that issue. The original run and its exception remain useful regression history, **not a description of the current branch's permissions**.

## Implemented candidate boundary

- `0003_signed_context.sql` introduces a cryptographically verified signed transaction envelope instead of trusting unsigned GUCs.
- `0004_project_access.sql` enforces tenant/project memberships and explicit operation roles.
- `0005_identity_sessions.sql` binds database authorisation to a registered unrevoked session. Later identity/provider and browser-auth migrations add issuer/subject binding, login challenges and revocation controls.
- `src/security/sign-database-context.mjs`, `scoped-database.mjs` and `service-login.mjs` implement trusted token verification, bounded transaction-scoped use and dedicated service-role checks.
- `db/tests/identity_spoof_gate.sql`, `signed_context_gate.sql`, `adversarial_permissions.sql`, `concurrent_scopes.sh` and `tests/integration/live-pool.test.mjs` exercise the boundary using an actual disposable PostgreSQL instance and real connection-pool driver.

## Mandatory security criteria

1. Arbitrary SQL without another actor's validated token or signing key must not mint their context via custom GUCs, SET ROLE, replay, a different backend, another transaction or a stale session.
2. Signed claims require issuer/audience/expiry checks, live session registration and project membership; access must cease on revocation.
3. Every pooled request uses its own transaction and clears all session state; cancellation, rollback and error must dispose of unsafe leases.
4. SQL functions with SECURITY DEFINER must have qualified, controlled search paths, no PUBLIC EXECUTE and reviewed per-service privileges. Adding an overload of a permitted function name must not bypass the allowlist.
5. No runtime table ownership, BYPASSRLS, migration privileges, signing-key reads or direct membership administration.
6. Production identity provider, certificate and signing-key lifecycle need supervised configuration and independent adversarial review before release.

## Remaining independent acceptance

Current synthetic CI establishes what those tests exercised, not all adversarial threat paths. Privileged DBA access, signer compromise, operational key escrow/rotation, live provider configuration, coordinated revocation, production grants, long-running concurrency, backup/PITR and incident drills remain outside this verification. Keep G1 draft until explicitly approved.
