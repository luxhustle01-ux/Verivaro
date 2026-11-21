# G1 PostgreSQL security boundary — current review

**Status:** Draft engineering implementation verified in disposable PostgreSQL CI. Not independently certified, production-deployed, or cleared for merge to main.

## Historical defect and remediation

The original 18 November 2026 foundation trusted the caller-writable `verivaro.tenant_id` and `verivaro.actor_id` GUCs. That was an impersonation vulnerability, demonstrated by the historical failing identity-spoof gate. **Those GUCs are no longer an authentication source.** Migration `0003_signed_context.sql` replaced that design with an HMAC-verified, backend-PID- and transaction-ID-bound context; migration `0005_identity_sessions.sql` adds a registered, unrevoked, unexpired session identifier. Migrated RLS policies require the signed context and project membership. Old custom GUC settings do not independently grant authorisation.

The service validates a trusted token and signs context for the actual acquired PostgreSQL transaction. The runtime SQL role has no access to the signing key or test-only signer. `src/security/scoped-database.mjs` uses a dedicated pooled login, fixed parameterised SQL, explicit READ COMMITTED, transaction-local signed scope, short timeouts, session cleanup and fail-closed lease destruction.

## CI evidence

- `db/tests/identity_spoof_gate.sql`, `signed_context_gate.sql`, `tenant_isolation.sql`, `adversarial_permissions.sql`, `concurrent_scopes.sh` test missing/forged scope, explicit signed tenant isolation, cross-tenant joins, revoked membership and concurrent operations.
- `tests/integration/live-pool.test.mjs` uses the real PostgreSQL driver and tests physical pooled-connection reuse, cancellation, revocation, error discard and cross-tenant isolation.
- `db/tests/full_security_gate.sql` checks forced RLS on five exposed core tables, least-privilege service roles, restricted SECURITY DEFINER functions and unexpected runtime grants. Its latest review-branch amendment also rejects service-executable function overloads and includes a rolled-back negative fixture.
- `docs/engineering/G1_ACCEPTANCE_REVIEW_20261121.md` records exact-run evidence. Success on a synthetic CI branch is not a production audit.

## Threat model and residual risks

A database superuser, schema owner or compromised trusted signer is outside the unprivileged-runtime SQL threat model; FORCE RLS does not protect against those authorities. A signing-key or service-token compromise still requires incident response and key rotation. Identity-provider configuration, production certificate issuance, key custody, actual deployment grants, administrator access, operational revocation and load behaviour remain to be established independently.

The original insecure migration exists in the historical forward-only chain: **all later migrations must be applied before any runtime role is permitted access.** Do not deploy or expose an intermediate 0001/0002 schema state. No customer data or production infrastructure has been verified here.

## Acceptance and ownership

Preserve drafts until exact-head PostgreSQL, core CI, browser and antivirus verification are green after the final change. Independent security review and G0–G6 release gates remain separate. No merge or deployment without owner approval.
