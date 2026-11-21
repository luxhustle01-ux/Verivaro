# G1 context signing-key rotation — controlled operational contract

**Status:** Development contract and synthetic SQL regression only. This is not an implemented zero-downtime production rotator, an incident drill, an HSM integration or a claim of independent review.

## Current design and evidence

The application signer in `src/security/sign-database-context.mjs` uses a 32-byte HMAC key supplied by trusted service provisioning. PostgreSQL verifies with the singleton `verivaro_private.context_key` table in `db/migrations/0003_signed_context.sql` (with session-bound v2 validation introduced by `db/migrations/0005_identity_sessions.sql`). The v2 envelope binds tenant, actor, session ID, backend PID, transaction ID and an expiry no later than 45 seconds. RLS still checks live session and membership. The runtime role cannot read or update the key. A single-key database verifier provides **no concurrent old/new key grace period**, so changing it deliberately invalidates every outstanding signed envelope.

`db/tests/context_key_rotation_gate.sql` is run on an isolated `verivaro_test` CI database. It checks an old envelope works before key replacement, stops authorising after a privileged key update, a newly issued envelope works with the replacement key, and rolling the transaction back restores the fixture. It neither accesses production key material nor changes a production database.

## Planned single-key rotation — operator sequence (NOT automated)

1. Authorise the change, confirm a tested backup and approved rollback/incident plan, and identify all signer instances and database environments. Generate a fresh independent 32-byte key using an approved secrets facility; do not generate, store, email or paste production key bytes into the repository, PR, Linear, or CI logs.
2. Place the service in maintenance/read-only-denial mode. Stop new authentication-context signing; drain or terminate active database transactions and background workers. Confirm no previous signer instance will continue operating against the old key.
3. Through separately authorised privileged database administration, replace the database singleton key and provision the matching new key to **all trusted signer instances**, using protected secret mounting with auditable access. Protect the change window and preserve no plaintext copies in tickets or logs.
4. Start a fresh nonprivileged signer/DB transaction and verify a newly signed envelope is accepted. Verify that an old-key envelope fails, including an old token bound to an otherwise valid session. Check tenant RLS isolation and session revocation. Restore service only after every instance is confirmed on the new key.
5. Retire old signer processes and the retired key material using the deployment's credential-custody procedure. Record the approval, affected instance IDs, audit timestamps, exact application/database versions, outcomes and incident disposition — **never key bytes**.

### Failure and rollback

If DB rotation and signer provisioning become desynchronised, deny traffic rather than returning to unsigned/legacy context. Rollback needs an explicitly authorised restoration of the previous trusted key or a coordinated new replacement plus incident response; neither is offered by the current application code. A pre-existing envelope is still transaction-bound, and its expiry/session/membership checks remain mandatory. Never assume DB ROLLBACK itself provides a production key rollback after the change commits.

### Known blockers

- One-key verification cannot support uninterrupted rolling updates while old and new signers coexist. A zero-downtime mechanism requires an independently designed versioned key ring, safe key IDs, bounded overlap, audit/control plane and an adversarially tested retirement barrier.
- No production KMS/HSM, operational secret distribution, external identity provider, supervised process restart, HA failover or incident recovery was executed.
- Independent security and operational approval are required before any deployment. The synthetic gate only verifies the **database's rejection/acceptance behaviour**, not the real-world rotation procedure.
