# G1 signed transaction context — reviewed implementation

**Status:** Candidate code and synthetic CI tests exist. Independent production approval remains open.

The `0003_signed_context.sql` migration supersedes the insecure caller-identity policies in migrations 0001/0002, and `0005_identity_sessions.sql` adds authenticated session registration, expiry and revocation. Applying the full migration chain before any runtime access is mandatory. Unsigned legacy `verivaro.tenant_id` and `verivaro.actor_id` settings do not authorise database operations.

The trusted service verifies an identity token, including issuer and audience, then uses an out-of-band 32-byte HMAC key to create a signed short-lived context for the actual pooled connection's PostgreSQL backend PID and transaction ID. The database verifies this using its private key table and the live session record. No production default key or runtime SQL signing endpoint exists; `verivaro_private.ci_sign` is a disposable test fixture only. Do not log tokens, contexts or keys.

The application acquires a dedicated least-privilege connection, clears prior session state, confirms login privileges, begins READ COMMITTED, sets statement/lock timeouts, obtains its transaction-bound challenge, signs the verified token and sets the signed context using a parameterised `set_config(...,true)` call. It checks membership through RLS and either commits and clears state or rolls back and destroys an unsafe lease. `tests/integration/live-pool.test.mjs` verifies real PostgreSQL driver pool reuse, cancellation, tenant isolation and session revocation with synthetic data; this supersedes earlier mock-only status language.

Remaining: production key/HSM custody and rotation runbooks, real trusted provider configuration, supervised service transport, operational credential replacement, independent code/penetration review, scalability tests and release approval. A compromised signer or database administrator is outside the unprivileged SQL attack model. Passing CI is not production certification.
