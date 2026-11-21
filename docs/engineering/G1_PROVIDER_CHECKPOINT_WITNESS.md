# G1 separately witnessed provider-key checkpoint — candidate integration contract

**Status:** Implemented as an **optional adapter**, with independent synthetic witness-state fixtures. No actual external authority was connected, approved or certified. Neither a local file nor an in-memory mock constitutes an independently protected production witness.

`src/security/provider-checkpoint-witness.mjs` exports `openWitnessBoundProviderVerifier({store,witness,issuer,audience,authorityKey,requiredAcr,catalogue,signature,...})`. The `store` must be the existing single-active-verifier local checkpoint store. The `witness` must be an *independently governed*, durable and atomic source with `read({issuer,audience})` and `compareAndSwap({issuer,audience,previous,next})`; both return a `{sequence,digest}` checkpoint. It must have separate storage, administration, backup, credentials and failure domains. Do **not** implement it as a second file on the same host, unprotected service variable, Git commit, untrusted HTTP response or ordinary database table owned by the signer.

## Enforced invariants

- Startup requires exact equality between local checkpoint and independent witness **before** accepting a signed provider-key catalogue. It rechecks both sources after binding the sole in-process verifier, rejecting races.
- Signed catalogue validation happens before the store is bound. Any rejected signature or stale catalogue cannot claim the verifier lease.
- Every keyset rotation checks the current witnessed checkpoint, then advances witness via independent atomic compare-and-swap *before* writing the local fsynced disk checkpoint. On a crash between commits, the witness is ahead and restart **fails closed**. This is intentional: operational reconciliation is required rather than silent rollback.
- Any indeterminate witness result, CAS error, local storage failure, disagreement or concurrency failure causes the active verifier to deny subsequent token validation. The witness must never claim a checkpoint is durable before it actually is.
- `verify()` is now **asynchronous**, reading both disk and the independently governed witness on **each token verification**. Missing, stale, inconsistent or unreadable witness state permanently denies that verifier until supervised restart. A read racing this process's authorised rotation rejects that token attempt but permits a fresh verification afterward. Production witnesses must deliver strongly consistent reads; availability failures reject authentication. Per-token I/O adds latency and availability dependencies. This remains a **single-active-service** mechanism; it is *not* a multi-node key-revocation protocol.

## Synthetic tests

`tests/unit/provider-checkpoint-witness.test.mjs` uses real disk checkpoints plus a separate in-memory fake witness to simulate external monotonic state. It checks local snapshot rollback detection, restart denial, witness-before-disk ordering, absent/stale witness, a simulated local fsync failure, post-startup external checkpoint advance, witness unavailability and verification/rotation races. This proves application handling, **not** independent custody, durability, Byzantine resistance, networking, failover, TLS, secure clock, power-loss resilience or multi-host consensus.

## Operational acceptance still required

Select and separately authorise a real monotonic witness outside the verifier's security domain; configure distinct nonexportable credentials, atomic compare-and-swap semantics, consistent reads, tamper-evident audit trail, incident recovery, high availability and partition behaviour. Independently test post-crash and restored snapshots before declaring production anti-rollback. A signed provider-key catalogue alone cannot provide monotonicity when both checkpoint and catalogue can be rolled back together.

Keep PR review open and do not deploy, purchase, activate a cloud service, or handle production keys without owner approval.

## Deadline and admission hardening (21 November 2026)

The adapter now accepts `checkpointIoTimeoutMs` (default **5000**, allowed 25–30000 ms) and
`maxConcurrentCheckpointReads` (default **8**, allowed 1–32). Startup, per-token
disk+witness reads, witness pre-rotation reads, monotonic CAS and local checkpoint
commit all have explicit application deadlines. Per-token verification denies
requests beyond the admission limit without faulting a healthy verifier; an
I/O timeout, failed remote read or uncertain persistence faults the verifier
closed. Tests use deliberately never-resolving reads and CAS operations.

The deadline uses an abort signal handed to `witness.read(scope,{signal})`,
`witness.compareAndSwap(request,{signal})` and `store.read({signal})`
(and the local commit). **This bounds the application's await, but does not
prove that an uncooperative transport has closed its socket**: production
adapters MUST enforce their own network connect/read deadlines, observe abort,
cap sockets and outstanding requests across processes, and instrument
latency/error budgets. Late completion after an I/O timeout must not restore a
faulted verifier; operator-led checkpoint reconciliation remains mandatory.
The 5-second default is provisional and requires measured SLO testing.

## Explicit HTTPS witness transport candidate (21 November 2026)

Implementation: \`src/security/provider-checkpoint-https-witness.mjs\` exports
\`createHttpsProviderCheckpointWitness({endpoint,issuer,audience,caPem,clientCertPem,clientKeyPem,requestTimeoutMs,maxInFlight,maxResponseBytes})\`.
It implements the existing witness \`read(scope,{signal})\` and
\`compareAndSwap({issuer,audience,previous,next},{signal})\` contract. This
is a **client transport only**, not an external trusted witness deployment.

- **Fixed target:** explicit HTTPS URI ending at \`/v1/provider-checkpoint\`,
  without query, fragment or user-info; no redirect following, no implicit proxy,
  dynamic target selection or authentication cookies. Public IP-literal targets
  and local addresses are rejected. \`allowLoopbackForTests:true\` permits only
  explicit localhost fixtures and must NEVER be configured in production.
- **Transport identity:** explicit PEM CA trust anchor and client certificate/key;
  TLS peer validation is always enabled and server hostname checking is retained.
  No bearer token, HTTP fallback, global insecure TLS option or system-root
  fallback. Production must configure independent certificate issuance, private
  key custody, expiry alarms, revocation and rotation externally.
- **Request shape:** HTTPS POST with canonical JSON (UTF-8, max 4096 bytes):
  read \`{"version":1,"operation":"read","issuer":"...","audience":"..."}\`;
  CAS adds \`"operation":"compare-and-swap"\`, \`"previous":{sequence,digest}\`,
  and \`"next":{sequence,digest}\`. The witness service must perform an atomic
  scoped, monotonic CAS with no automatic client retries.
- **Response shape:** status 200, JSON content type, \`Cache-Control: no-store\`,
  identity content encoding, and exact canonical JSON:
  \`{"version":1,"issuer":"...","audience":"...","checkpoint":{"sequence":1,"digest":"<64 lowercase hex>"},"consistency":"linearizable","durability":"committed"}\`.
  The implemented client validates exact scope, canonical encoding, strict keys,
  bounded response bytes, checkpoint format and the returned CAS result.
  Non-200, redirects, ambiguous JSON, unexpected claims, oversized bodies,
  closed sockets or missing headers fail closed. Claims of linearizability and
  committed durability are **remote declarations**, not independently proven.
- **Resource limits:** default request deadline **3000 ms** (25–30000 permitted),
  **8** concurrent in-flight transport requests (1–32 permitted), **2048**
  response bytes (256–8192 permitted), with a dedicated bounded HTTPS agent.
  Caller abort, deadline and client close cancel the native HTTPS request/socket;
  a timeout during CAS is an **uncertain commit** and must not be retried or
  treated as a successful rotation. The enclosing verifier permanently faults
  after a read failure or uncertain persistence. Cross-process load limits and
  network saturation still require independently tested infrastructure controls.
- **Unit evidence:** \`tests/unit/provider-checkpoint-https-witness.test.mjs\`
  creates disposable local certificates and a real local mTLS HTTPS server.
  Tests cover read/CAS, conflict, wrong trust CA, rejected unsafe configuration,
  redirects, oversized or ambiguous replies, timeout socket close, concurrent
  admission, caller abort and client shutdown. These are isolated CI fixtures;
  they **do not certify** remote witness availability, anti-rollback resilience,
  certificate governance, HSM/KMS, consistency under partitions, or recovery.
  
### Operational hold

Do not configure an externally hosted witness or move production credentials
under this task. Independent owner authorisation, separate administrative
security domain, atomic and durable server implementation, network policy,
outage drills, recovery procedures, realistic load and an external security
review are outstanding release gates. PR #4 remains draft and unmerged.
