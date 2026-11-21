# G1 external publisher reference — serialized signed CAS and uncertain ACK recovery

**Engineering-only fixture, 21 Nov 2026.** No remote service, production signing keys, dedicated independent administrative authority, or externally published freshness floor has been deployed.

The optional `src/security/provider-witness-publisher-reference.mjs` module implements the injected `anchor.read` / `anchor.compareAndSwap` contract previously exercised only with an in-memory fake. It persists a **single canonical signed receipt** to a private reference directory with one exclusive process lock, strict no-symlink and ownership checks, and temporary-file fsync + atomic rename + directory fsync before returning acknowledgement. Signatures are verified against a separately provided trusted Ed25519 public key. An injected `signStatement(bytes, statement)` callback is only a *reference signing capability*: a real signer must verify journal continuity independently and retain custody outside the witness process.

On startup, the publisher requires an independently supplied `{count,headHash}` floor matching the signed receipt **exactly**. It refuses an older, newer or forged state. A safe CAS conflict or invalid transition rejects without changing the receipt; 16 simultaneous contenders produce at most one successful write. An uncertain signer or persistence error faults the publisher and leaves the lock for manual reconciliation. A successful receipt replacement does **not** automatically update the external freshness floor.

`tests/unit/provider-witness-publisher-reference.test.mjs` connects the real on-disk witness journal, the receipt-guarded verifier and separate file-backed reference publisher. The tests cover successful paired publication/restart, concurrency, replay/fork/rollback rejection, competing writer lease, stale/truncated receipt snapshots, signer outage, and remote committed publication with its ACK deliberately discarded.

**Limitations and explicit release gates:** The publisher is on the same CI host as the journal and its temporary signer and thus is NOT independent anti-rollback custody. The file snapshot is not a replicated, append-only audit transparency log. No off-host floor publication, hardware-backed keys, cross-region atomicity, authorization policy, anti-split-brain protocol, hostile-local-admin resilience, or real crash/power-loss qualification is demonstrated. A privileged operator who controls the journal, publisher receipt, signer and trusted floor can still roll everything back. No automatic replay, repair or head promotion is allowed after an uncertain publication. A real production design requires independent publisher governance, durable quorum storage, separately controlled public-key trust anchors, authenticated monotonic floor custody, independent review and owner authorization. PR #4 remains draft and unmerged.

## Deadline, cancellation and crash-injection qualification (21 Nov 2026)

The publisher now accepts \`signerTimeoutMs\` (default 3000 ms, range 25–30000).
It invokes \`signStatement(bytes,statement,{signal})\` with an AbortSignal and
caps the application's await even for an uncooperative signer. Optional
\`compareAndSwap(request,{signal})\` propagates caller cancellation through
the signing boundary. An uncertain signing result latches fail-closed; a late
signature cannot be persisted by the publisher after the caller has failed.
The remote signer itself must also honour abort, enforce its own resource
limits, and never treat cancellation as permission to retry an ambiguous act.

Test-only \`enableTestFaultInjection:true\` plus \`faultInjection(phase)\`
supports \`after-temp-fsync\` and \`after-rename\` injection; it MUST NOT be
configured in any deployed workload. The tests include a separate Node
process exiting after the receipt rename but before the parent-directory
fsync, demonstrating an uncertain commit with an abandoned writer lock.
Visible receipt bytes after an ordinary process crash are **not proof of
power-loss durability**. A second process also attempts and is denied the
exclusive writer lease. Signer-timeout, caller-abort, and malformed-client
negative cases are covered. Safe pre-persistence malformed submissions
reject without poisoning a healthy publisher. Only a supervised, independently
verified operation may clear an abandoned lock; no auto-recovery path is added.


## Late signer, filesystem race and read-only recovery qualification

An adversarial test resolves a valid signer result AFTER its configured
deadline. The publisher must never persist it. The reference publisher
also refuses to start when pending receipt files, unexpected files or
a previous writer lock remain. Active operations recheck the private
directory identity, lock inode, and pre-existing receipt inode
immediately before rename. Same-content inode replacement and symlink
substitution are injected as negative cases. These checks narrow
opportunistic filesystem races but cannot eliminate time-of-check versus
time-of-use gaps, and cannot resist a privileged hostile local operator.

The read-only inspectReferenceWitnessReceiptRecovery API verifies an
independently trusted signed receipt and exact external freshness floor
and inventories any writer lock or orphan pending files. Every result
is MANUAL_REVIEW_REQUIRED, including a clean-looking directory. It does
not determine whether a lock belongs to a live process and never deletes
or promotes anything.

Required supervised procedure: (1) isolate authentication/writer traffic,
preserve local receipts, pending files, locks, journal and process logs;
(2) obtain signed external receipt, trusted public key and monotonic
freshness floor from independent custodians; (3) cross-check scope,
signatures, journal chain, latest sequence and checkpoint against the
external authority, explicitly accounting for a possible remote commit
with lost acknowledgement; (4) obtain two-person documented approval for
specific maintenance, rather than automatically reusing stale signing
keys, truncating files or deleting locks; (5) independently attest the
reconciled state and only then resume in fail-closed mode. Real power-loss
and multi-host integrity claims remain unverified and require external review.
