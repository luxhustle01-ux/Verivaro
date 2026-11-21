# G1 HTTPS witness recovery and failure-injection evidence — 21 November 2026

**Scope:** Engineering acceptance tests for an isolated, simulated HTTPS witness endpoint and real disposable local checkpoint files. No external witness or real credentials were used. This is *not* proof that the remote service is independently administered or that its CAS is power-loss durable.

## Integrated acceptance matrix

`tests/unit/provider-checkpoint-https-recovery.test.mjs` exercises the production-shaped witness HTTP client, the real file-backed checkpoint store, the actual signed-keyset verifier and ephemeral local mutual-TLS certificates:

| Fault scenario | Required outcome |
| --- | --- |
| Successful local/remote witnessed rotation | Both checkpoints advance to the signed second keyset; old key no longer authenticates before or after restart |
| Restore earlier local checkpoint | Existing witnessed second checkpoint rejects startup; no fallback to first keyset |
| Remote read network partition | Request aborts on deadline; active verifier permanently denies until supervised restart |
| Partition after remote CAS commit but before ACK | Rotation faults; local remains old; remote may be ahead; restart with old local checkpoint denied; no silent retry |
| Remote ACK received, local commit fails | Remote ahead, disk old; all authentication denied; restart mismatch requires reconciliation |
| CAS conflict and stale witness read | Conflict faults rotation; fresh identical checkpoints can be supervised-restarted; a subsequent stale remote read faults verification |

The tests use the actual HTTPS request path and real local checkpoint store, **not** the in-memory witness used by prior tests. The simulated remote CAS itself is process memory and does not emulate cross-host coordination, power-loss or cryptographic custody.

## Safety properties and unresolved risks

- **Safe failure over continuity:** A checkpoint mismatch means login is unavailable. Do not automatically copy the higher sequence into the lower checkpoint, replay a timed-out CAS or accept an old signed catalogue. A remote acknowledged write may have happened when the response never reached the client.
- **Operator recovery procedure (not automated):** halt authentication and rotation; preserve local checkpoint directory, signed catalogues and logs; independently inspect the authoritative witness and its durable audit trail; validate sequence, digest and signing-key continuity; obtain two-person approval for a documented restore/re-provision; confirm witness and local checkpoints agree before restarting the verifier; retain incident evidence. All steps require appropriate production governance and authorisation.
- **Security boundary:** Mock server advertises `linearizable` and `committed`, but these are *unverified self-assertions*. An independently administered durable witness, mTLS credential custody, CAS compare/commit semantics under concurrent writers, replay protection, external auditability, proper HA and geographic failure-domain isolation remain open.
- **Operational metrics to collect before approval:** p50/p95/p99 HTTPS read and CAS latency, transport socket counts, timeout and overload rates, login rejection during partition, CAS conflict incidence, reboot recovery elapsed time, partition and storage-rollback outcomes, witness audit-trail completeness.
- **Release restrictions:** review PR #4 remains draft and unmerged; no production rollout, key handling, paid infrastructure or new external system has been authorised.

**Qualification:** Only CI results tied to the exact commit containing these tests are valid. Read that run's terminal status before declaring the scenarios passed.
