# G1 anchored witness gate — exact freshness, publication uncertainty, and competing writers

**Status (21 Nov 2026):** Candidate reference coordination only. No independently administered anchor/publisher exists in Verivaro, and no production infrastructure or keys are connected.

`src/security/provider-witness-anchor-gate.mjs` composes the existing local fsynced hash-chain journal with an **injected** independently governed signed-receipt service contract: `anchor.read(scope, {signal})` and `anchor.compareAndSwap({issuer,audience,previous,statement}, {signal})`. The caller supplies the external anchor's trusted Ed25519 public key **and** a separately retained freshness floor `{count,headHash}` from another independently controlled location. Neither the signer nor the floor is automatically provisioned, published, or obtained from the witness's own filesystem.

## Safe ordering and constraints

- Startup verifies the remote receipt signature and exact independently trusted `count` + `headHash` before opening the exclusive local journal writer. The journal is checked against the same pinned head; the remote is re-read under the lock to detect races. A validly signed stale receipt, a newer unapproved receipt, a rolled-back journal, or mismatched state **denies startup**. Operators must independently reconcile state; there is no auto-promotion.
- Per-read verification checks the journal and freshly authenticated remote receipt against the guard's last accepted count, hash, and checkpoint. Remote outage, bad signature, rollback, or inconsistent state latches denial.
- Monotonic CAS first rechecks local and remote state, then commits and fsyncs the journal, then requests external atomic publication with the exact previous signed receipt and new canonical unsigned statement. Publication ACK is independently signature-checked and followed by a fresh remote read **before** returning success.
- If publication fails, times out, is committed without ACK, or a concurrent remote writer advances first, the guard fails closed. No automatic retry, rollback, head promotion, or local repair is attempted. The signed `issuedAt` field is not a trusted timestamp.
- Per-operation I/O deadlines bound application awaits; a real independent publisher must also honour cancellation and make CAS atomic/durable across power loss and network partitions. A timeout during remote publication leaves the commit outcome **uncertain**, not safely rejected.

## Adversarial qualification

`tests/unit/provider-witness-anchor-gate.test.mjs` uses a real private on-disk journal and an **in-memory synthetic signer/publisher** under distinct test-only objects. It covers restart with fresh/old trusted floor, a signed stale receipt, failed publication after local fsync, remotely committed-but-unacknowledged publication, concurrent writers (one success), competing writer lock, out-of-band remote advances, forged signatures and invalid floors.

**Critical unresolved threat:** An adversary able to roll back the journal, external signed receipt **and** trusted floor together can still defeat freshness. A signer key controlled by the witness operator is not independent. Future acceptance requires independent authenticated floor custody with durable monotonic storage, atomic publish, administrative separation, disaster-recovery drills, and external security review. The current reference guard deliberately sacrifices availability on any ambiguity. Keep PR #4 draft and unmerged.

**Admission detail:** A stale client CAS detected *before* any journal or external publication attempt is a safe conflict and does not permanently fault a healthy guard. Any remote uncertainty, local I/O failure, invalid signature or post-write error still latches denial.
