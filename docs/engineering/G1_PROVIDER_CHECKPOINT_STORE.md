# G1 Provider keyset durable local checkpoint — bounded implementation

The adapter \`src/security/provider-checkpoint-store.mjs\` provides a **single-host, single-active-verifier** checkpoint for the signed provider keyset. It is not a separate trust authority and does not give a cryptographic guarantee against volume snapshot rollback or a compromised owner/superuser.

## Establish trust (operator procedure)

- Provision a dedicated **absolute** private directory owned by the verifier's UID, mode 0700, on a trusted local filesystem with POSIX exclusive creation, atomic rename and fsync guarantees. No directory symlinks. No network/replicated FS or container-ephemeral storage for authoritative use.
- Operator establishes the initial checkpoint from an **independently approved signed catalogue**: canonical UTF-8 JSON with exactly \`version\`, \`issuer\`, \`audience\`, \`sequence\` (positive safe integer) and \`digest\` (SHA-256 lowercase hex); serialize in that order, followed by a single newline, to \`provider-keyset-checkpoint.json\`, owned by the process and mode 0600. The library **does not bootstrap a missing anchor** or accept one from JWT input.
- Call \`openFileProviderCheckpointStore({directory,issuer,audience})\`, then \`openFileBackedProviderVerifier({store,issuer,audience,requiredAcr,authorityKey,catalogue,signature,now})\`. Every startup reopens the checkpoint and checks signed keyset sequence/digest. Caller must close store at planned shutdown.

## Behaviour and limits

- Opening creates \`.provider-keyset-instance.lock\` exclusively to allow only one active verifier owner for a directory. An abandoned lock remains on crash; **never automatically delete**. An operator must reconcile checkpoint and storage state and approve lock removal.
- The disk lease now binds **exactly one in-memory verifier**. Further wrapper constructions on the same open store fail closed; direct store compare-and-swap is disabled after binding. A failed signature/catalogue validation before binding may be retried using the same trusted checkpoint. Parallel verifier creation admits exactly one owner.
- Compare-and-swap rejects invalid, nonmonotonic or mismatched prior checkpoint. Replacement is written to an exclusively created 0600 temporary file, synced, renamed atomically, then the containing directory is synced and the stored value reread. The verifier rejects all tokens while persistence is in flight; ambiguous errors fault the verifier until trusted restart.
- The checkpoint file contains **no signing key**, only sequence/digest and scope. Access controls are required for integrity, not secrecy.
- The adapter does not replicate across hosts. A caller that bypasses the wrapper, copies a checkpoint from a backup, or restores an older disk image defeats local monotonicity. It is **not production anti-rollback certification**; deploy a separately governed monotonic authority (e.g., external tamper-evident checkpoint service with atomic CAS) before operating multiple verifier nodes or claiming rollback resistance against privileged storage administrators.
- Tests under \`tests/unit/provider-checkpoint-store.test.mjs\` verify physical writes, restart, stale keyset refusal, single owner, permissions, tamper rejection and compare-and-swap. They are **real local filesystem tests**, not an independent hardware trust evaluation or power-loss injection test.

No merge, production deployment or live provider keys are authorised by this contract.
