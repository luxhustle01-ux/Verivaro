# G1 Witness journal reference: concurrent CAS, replay and audit integrity

**Scope — 21 November 2026.** This is a **single-host, synthetic reference implementation**, not an independently administered witness service, deployable production server, or proof of external anti-rollback protection.

The optional `src/security/provider-witness-journal.mjs` reference module stores its checkpoint state in **one append-only hash-chained journal** (rather than a separate checkpoint and audit file). It rejects noncanonical or re-ordered records. Each record binds issuer/audience scope, record index, previous checkpoint, next checkpoint, previous digest, and record digest; SHA-256 includes a version-specific domain separator. The first entry encodes an explicitly provisioned checkpoint.

The **trusted audit head must be acquired and retained outside the journal's host and administrative domain**. `openReferenceWitnessJournal` requires it at startup, validates the entire chain against it, acquires a filesystem exclusive lock, then revalidates. It does not auto-provision missing logs or auto-recover ambiguous/truncated entries. A journal owner who can also replace the external trusted head could forge the entire history; an unauthenticated on-disk hash chain alone does not solve that problem.

## Defined behaviour

- `encodeWitnessGenesis({issuer,audience,checkpoint})` produces an initial canonical journal record and its digest for an externally governed provisioning workflow. It **does not create a remote trusted authority**.
- `verifyWitnessJournal(bytes,{issuer,audience,trustedHead})` verifies canonical records and chained hashes end to end against the independently retained head.
- `openReferenceWitnessJournal({directory,issuer,audience,trustedHead})` operates only in a private single-owner filesystem directory with an exclusive process lock; `read(scope)` refuses out-of-scope requests; `compareAndSwap({issuer,audience,previous,next})` serializes admission, enforces a strictly increasing sequence, appends and `fsync`s the new record before returning acknowledgement.
- A CAS conflict or duplicate/replay is rejected without changing state. Disk mutation, noncanonical content, partial append, missing audit anchor or uncertain I/O faults closed.
- The `audit()` result exposes the new digest, which **must be stored and validated independently** if the process is later restarted. The reference module does not implement cross-domain anchoring, electronic signatures, WORM storage, client identity assignment or external audit publication.

## Synthetic test acceptance

`tests/unit/provider-witness-journal.test.mjs` exercises 16 simultaneous CAS contenders, duplicated/replayed and stale requests, descending sequences, mismatched tenant-like scope, chain tampering, truncation, reordering, snapshot rollback, active-writer exclusion, and supervised restart requiring the updated externally supplied head.

**Limitations:** The process lock does not solve clustered or network split-brain. The journal is local storage, not off-host custody. `fsync` ordering is checked in code but not power-loss durability tested. No durable mTLS server wraps the module yet, and no hostile local-privilege or multi-host adversary was defeated. A trusted external anchoring store, independent principal-controlled credentials, replication/consensus, power-loss drills and third-party security review remain prerequisites for production. Do not merge or deploy the G1 draft by interpreting synthetic tests as certification.
