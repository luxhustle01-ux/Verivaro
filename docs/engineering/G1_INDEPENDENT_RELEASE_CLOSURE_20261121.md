# G1 P0-B — independent release evidence and closure contract

**21 November 2026 · Status: NOT APPROVED · Draft PR #4 · zero spending authorised**

This is a reviewer-ready acceptance checklist, **not** an independent security review or a claim that the product is production-ready. The latest security increment belongs to the G1 PostgreSQL control stack, not the whole product release.

## Verified in disposable GitHub CI (review source SHA f24ef1ff7f7672fdaad3d098a75a5c2f8468e997)

- The exact 63 source SQL migrations were applied in order with a persistent PostgreSQL history table, reviewed SHA-256 file digests and chained entry hashes.
- The 63-row history head was compared with the locked repository baseline. The individual migration transaction commits its SQL schema change and matching ledger row atomically.
- Separate disposable restart database executed real migrations 0001/0002: backend termination before COMMIT, rollback of both schema DDL and ledger row, successful new-process retry, no duplicated replay, out-of-order refusal and deliberate ledger-tamper refusal.
- PostgreSQL G1 integration #451 at the previous commit and the new integration workflow at source f24ef1f reported security/restore role checks. The f24ef1f PostgreSQL job also recorded a restored catalogue containing the ledger table and both 21-role audits.
- CI is synthetic and self-operated; an independent owner, security assessor and buyer have **not** certified these controls.

## Release-hardening actions that can be developed without additional spending

1. Replace the CI-only superuser migrator with a least-privileged, separately governed production migration identity and a production bootstrap/migration-history reconciliation procedure. Prove privilege separation against actual deployment roles.
2. Produce an independently signed SHA-256 migration release manifest and externally retained monotonic history witness, with explicit rollback/restore recovery approval. Prove loss-of-witness, snapshot rollback, tamper and concurrency failure cases.
3. Rehearse production-equivalent staged upgrades from an existing real-schema snapshot and encrypted restore, interrupted operations, retry, backward/forward app compatibility, lock duration and disaster recovery objectives.
4. Test production TLS, live identity-provider configuration, key custody and rotations with independent assessors; capture reproducible security review/penetration findings and their closure.
5. Complete G0–G6 acceptance, legal/privacy and transferable IP review, iPhone Safari device evidence, meaningful load tests and real buyer/customer commercial validation.

## Approval policy

Every unresolved item must have an accountable independent reviewer or owner, a dated artifact and exact source/deployment SHA, negative test evidence, and an explicit acceptance decision. Unsupported rows remain `NOT_VERIFIED`; self-assessed GitHub Actions cannot substitute for independent signoff.

Current register: `docs/engineering/G1_BUYER_EVIDENCE_MANIFEST_20261121.json`. Critical flags remain `productReleaseApproved=false`, `productionSecurityCertified=false`, and `commercialDemandValidated=false`.

**No merges, live deployment, spending, real customer access or removal of the draft safeguard.**
