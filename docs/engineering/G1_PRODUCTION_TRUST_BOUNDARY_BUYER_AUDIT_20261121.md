# G1 production trust-boundary and buyer-readiness audit

**21 November 2026 · Repository / code / synthetic CI audit · PR #4**

**Decision: NOT PRODUCTION-APPROVED; NOT MARKET-SALE VALIDATED.** Verivaro is presently a code-and-demonstration asset with substantial tested components, **not a commissioned production SaaS**. The approved V4.0 blueprint explicitly frames the business model as *build and sell the software asset*, with no requirement to operate a live service. The proposed asking ambition is not a sale valuation. This audit gives neither certification nor a numerical completion percentage.

## Audited sources and limits

Reviewed the PR #4 head, repository tree, README, engineering status, G1 acceptance/security/runtime/credential notes, V4.0 blueprint, core/PostgreSQL/browser/antivirus/maximum-recovery workflow configuration and G1 recovery/reference modules. The Git tree contains a wide source and test footprint, but **files and green tests prove only the specific exercised conditions**. Source-level review is not an independent penetration test. The project remains public and uses synthetic fixtures; real customer files and credentials must not be introduced to the repository.

**Evidence grades:** `PARTIAL_CI` = specific synthetic CI / integration paths have tests; `REFERENCE_ONLY` = deliberately local or simulated trust service; `NOT_VERIFIED` = required proof absent; `NOT_CLEARED` = legal/IP gate open; `NOT_VALIDATED` = commercial demand not tested. The manifest at `docs/engineering/G1_BUYER_EVIDENCE_MANIFEST_20261121.json` indexes source paths and records the release decision.

## Actual trust-domain architecture for acquisition diligence

| Domain | Existing code / tests | Production authority needed | Gate |
| --- | --- | --- | --- |
| T1 Identity and application edge | `src/security/application-runtime.mjs`, signed provider context; `docs/engineering/G1_APPLICATION_RUNTIME.md` | Buyer-run IdP, origin/TLS, production PKI, session/role revocation, IAM audit and runbooks | **P0** |
| T2 PostgreSQL data and tenancy | SQL migration chain, FORCE RLS, signed scoped transactions, disposable PostgreSQL and pool tests | Dedicated production roles/owners, restricted signer custody, non-superuser runtime, access review, migration drills | **P0** |
| T3 Source evidence and object custody | Quarantine/ClamAV/PDF/Office, encrypted spools, export and backup fixtures | Separate durable encrypted storage, tenant custody, malware incident response, deletion/legal-hold policy, real resource caps | **P0** |
| T4 Independent audit witness | Signed journal/receipt and HTTPS witness guard plus reference publisher | Physically/administratively separate signed anchor service and monotonic external floor; trusted public-key/receipt policies | **P0** |
| T5 Recovery-review register and floor | Two-reviewer signed protocol, local consumption register and file-backed authority | Independent signer and serial/high-water-mark store; remote **linearizable** conditional writes, fencing and key lifecycle | **P0** |
| T6 Operations and recovery | Backup, restore, replay, release and monitor fixtures; restore/maximum-recovery jobs | Independently witnessed RTO/RPO, actual abrupt power-loss recovery, cross-host partition drills, incident custody and external backup | **P0** |
| T7 Commercial/IP and buyer transition | V4.0 specification, repository, demonstration and test evidence | License/IP audit, trademark clearance, transfer documentation, reproducible buyer install, buyer demand/pricing validation | **P0** |

**Signed-receipt freshness improvement (reference only):** The earlier v1 receipt checked signature and scope but lacked a request challenge or age enforcement. The reference protocol now requires **v2 Ed25519 receipts with unique 32-byte challenges, bounded expiry and receipt-age checks**, and rejects legacy v1 downgrade or stale authentic responses. This closes the identified *reference-level signed-response replay weakness*. **Production blockers remain:** independent trusted clock, independent signing-key custody, authenticated externally operated authority, off-host monotonic high-water mark, true distributed CAS/fencing and independent hostile-host assessment. A nonce does not ensure freshness if the entire trusted authority domain has been rolled back or compromised.

The local `O_EXCL` file lock is single-host writer exclusion; it is not leader election or a globally fenced lease. JavaScript path checks cannot remove the TOCTOU race against a privileged administrator. A child-process `process.exit` after `fsync` tests interruption order, **not** an actual power interruption, disk flush guarantee or multi-AZ failover. Production key and floor operators must be independent of the application and storage administrator.

## Prioritized buyer-risk remediation

| Priority | Concrete action | Objective acceptance evidence |
| --- | --- | --- |
| **P0-A** | Specify production authority trust/credential diagram, independent key custody, request-nonce/receipt age, two-key rotation/revocation and remote atomic CAS/fencing | Threat model, protocol test vectors, remote implementation and independent-host adversarial audit |
| **P0-B** | Remove or clearly quarantine any compatibility paths trusting caller-writable tenant identity; deploy full migration chain without exposing interim schema | Production-like negative-privilege scripts, trusted IdP tests, migration rehearsal and approver signoff |
| **P0-C** | Prove artifact recovery and tamper evidence under real process power-loss and split-brain, with external authenticated floor | Measured fail-closed recovery report, hard power-cycle/off-host drill, immutable incident report, explicit RPO/RTO |
| **P0-D** | Produce buyer demo with coherent end-to-end evidence lifecycle (source → reviewer → deficiency → proof → handover) | Recorded synthetic mobile session, reproducible installer, complete data provenance, no manual hidden steps |
| **P0-E** | Document source provenance, dependency licenses, ownership and transfer constraints | SBOM, license inventory, trademark/domain legal check and buyer-ready assignment schedule |
| **P0-F** | Validate problem/desirability through permitted external buyer interviews or paid commitments | Dated qualitative and quantitative evidence; do not equate a polished demo with willingness to buy |
| **P1** | Expand release checks to include exact-head maximum-recovery and integrated G0–G6 traceability; publish static asset manifest | One immutable handover manifest with per-gate evidence, logs, failing-case controls and scoped exclusions |
| **P2** | Optional buyer-requested hosting/tenant migration adapter | Demonstrated only after acquisition scope and cost owner confirmed |

An asset may be sold as a **prototype/source-IP acquisition** before SaaS deployment, but the sale description, warranty language and purchase price must reflect open P0s. There is no independently evidenced demand or valuation range here.

## CI audit corrections made in this increment

1. The top-level README previously stated that the code was only local domain functions with no authenticated runtime. That was stale relative to `src/security/application-runtime.mjs`, PostgreSQL scope and browser tests. README now clearly describes *partial engineering slices*, not a fully functioning SaaS.
2. `docs/engineering/STATUS.md` described the original import (43 tests) despite later test and integration additions. Its replacement reflects current scope without upgrading any gate to production-approved.
3. `.github/workflows/recovery-capacity.yml` previously triggered on the engineering parent and PRs targeting main, **but not this audit branch**, whose PR targets the engineering parent. The updated push branch filter makes the maximum-recovery matrix applicable to the exact reviewed code head.
4. The machine-readable evidence manifest and a Node regression check ensure referenced evidence paths exist and block an inconsistent claim of approval while any declared blocker remains open. This is *document consistency*, not an external assessor or a security certification.

## Reconciliation and buyer handover rules

Keep PR #4 draft and do not merge/rebase it without owner approval. At final handover, identify a single immutable repository SHA, capture all relevant workflow URLs and job artifacts *for that SHA*, generate a SHA-256 inventory of the downloadable asset, and provide a setup/test/demo guide with expected synthetic output. Separate source ownership from unverified brand clearance and third-party dependency rights. Never put signing credentials, customer data or real production receipts in the public repo. An external buyer should retain authority over any subsequent deployment, costs and operational key custody.

**Audit disposition:** engineering progress is real; independent production assurance and commercial sale evidence remain unproven. This document is a prioritized due-diligence plan, not proof that any unexecuted gate has passed.
