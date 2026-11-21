# Reproducible synthetic buyer walkthrough — documentary discrepancy to handover

**21 November 2026 · P0-D partial demonstration, not a completed buyer/mobile product.**

Run `npm run demo:buyer` on the pinned Node 22.16.0 engineering checkout. No environment variables, credentials, network services, real documents or purchases are required. The command prints a deterministic JSON transcript from **real Verivaro domain and package verification code**, not a slideshow or hard-coded success flag. CI executes this command and a negative case test suite.

The scenario follows a synthetic HVAC installation certificate with a mandatory contract serial `HVAC-001`. Four transitions are run:

1. **Missing:** Contract requirement present; no certificate proof, mandatory blocker.
2. **Conflicting:** Approved certificate says `HVAC-002`; the configured criterion conflicts with the evidence.
3. **Provisional:** A corrected `HVAC-001` certificate supersedes the older document version; reviewer approval is pending, so readiness is still blocked.
4. **Reviewed:** Corrected certificate approved; exact configured documentary checks pass and the required evidence is source-linked, with no mandatory blockers.

Each stage derives `status`, `reason`, evidence source identifiers, blocker state and a deterministic SHA-256 **draft snapshot** from `packages/domain/evidence.ts` and `packages/export/snapshot.mjs`. The demonstration verifies that the old snapshot is stale after source correction; it does not silently reuse superseded proof.

After the final configured check passes, the demo uses the **actual** `createSubmissionPackage` and `verifySubmissionPackage` functions. The package includes the synthetic approved text evidence and a canonical manifest; the verifier checks exact bytes against digests computed by the *same test process*. The archive is zeroed after verification, and the CLI reports hashes and counts rather than exporting sensitive data. Negative tests reject unreviewed proof, cross-project source injection, modified archives and inconsistent expected hashes.

**Critical disclosure:** The `readSubmission` workflow used to assemble this synthetic demonstration is a test stub. It does **not** authenticate an actor, authorize a real release, establish signer custody, prove source authenticity, validate compliance, or deliver a package to an actual recipient. Package hash verification against **self-held** digests is an internal integrity consistency demonstration, not independent or nonrepudiable verification. The mobile UI, real reviewer workflow, production database authorization and source-evidence ingestion remain separate acceptance gates.

**Buyer use:** demonstrate deterministic defect detection, conservative review gates, source provenance and package byte integrity on synthetic data. Do not claim customer adoption, verified economic savings, AI-generated document interpretation, independently trusted hashes or production-ready SaaS. The comprehensive buyer-readiness limitations remain in `G1_PRODUCTION_TRUST_BOUNDARY_BUYER_AUDIT_20261121.md`. This milestone advances P0-D only partially; a separately evaluated mobile session is still required.
