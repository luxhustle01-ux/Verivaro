# G1 Loopback HTTPS witness and external audit receipt contract — 21 November 2026

**Status:** CI-only simulation. No production independent witness, external signing system or separately administered head anchor is connected or commissioned.

## Network integration

\`tests/fixtures/witness-loopback-server.mjs\` exposes a fixture-only HTTPS server bound to \`localhost\`, wired to the file-backed reference journal. It requires mTLS with a pinned test CA and rejects malformed, oversized, noncanonical, incorrect-scope and unauthenticated requests. Only \`POST /v1/provider-checkpoint\` accepts \`read\` and \`compare-and-swap\`. A success response is sent only after the reference journal reports a completed, fsynced checkpoint. Competing requests cannot both commit the same predecessor; a conflict or admission overload never authorizes a token. The fixture cannot act as a production service and must not be bound externally.

\`tests/unit/provider-witness-https-integration.test.mjs\` tests real HTTPS requests including 16 concurrent contenders, replay, missing client identity, wrong scope or method, malformed/duplicate JSON and a tampered journal. The reference journal is **not protected against privileged host compromise**, distributed split brain, malicious firmware, or power-loss uncertainty.

## Offline head receipt (NOT independent publication)

\`src/security/provider-witness-audit-receipt.mjs\` creates a canonical, **unsigned** audit-head statement containing the scope, head hash, checkpoint, journal count and claimed issue date. It has **no signing private key** and no automatic publication. An outside independent signing entity must sign its bytes with an Ed25519 key whose public key is obtained by the verifier independently from the witness host.

\`verifyExternallySignedWitnessAuditReceipt\` verifies the signature, expected issuer/audience, externally trusted public key, minimum retained journal count and, when supplied, an independently retained expected head hash. A correctly signed but old statement **can be replayed** unless the verifier retains a trusted freshness floor or expected head separately. \`issuedAt\` is a self-asserted field, **not** a trusted timestamp. A signature from a key controlled by the witness operator is **not** evidence of independent custody.

An authorised future publication mechanism needs independently governed nonexportable signing-key custody, an authenticated external write/read channel, durable monotonic receipt storage, accountability/revocation, liveness and rollback testing, signer approval policies and a supervised reconciliation procedure. No such mechanism has been deployed or claimed here. Keep draft PR #4 unmerged pending owner review and production gates.
