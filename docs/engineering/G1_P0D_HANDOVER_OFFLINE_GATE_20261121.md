# G1 / P0-D — Synthetic offline buyer viewer and real evidence handover gate

**21 November 2026 · engineering review only · PR #4 (draft)**

**Decision:** Six exact-head workflows were independently confirmed green on Git SHA `86b9977f322761ba98beb5583e01e8573d793f9a`; future commits require requalification. This is a synthetic buyer demonstration plus a disposable PostgreSQL regression, **not** a production release, compliance certificate, genuine buyer pilot or verified purchase intent.

## What changed

1. The source-backed four-stage HVAC showcase remains driven by the deterministic domain evaluator. An offline, self-contained `buyer-offline.html` is generated from that exact payload and original viewer code. It includes embedded CSS and an inline script restricted by SHA-256 content-security-policy hashes. There is no network request or local listener in the offline variant.
2. `createPortableBuyerBundle` now assembles a canonical STORE ZIP containing eight files: `index.html`, `buyer-showcase.css`, `buyer-showcase.js`, `buyer-demo.json`, `README.txt`, `preview.mjs`, `buyer-offline.html`, and `manifest.json`.
3. The verifier checks archive SHA-256, canonical ZIP structure, per-file digests, fail-closed synthetic flags, and exact regeneration of the standalone viewer from the other assets. **A self-computed hash cannot authenticate its publisher.**
4. The optional `sourceRevision` field records the exact 40-character Git commit SHA used by the CI bundling workflow. The archive verifier can require a caller-supplied expected revision to prevent mixing up artifacts between commits. This is **traceability, not a signature or independently verified build provenance**: the originating GitHub commit and downloaded ZIP digest must be checked through trusted channels to establish identity.
5. The packaged preview's real HTTP tests reject writes, unknown paths and forged Host headers. The portable HTML test runs through real Chromium and WebKit browser engines at 320, 390, and 1280 CSS-pixel widths, and asserts no HTTP(S) requests are made.
6. The existing disposable-PostgreSQL `live-requirement-graph.test.mjs` now exercises encrypted evidence ingestion → independent requirement/link review → exact approved submission → owner-only assembled handover → canonical byte verification, then changes a source-linked evidence graph *during archive assembly* and requires the final authorisation check to fail closed. The test also checks wrong actor/project scope and tampered archive detection.
7. A GitHub Actions workflow produces an ephemeral ZIP, JSON receipt and individual offline HTML artifact for buyer review. This is **not** public hosting or an authenticated production export.

## How to reproduce locally without purchasing anything

Use the repository's pinned Node 22.16.0 version and its existing lockfile. Run:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm test
npm run demo:buyer:bundle -- ./verivaro-synthetic-buyer.zip
```

The exporter refuses to overwrite an existing ZIP. Extract the archive and open `buyer-offline.html` in an HTML/JavaScript-capable local browser, or, where Node is available on the same computer, run `node preview.mjs`. Opening a local HTML file in an iPhone file viewer is **device/application dependent** and physical iPhone validation has not been completed.

**Additional CI gates:** `.github/workflows/browser-workspace.yml` for Chromium/WebKit; `.github/workflows/postgres-g1.yml` for PostgreSQL 16 and actual scoped ingestion and approval; `.github/workflows/buyer-bundle.yml` for canonical packaging and artifact export. Successful syntax checks, JavaScript unit tests or browser playback do **not** replace the independent real database and custody tests.

## Negative acceptance cases

- An unreviewed or conflicting proof blocks approval.
- The submitting actor cannot approve its own exact graph; owner cannot bypass the independent reviewer role.
- A contributor or foreign-project actor cannot export an approved handover.
- The packager reads a fresh authorization after retrieving the encrypted source bytes, and an evidence-graph change invalidates the old authorization.
- An altered ZIP byte, modified manifest or separately edited offline HTML fails verification.
- The offline browser cannot require external scripts, assets or network calls.
- No client interface contains a real approve/release control or deploys any customer data.

## Open acquisition and production gates

The offline HTML is a **synthetic presentation**, not the live PostgreSQL workflow. Real customer onboarding, mobile iPhone hardware verification, hosted identity, externally custodied signing keys, independent witness and monotonic floor, operational recovery testing, penetration assessment, intellectual-property/licensing clearance and commercial buyer willingness to pay remain unproven. The static package does not include a production installer or actual financial return evidence.

**No merge to main, deployment, purchase, external publication or new account integration is authorized by this engineering change.**
