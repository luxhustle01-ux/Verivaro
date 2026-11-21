# Verivaro — engineering increment 0.1.0

Intelligence. Verified.

**Status:** Engineering prototype and synthetic/test-data verification on an unmerged draft review branch; **not a production-ready or sale-validated application**. The [V4.0 master blueprint](docs/product/MASTER_BLUEPRINT.md) remains the design baseline. The [current engineering status](docs/engineering/STATUS.md), [G1 production trust-boundary and buyer audit](docs/engineering/G1_PRODUCTION_TRUST_BOUNDARY_BUYER_AUDIT_20261121.md), and [machine-readable evidence register](docs/engineering/G1_BUYER_EVIDENCE_MANIFEST_20261121.json) distinguish tested slices from deployment and buyer acceptance.

This public repository is restricted to synthetic examples and source code. Never commit actual project documents, customer records, credentials or confidential data. No license granting redistribution is implied; ownership and license review remain open.

## Local verification

Node.js 22.16.0 is the exact local baseline, not a production security endorsement. The temporary runner uses experimental native TypeScript stripping. There are no runtime dependencies.

```sh
npm ci --ignore-scripts
npm test
npm run demo
npm run demo:buyer
npm run demo:buyer:web
```

The demo prints a blocked finding for a synthetic mismatched equipment serial; it does not host a website.

The separate [synthetic buyer walkthrough](docs/engineering/G1_SYNTHETIC_BUYER_WALKTHROUGH_20261121.md) reproduces missing → conflicting → provisional → reviewed proof and checks a canonical package against self-held hashes. It is **not** a real buyer/mobile session, authenticated release or independent custody claim.

The [read-only browser showcase](docs/engineering/G1_MOBILE_BUYER_SHOWCASE_20261121.md) presents the same fixture as a four-stage mobile-responsive interface. The local preview is **loopback-only** and intended for developer/buyer inspection on a machine running Node; it is not a public website or an iPhone-deployed app. Chromium/WebKit browser CI checks responsive behavior and the non-release safety boundary.

## Portable acquisition-review bundle

Run the zero-dependency, synthetic-only ZIP exporter on Node 22.16.0:

```sh
npm run demo:buyer:bundle -- ./verivaro-synthetic-buyer.zip
```

The command refuses to overwrite an existing file. The archive contains the standalone `buyer-offline.html` viewer (no local server or external requests), the multi-file static-browser version, the exact four synthetic proof stages, an optional private-loopback Node preview (`node preview.mjs`), a manifest of every bundled file with SHA-256 and byte counts, and a text guide. The offline page is designed for local HTML/JavaScript-capable browsers; physical iPhone compatibility is not yet verified. It is **not** a production installer, authenticated release, signed provenance or independent custody attestation. The printed archive digest is a **self-held** value unless separately delivered by a trusted channel.

The [buyer handover workflow](.github/workflows/buyer-bundle.yml) packages the same ZIP and build receipt as short-retention GitHub Actions artifacts after verification, without a paid host, public deployment or real customer data. These artifacts are for source-code acquisition review and do **not** certify demand, licensing, product completeness or transfer readiness.

The existing disposable-PostgreSQL integration test now also exercises real encrypted ingestion → distinct reviewer approval → owner-authorised submission → canonical package bytes → SHA-256 verification → stale-graph rejection. These passed the six-workflow CI matrix at immutable baseline `86b9977f322761ba98beb5583e01e8573d793f9a`; later changes require their own verification. They are not real buyer acts or independent release signoff.

Detailed test contracts, limitations and local reproduction: [G1/P0-D offline buyer and handover acceptance record](docs/engineering/G1_P0D_HANDOVER_OFFLINE_GATE_20261121.md).

## Third-party and source-IP due diligence

The [P0-E licence and ownership audit](docs/engineering/G1_P0E_IP_DUE_DILIGENCE_20261121.md) separates repository-declared dependencies from actual legal clearance. An automated, deterministic **lockfile/workflow inventory** is available with:

```sh
node buyer-ip-inventory.mjs ./buyer-ip-inventory.json
```

The inventory covers four local npm lockfiles, pinned GitHub Actions references and a small explicit set of external CI tools. The buyer artifact workflow includes the resulting JSON and its hash receipt. **It is not a complete SBOM, a proof of source ownership, a legal licence audit or authority to sell/transfer third-party rights.** No customer data or paid service is needed to generate it.

## Components

- Evidence verification: exact-source checks, revision consistency, mandatory submission blockers and dependency impact.
- ProofLock: confirmed UTC evidence deadlines, not a live schedule or notification service.
- Financial rules: exact AUD cents, basis grouping, confirmed milestone deduplication, unknown counts; not legal or payment entitlement.
- Draft snapshots: deterministic index and text digest verification; not a signed or released handover.

## PostgreSQL migration integrity gate

The [P0-B source migration register](docs/engineering/G1_P0B_MIGRATION_CHAIN_20261121.md) tracks all 63 numbered SQL migrations by Git blob identity and byte length. The PostgreSQL workflow verifies **the complete on-disk chain and exact CI application order before executing any migration**, then retains its final privilege audit after migration 0063. New or modified migrations require an explicit reviewed register update.

Run `node scripts/verify-migration-chain.mjs` for the same preflight locally. **This is Git SHA-1 repository-drift detection, not an independently signed, collision-resistant supply-chain attestation or production migration history.** The migration owner, database role custody, backup/rollback rehearsal, deployment downtime and customer environment remain unverified.

## Engineering slices currently in the repository

The [P0-A buyer trust acceptance register](docs/engineering/G1_P0A_BUYER_ACCEPTANCE_REGISTER_20261121.json) now lists eight **unverified** off-host and ownership proof requirements. A new synchronous, in-memory authority transition model tests stale writer fencing, policy revocation ordering, simulated partitions and lost acknowledgements without asserting remote consensus or production safety.

The G1 recovery-floor signer now supports a [reference-only, serial-bound Ed25519 key schedule](docs/engineering/G1_REVIEW_FLOOR_AUTHORITY_REFERENCE_20261121.md), with old-signer rejection after a serial transition. A separately signed [P0-A trust-policy contract](docs/engineering/G1_P0A_REMOTE_AUTHORITY_CONTRACT_20261121.md) now specifies same-serial revocation, independently pinned policy checkpoints and fail-closed reference-gate checks; **it has no actual independent policy authority, distributed consensus or deployed key custody**. The schedule must be pinned outside the authority's trust domain; this is **not** external key custody or a deployed revocation service.

The original domain-function demo remains limited. Additional **synthetic CI-tested engineering slices** now include a PostgreSQL 16 migration and tenant-isolation gate; identity/session and scoped-transaction code; a local TLS application runtime; evidence quarantine/retrieval/recovery; browser workspace checks in Chromium and WebKit; and reference G1 signed witness, two-reviewer approval and floor-publication components. Consult `docs/engineering/` and the workflows for precise coverage. These pieces **are not evidence of a fully integrated customer product**.

## Security and commercial boundary

The G1 witness publisher, consumption register and floor authority are deliberately **single-host reference implementations**, not independent trust infrastructure. The injected signing capabilities, trusted state, browser identity provider, deployment credentials and real data-custody operation have **not** been proven under a production trust domain. Browser/runtime pathways exist, but a complete product UI and production operating environment do not. No independently verified penetration test, production recovery or customer payment/demand evidence is recorded.

**Do not claim production readiness, fully independent immutable evidence, compliance certification or verified market demand.** Release approval requires separately evidenced gates in the buyer audit and V4.0 blueprint. No real-data ingestion, external deployment, paid infrastructure or automatic merge is authorised. ProfitPilot code and data are not reused.
