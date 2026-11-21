# P0-E — Source-IP and third-party dependency acquisition audit

**21 November 2026 · Synthetic, repository-scoped diligence · NOT LEGALLY CLEARED**

## Verified by repository inspection (not external legal verification)

Verivaro has **four npm v3 lockfiles**: a dependency-free root and three separate pinned PostgreSQL driver installations. The three service/test-driver lockfiles currently list the same **14 distinct npm package name/version records**, all with SHA-512 lock integrity metadata; declared package licences are **MIT or ISC**. These declarations come from lockfile metadata, **not** direct verification of each publisher's licence text or transfer permissions.

The audited GitHub Actions jobs use full immutable SHA references for Actions, but an Action revision alone does not pin its own runtime dependencies or prove its publisher's licence. The workflow setup references **Playwright 1.56.1**, **PostgreSQL 16** and a system-installed **ClamAV daemon**. Their transitive dependencies and licence notices are **not** included in the 14-package npm inventory. No top-level LICENSE file was observed in the audited repository tree. Public visibility does not itself grant redistribution or commercial assignment rights.

## Reproducible implementation

Run from the repository root on pinned Node 22.16.0:

```sh
node --experimental-strip-types --test tests/unit/buyer-ip-inventory.test.mjs
node buyer-ip-inventory.mjs ./buyer-ip-inventory.json
```

The script reads only four local lockfiles, their matching package manifests and six local GitHub Actions workflow files; no registry access, network calls or package download is required. It emits deterministic, sorted JSON, one record per distinct npm name/version, with lockfile source locations, declared licence, registry URL and integrity metadata, plus pinned Action SHA references and explicit excluded toolchains. A caller may supply a 40-hex Git commit through `VV_SOURCE_REVISION`, but **that is a self-held traceability string, not publisher-authenticity proof**.

The generator rejects a missing/unmatched root manifest, altered package integrity/registry provenance, conflicting duplicate package metadata, unpinned GitHub Actions and unexpected changes to three explicitly reviewed external tool references. The CLI creates a new mode-0600 file and refuses overwrite. These checks **do not** demonstrate complete software composition or copyright ownership.

The existing `.github/workflows/buyer-bundle.yml` now generates a downloadable JSON inventory and digest receipt alongside the synthetic offline buyer demonstration, requiring no additional host. This is an engineering artefact and not verified customer installation.

## Unresolved rights / acquisition checklist

- **Title and contributor chain:** identify every human and AI-assisted contributor, employment/contractor agreements, provenance of each SQL/JS/Python asset, copy-pasted or imported code and assignment permissions. Cannot be inferred from Git metadata.
- **Licences and notices:** obtain authoritative licence texts for all third-party dependencies and transitive components; check MIT/ISC notice obligations, any native binaries, PostgreSQL licensing, ClamAV and browser-tool redistribution, and delivered notice files. No conclusion reached here.
- **Open-source project distribution:** decide whether Verivaro itself is licensed, source-only asset assigned privately or delivered under a negotiated software purchase agreement. Absence of a top-level licence leaves third parties with no general licence grant; actual ownership is still unproven.
- **Brand and domain:** search jurisdiction-specific Verivaro trademark and domain conflicts and verify enforceable transfer/control. Not performed.
- **Software sale:** buyer counsel should review assignment representations, warranties, retained components, downstream third-party licences, contributor waivers, support disclaimers and escrow/transfer conditions.
- **Supply chain:** produce a complete SPDX/CycloneDX inventory only after enumerating build containers, runner packages, plugins, source tooling and any vendored dependencies; independently audit security/licence metadata and generate notices.

## Status disposition

**P0-E remains NOT_CLEARED.** The new output improves the buyer's visibility into third-party declarations, but does not establish legal eligibility, a market price, revenue, customer willingness to pay, security certification or safe production deployment. No paid clearance, external outreach, new registration, public release or asset transfer was undertaken.
