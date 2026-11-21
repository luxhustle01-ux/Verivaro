# Mobile synthetic buyer showcase — read-only P0-D reference

**21 November 2026.** Buyer-facing UI over the existing deterministic synthetic evidence evaluator, not a production application, customer pilot or independent security assessment.

## Technical handoff

Run `npm run demo:buyer:web` on the pinned Node 22.16.0 repository checkout. It binds an ephemeral port **only to 127.0.0.1** and prints a local preview URL. It has no external listener, third-party assets, database, authentication, real customer information, public deployment, payment, or outbound API. A buyer working on a computer could view the local site; no iPhone-specific remote access is implied. This is an engineering fixture; an actual distributable deployment would require a separately approved design.

`src/demo/buyer-showcase.mjs` derives the UI data from `runSyntheticBuyerDemo` and source scenarios; `src/demo/buyer-showcase-server.mjs` serves exact repository-owned HTML/CSS/JS and JSON with no-store, anti-framing, no-inline-script CSP, no external connections and GET/HEAD-only responses. `src/demo/buyer-showcase.js` renders data using `textContent`, never `innerHTML`. Its four stage controls show **missing → conflicting → pending review → configured documentary checks passed**. Each stage includes exact source text, revisions, review state, blocker count, and why the decision changed. A final package summary shows SHA-256 digests and byte counts while making the **self-held, not independent** verification boundary explicit.

There is **no approval button, anonymous upload, public package download, forged reviewer identity or production mutation**. Readiness at stage four is *only* successful synthetic configured text checking. The artifact's signatures, independent provenance, commercial demand and legal compliance are not verified.

Browser regression runs on Chromium and WebKit for 320px, 390px and 1280px layouts, checking step navigation, 44px-tall controls, absence of horizontal overflow, conservative blocking on unapproved steps, explanatory package summary, script execution safety with malicious source strings, and fail-closed behavior when claimed approval flags change. Node tests verify the payload, secure local transport headers and refusal of writable routes.

**Open P0-D items:** true iPhone-device validation; end-to-end authenticated reviewer roles, actual customer data intake/rights, independent trusted hash custody, production backend/hosting decision, full buyer purchase/transfer due diligence and measured commercial demand. PR #4 remains draft, unmerged, undeployed.
