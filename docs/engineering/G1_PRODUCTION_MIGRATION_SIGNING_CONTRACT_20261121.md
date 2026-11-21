# G1 — least-privilege migration and independently signed release contract

21 November 2026. Reference architecture and synthetic CI only. **Production release NOT APPROVED.**

## PostgreSQL 16 migration roles

**Provisioner:** Independent DBA is required for initial role/extension creation and any privileged SQL. It is not an application or unattended migrator account.

**Schema owner:** vv_production_schema_owner is NOLOGIN, NOSUPERUSER, NOINHERIT, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS. Ownership must be restricted to approved application schemas and objects.

**Migration executor:** vv_production_migration_executor starts NOLOGIN with all the restrictive attributes above. A SET-only membership allows changing to schema owner explicitly, not inherited schema-owner privileges. It must not hold privileges on unrelated databases or schemas. A separately approved identity and controlled credential custody are required to enable access later.

**Application roles:** Never members of either migration role and never holders of schema CREATE, object ownership, or ledger mutation privileges.

The checked-in db/security/production-migration-roles.sql is a reference bootstrap requiring an independently authorised operator. It is NOT run by CI. The synthetic db/tests/least_privilege_migrator.sql creates disposable substitute roles, confirms CREATE ROLE and ordinary un-elevated DDL fail, verifies explicit owner-only scoped DDL, and rolls back.

**Critical first-install incompatibility:** Existing migrations 0001–0063 include CREATE ROLE and other privileged operations. They cannot all run unchanged as a no-CREATEROLE executor. An independent DBA must produce a reviewed, provisioner-scoped bootstrap or migration-reconciliation plan for the existing scripts. Do not silently grant superuser or CREATEROLE to the unattended executor. src/security/migration-role-policy.mjs inventories privileged statements for review but is not a complete SQL parser.

## Offline independently verifiable release manifest

Prepare **unsigned** canonical JSON by running the read-only command:

    node scripts/migration-release-cli.mjs draft 1 <exact-Git-commit-SHA>

The manifest binds exactly 63 locked SQL files plus nine named source-security and CI files, their SHA-256 digests and byte lengths, the linked PostgreSQL ledger head, and Git HEAD. The generated manifest explicitly says productionApproved=false.

Independent verifier command:

    node scripts/migration-release-cli.mjs verify <manifest> <external-policy> <separately-obtained-policy-sha256> <owner-signature> <reviewer-signature>

All input files must be outside the repository checkout. The exact public-key policy digest MUST be pinned through a separate trusted channel; computing the pin from an untrusted bundled policy does not confer independent trust. The policy contains schemaVersion=1, type=VERIVARO_EXTERNAL_RELEASE_TRUST_V1, a minimumSequence floor, threshold=2 and independent Ed25519 SPKI public keys for the roles owner and independent-reviewer (with distinct key IDs and explicit revoked booleans). Policy, manifest and signature envelopes use canonical Node JSON.stringify(value) followed by exactly one newline, encoded as UTF-8. Unknown fields and ambiguous JSON reject.

A signature envelope contains schemaVersion=1, type=VERIVARO_ED25519_RELEASE_SIGNATURE_V1, keyId, manifestSha256 (hash of exact manifest bytes) and signature (base64 Ed25519 64-byte signature). Sign the exact bytes of the ASCII domain separator VERIVARO_MIGRATION_RELEASE_ED25519_V1 followed by a zero byte followed by the canonical manifest bytes. In Node, crypto.sign(null, payload, externally held privateKey) is the signing primitive. Distinct valid owner and reviewer signatures are mandatory.

The verifier checks the independently pinned policy digest, non-revoked keys, distinct signer roles, minimum sequence, signatures, exact files, ledger head and source checkout. **No trusted private keys, signing keys, public-key trust policy, policy pin or production signatures are created or committed.** Unit-test keys are ephemeral and not release-signing identities.

## Remaining hard boundaries

This system proves only that supplied signed release bytes match the independently supplied pinned policy and source checkout. It does NOT establish actual human independence, private-key custody, external write-protected monotonic rollback witnessing, production database contents, deployed binary provenance, actual provider configuration or operational risk acceptance. Privileged DB administrators can alter the ledger, and source history can be rolled back unless an independent witness is used. Real HA failure/restore tests, staging upgrades, external security assessment, legal/IP transferability, actual commercial demand and G0–G6 release gates remain unresolved.

Release flags remain productReleaseApproved=false, productionSecurityCertified=false, commercialDemandValidated=false. The PR remains draft; no merge, deployment or additional spending is permitted.
