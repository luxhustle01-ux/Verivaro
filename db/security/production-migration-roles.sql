-- REFERENCE ONLY: independently authorised PostgreSQL 16 bootstrap.
-- Do not execute in CI or run automatically on a target deployment.
-- Cluster-global roles: stop on any existing roles and reconcile separately.
-- No direct LOGIN, CREATEROLE, BYPASSRLS or database-wide SUPERUSER.
BEGIN;
CREATE ROLE vv_production_schema_owner
 NOLOGIN NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE vv_production_migration_executor
 NOLOGIN NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE vv_production_ledger_custodian
 NOLOGIN NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
-- PostgreSQL 16: only explicit SET ROLE access, never automatic INHERIT.
GRANT vv_production_schema_owner TO vv_production_migration_executor
 WITH INHERIT FALSE, SET TRUE;
-- The independently owned ledger custodian role MUST NOT be granted to the
-- executor, schema owner or runtime roles. No identity credentials are here.
-- A DBA separately scopes CREATE on the dedicated database to schema owner,
-- provides a short-lived migration login, and grants ledger SELECT+INSERT only
-- after independent review. No UPDATE/DELETE/TRUNCATE on migration ledger.
-- Existing installs require read-only inventory and an approved recovery plan.
COMMIT;
