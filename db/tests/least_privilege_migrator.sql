-- Disposable PostgreSQL 16 privilege contract; all roles/objects roll back.
\set ON_ERROR_STOP on
BEGIN;
CREATE ROLE vv_ci_migration_schema_owner
 NOLOGIN NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE vv_ci_migration_executor
 NOLOGIN NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE vv_ci_migration_application
 NOLOGIN NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT vv_ci_migration_schema_owner TO vv_ci_migration_executor
 WITH INHERIT FALSE, SET TRUE;
CREATE SCHEMA vv_ci_migration_sandbox AUTHORIZATION vv_ci_migration_schema_owner;
REVOKE ALL ON SCHEMA vv_ci_migration_sandbox FROM PUBLIC;
DO $gate$
BEGIN
 IF pg_has_role('vv_ci_migration_executor','vv_ci_migration_schema_owner','USAGE')
  OR NOT pg_has_role('vv_ci_migration_executor','vv_ci_migration_schema_owner','SET')
  OR pg_has_role('vv_ci_migration_application','vv_ci_migration_schema_owner','SET')
  OR has_schema_privilege('vv_ci_migration_application','vv_ci_migration_sandbox','CREATE')
  OR has_schema_privilege('vv_ci_migration_executor','vv_ci_migration_sandbox','CREATE')
 THEN RAISE EXCEPTION 'migration schema ownership privilege escaped'; END IF;
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN
  ('vv_ci_migration_schema_owner','vv_ci_migration_executor','vv_ci_migration_application')
  AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls OR rolinherit OR rolcanlogin))
 THEN RAISE EXCEPTION 'migration privilege role attribute mismatch'; END IF;
END $gate$;
SET LOCAL ROLE vv_ci_migration_executor;
DO $deny$
BEGIN
 BEGIN
  EXECUTE 'CREATE TABLE vv_ci_migration_sandbox.denied(id integer)';
  RAISE EXCEPTION 'executor gained inherited CREATE unexpectedly';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 BEGIN
  EXECUTE 'CREATE ROLE vv_ci_migration_escalation NOLOGIN';
  RAISE EXCEPTION 'executor acquired CREATEROLE unexpectedly';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $deny$;
SET LOCAL ROLE vv_ci_migration_schema_owner;
CREATE TABLE vv_ci_migration_sandbox.allowed(id integer PRIMARY KEY);
RESET ROLE;
DO $check$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='vv_ci_migration_sandbox' AND c.relname='allowed'
   AND c.relowner='vv_ci_migration_schema_owner'::regrole)
 THEN RAISE EXCEPTION 'owner-directed DDL did not succeed'; END IF;
 IF to_regclass('vv_ci_migration_sandbox.denied') IS NOT NULL
 THEN RAISE EXCEPTION 'unprivileged DDL persisted'; END IF;
 RAISE NOTICE 'least_privilege_migration_role_gate_passed';
END $check$;
ROLLBACK;
