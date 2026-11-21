-- READ-ONLY POST-MIGRATION OBSERVATION, NOT AN APPROVAL OR BACKFILL.
-- Execute only after independent release identity, source hash, and DB selection
-- have been validated. PostgreSQL 16; no secrets are read or exported.
\set ON_ERROR_STOP on
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
DO $vv_observe$
DECLARE r text;
DECLARE expected_roles text[]:=ARRAY[
 'verivaro_runtime','verivaro_identity_service','verivaro_recovery_service',
 'verivaro_recovery_approver','verivaro_share_gateway','verivaro_release_service',
 'verivaro_recipient_gateway','verivaro_admission_service',
 'verivaro_admission_reconciler','verivaro_monitor_worker',
 'verivaro_incident_operator','verivaro_monitor_reader','verivaro_alert_sender',
 'verivaro_restore_reviewer','verivaro_identity_provisioner',
 'verivaro_identity_events','verivaro_api_admission','verivaro_evidence_ingestor',
 'verivaro_evidence_reader','verivaro_evidence_auditor','verivaro_tenant_operator'
];
DECLARE versions bigint; maximum integer;
BEGIN
 IF (SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname=ANY(expected_roles))<>21
 THEN RAISE EXCEPTION 'privileged migration reconciliation: service role inventory incomplete'; END IF;
 FOR r IN SELECT unnest(expected_roles) LOOP
  IF EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=r AND
     (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR
      rolbypassrls OR rolinherit OR rolcanlogin))
  THEN RAISE EXCEPTION 'privileged migration reconciliation: service role elevated %',r; END IF;
 END LOOP;
 IF to_regclass('verivaro_migration.history') IS NULL
 THEN RAISE EXCEPTION 'privileged migration reconciliation: no database ledger'; END IF;
 EXECUTE 'SELECT count(*), COALESCE(max(version),0) FROM verivaro_migration.history'
  INTO versions,maximum;
 IF versions<>63 OR maximum<>63
 THEN RAISE EXCEPTION 'privileged migration reconciliation: incomplete 63-entry ledger'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='vv_production_schema_owner'
   AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolbypassrls
   AND NOT rolreplication AND NOT rolcanlogin AND NOT rolinherit)
 THEN RAISE EXCEPTION 'privileged migration reconciliation: schema owner missing or elevated'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='vv_production_migration_executor'
   AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolbypassrls
   AND NOT rolreplication AND NOT rolcanlogin AND NOT rolinherit)
 THEN RAISE EXCEPTION 'privileged migration reconciliation: executor missing or elevated'; END IF;
 IF pg_catalog.pg_has_role('verivaro_runtime','vv_production_schema_owner','SET')
 OR pg_catalog.pg_has_role('verivaro_runtime','vv_production_migration_executor','SET')
 THEN RAISE EXCEPTION 'privileged migration reconciliation: application role escalation'; END IF;
 RAISE NOTICE 'observed legacy role attributes and count=63; independent source/hash/signature check STILL REQUIRED';
END $vv_observe$;
ROLLBACK;
