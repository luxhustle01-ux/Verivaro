-- Full G1 post-migration regression; not a substitute for production audit.
DO $audit$
DECLARE r record; t record; p record; s record; role_count integer:=0;
BEGIN
 FOR r IN SELECT oid,rolname,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication,rolinherit,rolcanlogin
 FROM pg_roles WHERE rolname LIKE 'verivaro_%' LOOP
  role_count:=role_count+1;
  IF r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolinherit OR r.rolcanlogin THEN
   RAISE EXCEPTION 'elevated service role: %',r.rolname;
  END IF;
  IF EXISTS(SELECT 1 FROM pg_roles g WHERE g.oid<>r.oid
   AND (g.rolsuper OR g.rolbypassrls OR g.rolcreaterole OR g.rolcreatedb OR g.rolreplication OR g.rolname LIKE 'pg_%' OR g.rolname LIKE 'verivaro_%')
   AND pg_has_role(r.oid,g.oid,'MEMBER')) THEN RAISE EXCEPTION 'unexpected indirect service privilege: %',r.rolname; END IF;
  FOR s IN SELECT oid,nspname FROM pg_namespace WHERE nspname LIKE 'verivaro%' LOOP
   IF has_schema_privilege(r.oid,s.oid,'CREATE') OR (s.nspname='verivaro_private' AND has_schema_privilege(r.oid,s.oid,'USAGE'))
   THEN RAISE EXCEPTION 'unsafe schema permission: % %',r.rolname,s.nspname; END IF;
  END LOOP;
  FOR t IN SELECT c.oid,c.relname,c.relowner,n.nspname,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c
   JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname LIKE 'verivaro%' AND c.relkind IN ('r','p','v','m') LOOP
   IF pg_has_role(r.oid,t.relowner,'MEMBER') OR has_table_privilege(r.oid,t.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   OR has_table_privilege(r.oid,t.oid,'INSERT')
   OR (has_table_privilege(r.oid,t.oid,'SELECT') AND NOT(r.rolname='verivaro_runtime' AND t.nspname='verivaro' AND t.relname IN ('tenants','projects','memberships','project_members','evidence')))
   THEN RAISE EXCEPTION 'unexpected table privilege: % %.%',r.rolname,t.nspname,t.relname; END IF;
   IF t.nspname='verivaro' AND t.relname IN ('tenants','projects','memberships','project_members','evidence')
   AND NOT(t.relrowsecurity AND t.relforcerowsecurity) THEN RAISE EXCEPTION 'missing forced RLS: %',t.relname; END IF;
  END LOOP;
 END LOOP;
 IF role_count<21 THEN RAISE EXCEPTION 'incomplete role coverage'; END IF;
 FOR p IN SELECT pr.oid,pr.proname,pr.proconfig,pr.proacl,pr.proowner,n.nspname FROM pg_proc pr JOIN pg_namespace n ON n.oid=pr.pronamespace
 WHERE n.nspname LIKE 'verivaro%' AND pr.prosecdef LOOP
  IF NOT EXISTS(SELECT 1 FROM unnest(p.proconfig) v WHERE v LIKE 'search_path=pg_catalog%')
  OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')
  THEN RAISE EXCEPTION 'unsafe definer boundary: %.%',p.nspname,p.proname; END IF;
 END LOOP;
 -- Audit sensitive functions across every service role including future roles.
 FOR r IN SELECT oid,rolname FROM pg_roles WHERE rolname LIKE 'verivaro_%' LOOP
  FOR p IN SELECT pr.oid,pr.proname,n.nspname FROM pg_proc pr JOIN pg_namespace n ON n.oid=pr.pronamespace
   WHERE n.nspname IN ('verivaro_identity','verivaro_sharing','verivaro_admission','verivaro_monitor','verivaro_alerting','verivaro_recovery','verivaro_mutation','verivaro_ingestion','verivaro_tenant_admin','verivaro_verification') LOOP
   IF has_function_privilege(r.oid,p.oid,'EXECUTE') AND NOT (
    (r.rolname='verivaro_evidence_auditor' AND p.nspname='verivaro_ingestion' AND p.proname='attestation_inventory') OR
    (r.rolname='verivaro_evidence_reader' AND p.nspname='verivaro_ingestion' AND p.proname IN ('fetch_object','fetch_customer_package_object')) OR
    (r.rolname='verivaro_evidence_ingestor' AND p.nspname='verivaro_ingestion' AND p.proname IN ('authorize_upload','commit_upload_v2','authorize_capture','commit_capture')) OR
    (r.rolname='verivaro_runtime' AND p.nspname='verivaro_ingestion' AND p.proname='list_evidence_metadata') OR
    (r.rolname='verivaro_tenant_operator' AND p.nspname='verivaro_tenant_admin' AND p.proname IN ('bootstrap','approve_enrollment','complete_transfer','issue_invitation')) OR
    (r.rolname='verivaro_runtime' AND p.nspname='verivaro_tenant_admin' AND p.proname IN ('request_enrollment','directory','change_access','request_transfer','accept_transfer','pending_transfers','enrollment_requests','cancel_invitation','redeem_invitation')) OR
    (r.rolname='verivaro_runtime' AND p.nspname='verivaro_verification' AND p.proname IN ('write_requirement','review_requirement','link_evidence','review_link','assessment','import_source_line','import_source_line_v2','import_source_line_v3','import_office_source','import_ocr_source','review_ocr_source','propose_ocr_correction','review_ocr_correction','prepare_submission','review_submission','authorize_submission','read_submission','submission_list','inspect_submission','propose_dependency','review_dependency','propose_dependency_removal','review_dependency_removal','dependency_removal_candidates','write_milestone','propose_evidence_window','review_evidence_window','prooflock_records','write_prooflock_alert_policy','prooflock_insights_records','propose_recovery','review_recovery','prooflock_recovery_records','write_financial_record','review_financial_record','financial_records','record_chronology','review_chronology','project_archive_records','grant_acknowledgement','revoke_acknowledgement','record_acknowledgement','acknowledgement_list','assign_resolution','advance_resolution','resolution_list','grant_customer_package','revoke_customer_package','preview_customer_package','read_customer_package','customer_package_list','trustproof_page','write_export_template','export_template_list','read_export_template','publish_organisation_template','organisation_template_list','import_organisation_template','write_lifecycle_event','lifecycle_records','portable_archive_inventory','write_evidence_metadata','review_evidence_metadata','evidence_intelligence_records','pin_document_condition','record_import_lineage','import_lineage_list')) OR
    (r.rolname='verivaro_runtime' AND p.nspname='verivaro_mutation' AND p.proname IN ('rename_project','create_project','project_directory','change_project_access','archive_project','project_report')) OR
    (r.rolname='verivaro_runtime' AND p.nspname='verivaro_sharing' AND p.proname IN ('issue_share','issue_recipient_share','revoke_share','request_evidence_release','review_evidence_release','workspace_tenants','release_workspace','workspace_issue_recipient','workspace_revoke_recipient','workspace_shares')) OR
    (r.rolname='verivaro_identity_service' AND p.nspname='verivaro_identity' AND p.proname IN ('begin_login','redeem_login','revoke_session','store_browser_flow','take_browser_flow','store_browser_session','read_browser_session','logout_browser','logout_all_browser','record_auth')) OR
    (r.rolname='verivaro_api_admission' AND p.nspname='verivaro_admission' AND p.proname IN ('api_peer','api_actor')) OR
    (r.rolname='verivaro_identity_events' AND p.nspname='verivaro_identity' AND p.proname='apply_provider_event') OR
    (r.rolname='verivaro_identity_provisioner' AND p.nspname='verivaro_identity' AND p.proname IN ('provision_binding','disable_binding')) OR
    (r.rolname='verivaro_recovery_service' AND p.nspname='verivaro_identity' AND p.proname IN ('disable_actor','request_recovery','recover_actor')) OR
    (r.rolname='verivaro_recovery_approver' AND p.nspname='verivaro_identity' AND p.proname='approve_recovery') OR
    (r.rolname='verivaro_release_service' AND p.nspname='verivaro_sharing' AND p.proname IN ('register_approved_export','preflight_approved_export','revoke_export')) OR
    (r.rolname='verivaro_share_gateway' AND p.nspname='verivaro_sharing' AND p.proname='resolve_share') OR
    (r.rolname='verivaro_recipient_gateway' AND p.nspname='verivaro_sharing' AND p.proname='resolve_recipient_share') OR
    (r.rolname='verivaro_admission_service' AND p.nspname='verivaro_admission' AND p.proname IN ('acquire','release','finish')) OR
    (r.rolname='verivaro_admission_reconciler' AND p.nspname='verivaro_admission' AND p.proname='reconcile') OR
    (r.rolname='verivaro_monitor_worker' AND p.nspname='verivaro_monitor' AND p.proname IN ('evaluate','health')) OR
    (r.rolname='verivaro_monitor_reader' AND p.nspname='verivaro_monitor' AND p.proname IN ('health','list_open','recent_alerts','alert_delivery_health')) OR
    (r.rolname='verivaro_incident_operator' AND p.nspname='verivaro_monitor' AND p.proname IN ('health','list_open','recent_alerts','alert_delivery_health','acknowledge','resolve_incident')) OR
    (r.rolname='verivaro_alert_sender' AND p.nspname='verivaro_alerting' AND p.proname IN ('claim','finish')) OR
    (r.rolname='verivaro_restore_reviewer' AND p.nspname='verivaro_recovery' AND p.proname IN ('attest_review','review_status'))
   ) THEN RAISE EXCEPTION 'cross-service execute privilege: % %.%',r.rolname,p.nspname,p.proname; END IF;
  END LOOP;
 END LOOP;
 RAISE NOTICE 'full G1 role and definer audit passed (% roles)',role_count;
END $audit$;

-- The main EXECUTE allowlist is organised by routine *name*, not argument
-- signature. Reject multiple service-executable overloads under one approved
-- schema/name to stop a new signature inheriting an existing name's approval.
DO $overloads$
DECLARE duplicate record;
BEGIN
 SELECT r.rolname AS service_role,n.nspname AS routine_schema,p.proname AS routine_name,
        count(*)::integer AS signatures
 INTO duplicate
 FROM pg_catalog.pg_roles r
 CROSS JOIN pg_catalog.pg_proc p
 JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE r.rolname LIKE 'verivaro_%'
   AND n.nspname LIKE 'verivaro%'
   -- pgcrypto is installed under verivaro_private and legitimately overloads
   -- names. A service lacking schema USAGE cannot invoke those routines.
   AND n.nspname <> 'verivaro_private'
   AND pg_catalog.has_schema_privilege(r.oid,n.oid,'USAGE')
   AND p.prokind IN ('f','p')
   AND pg_catalog.has_function_privilege(r.oid,p.oid,'EXECUTE')
 GROUP BY r.rolname,n.nspname,p.proname
 HAVING count(*)>1
 LIMIT 1;
 IF FOUND THEN
   RAISE EXCEPTION 'ambiguous service function allowlist: % %.% (% executable signatures)',
     duplicate.service_role,duplicate.routine_schema,duplicate.routine_name,duplicate.signatures;
 END IF;
 RAISE NOTICE 'approved_function_overload_gate_passed';
END $overloads$;

-- Disposable negative probe: verify the same privilege query would identify
-- an additional grantable signature under an already allowed name. ROLLBACK
-- leaves no callable function or role grant after the test.
BEGIN;
CREATE FUNCTION verivaro_verification.assessment(text) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog
AS $probe$ SELECT '{}'::jsonb $probe$;
REVOKE ALL ON FUNCTION verivaro_verification.assessment(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.assessment(text) TO verivaro_runtime;
DO $negative$
DECLARE signatures integer;
BEGIN
 SELECT count(*)::integer INTO signatures
 FROM pg_catalog.pg_proc p
 JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='verivaro_verification'
   AND p.proname='assessment'
   AND pg_catalog.has_function_privilege('verivaro_runtime',p.oid,'EXECUTE');
 IF signatures<2 THEN
   RAISE EXCEPTION 'synthetic function overload was not detected';
 END IF;
 RAISE NOTICE 'synthetic_unapproved_function_overload_detected';
END $negative$;
ROLLBACK;
