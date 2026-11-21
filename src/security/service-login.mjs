// Shared PostgreSQL connection-boundary validation. This is a deployment
// misconfiguration guard, not a substitute for PostgreSQL ACL enforcement.
// PostgreSQL 16 grants have independent SET, INHERIT and ADMIN options:
// membership alone does not establish safe or usable SET ROLE authority.
const roles=new Set(['verivaro_runtime','verivaro_share_gateway','verivaro_recipient_gateway','verivaro_admission_service','verivaro_monitor_worker','verivaro_monitor_reader','verivaro_alert_sender','verivaro_identity_service','verivaro_identity_events','verivaro_api_admission','verivaro_evidence_ingestor','verivaro_evidence_reader','verivaro_evidence_auditor','verivaro_release_service','verivaro_tenant_operator']);
const name=/^[a-z][a-z0-9_]{0,62}$/;
export function validateServiceIdentity(role,expectedLogin){
 if(!roles.has(role)||(typeof expectedLogin!=='string'||!name.test(expectedLogin)||expectedLogin===role||expectedLogin.startsWith('pg_')||expectedLogin.startsWith('verivaro_')))throw Error('invalid service identity configuration');
}
const CHECK=String.raw`SELECT
 l.rolname::text AS login_name,
 (
 l.rolsuper OR l.rolbypassrls OR l.rolcreaterole OR l.rolcreatedb OR l.rolreplication OR l.rolinherit OR NOT l.rolcanlogin
 -- A reused connection must be in its original authenticated login context;
 -- an already-activated SET ROLE is not an admissible checkout state.
 OR current_user<>session_user
 OR (l.rolvaliduntil IS NOT NULL AND l.rolvaliduntil<=clock_timestamp())
 OR g.rolsuper OR g.rolbypassrls OR g.rolcreaterole OR g.rolcreatedb OR g.rolreplication OR g.rolinherit
 -- No dedicated login/service-group startup GUC may silently alter session
 -- policy. Includes both ALTER ROLE SET and ALTER ROLE IN DATABASE SET.
 -- Also deny ALTER DATABASE SET defaults on the connected database:
 -- unlike role-specific settings, these appear with setrole=0.
 -- This is a strict zero-overrides contract, including benign settings.
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_db_role_setting s
   WHERE s.setrole IN (l.oid,g.oid)
     OR (s.setrole=0 AND s.setdatabase=(
       SELECT d.oid FROM pg_catalog.pg_database d
       WHERE d.datname=current_database())))
 -- The allowed NOLOGIN group must not hold cluster-wide database ownership,
 -- independent database/schema CREATE, or explicit parameter SET authority.
 -- These privileges become usable as soon as the login SET ROLEs to g.
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_database d
   WHERE d.datdba=g.oid OR has_database_privilege(g.oid,d.oid,'CREATE'))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n
   WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'
     AND has_schema_privilege(g.oid,n.oid,'CREATE'))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_parameter_acl p
   CROSS JOIN LATERAL pg_catalog.aclexplode(p.paracl) a
   WHERE a.grantee=g.oid)
 OR NOT pg_has_role(l.oid,g.oid,'MEMBER')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles x WHERE x.oid NOT IN (l.oid,g.oid) AND pg_has_role(l.oid,x.oid,'MEMBER'))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles x WHERE x.oid<>g.oid AND pg_has_role(g.oid,x.oid,'MEMBER'))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=l.oid AND m.admin_option)
 OR has_database_privilege(l.oid,current_database(),'CREATE')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND has_schema_privilege(l.oid,n.oid,'CREATE'))
 -- Refuse explicit login ACLs, including system-catalog grants, and
 -- ownership of application objects outside the designated NOLOGIN group.
 -- A dedicated login must also not own another database in this cluster.
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n
   LEFT JOIN LATERAL pg_catalog.aclexplode(n.nspacl) a ON true
   WHERE a.grantee=l.oid OR (n.nspname NOT LIKE 'pg_%'
     AND n.nspname<>'information_schema' AND n.nspowner=l.oid))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c
   JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   LEFT JOIN LATERAL pg_catalog.aclexplode(c.relacl) a ON true
   WHERE a.grantee=l.oid OR (n.nspname NOT LIKE 'pg_%'
     AND n.nspname<>'information_schema' AND c.relowner=l.oid))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
   JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   LEFT JOIN LATERAL pg_catalog.aclexplode(p.proacl) a ON true
   WHERE a.grantee=l.oid OR (n.nspname NOT LIKE 'pg_%'
     AND n.nspname<>'information_schema' AND p.proowner=l.oid))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_type t
   JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
   LEFT JOIN LATERAL pg_catalog.aclexplode(t.typacl) a ON true
   WHERE a.grantee=l.oid OR (n.nspname NOT LIKE 'pg_%'
     AND n.nspname<>'information_schema' AND t.typowner=l.oid))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_default_acl d
   LEFT JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) a ON true
   WHERE a.grantee=l.oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_database d
   LEFT JOIN LATERAL pg_catalog.aclexplode(d.datacl) a ON true
   WHERE d.datdba=l.oid OR a.grantee=l.oid)
 -- PostgreSQL 16 grants can also target configuration parameters,
 -- large objects, tablespaces, procedural languages and FDW objects.
 -- Some of these can carry powerful non-table capabilities, such as SET
 -- on session_replication_role, independent of the service group membership.
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_parameter_acl p
   CROSS JOIN LATERAL pg_catalog.aclexplode(p.paracl) a
   WHERE a.grantee=l.oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_largeobject_metadata lo
   LEFT JOIN LATERAL pg_catalog.aclexplode(lo.lomacl) a ON true
   WHERE lo.lomowner=l.oid OR a.grantee=l.oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_tablespace s
   LEFT JOIN LATERAL pg_catalog.aclexplode(s.spcacl) a ON true
   WHERE s.spcowner=l.oid OR a.grantee=l.oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_language lang
   LEFT JOIN LATERAL pg_catalog.aclexplode(lang.lanacl) a ON true
   WHERE lang.lanowner=l.oid OR a.grantee=l.oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_foreign_data_wrapper fdw
   LEFT JOIN LATERAL pg_catalog.aclexplode(fdw.fdwacl) a ON true
   WHERE fdw.fdwowner=l.oid OR a.grantee=l.oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_foreign_server fs
   LEFT JOIN LATERAL pg_catalog.aclexplode(fs.srvacl) a ON true
   WHERE fs.srvowner=l.oid OR a.grantee=l.oid)
 OR (l.oid<>g.oid AND (
  g.rolcanlogin OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m
    WHERE m.member=l.oid AND m.roleid=g.oid AND m.inherit_option=false
      AND m.set_option=true AND m.admin_option=false)
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname LIKE 'verivaro%' AND has_schema_privilege(l.oid,n.oid,'USAGE'))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_class t JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
    WHERE n.nspname LIKE 'verivaro%' AND t.relkind IN ('r','p','v','m','f')
    AND (t.relowner=l.oid OR has_table_privilege(l.oid,t.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
    OR has_any_column_privilege(l.oid,t.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
    WHERE n.nspname LIKE 'verivaro%' AND (p.proowner=l.oid OR a.grantee=l.oid))
 ))
 OR (l.rolname::text<>$2 OR l.oid=g.oid OR g.rolcanlogin)
 ) AS privileged
 FROM pg_catalog.pg_roles l CROSS JOIN pg_catalog.pg_roles g
 WHERE l.rolname=session_user AND g.rolname::text=$1`;
export async function assertServiceLogin(client,role,expectedLogin){
 validateServiceIdentity(role,expectedLogin);
 // Discarded session may still have unsafe role/database default search_path.
 await client.query('SET search_path TO pg_catalog');
 const r=await client.query(CHECK,[role,expectedLogin]);
 if(r.rows.length!==1||r.rows[0].privileged!==false||r.rows[0].login_name!==expectedLogin)throw Error('unsafe service login');
}
