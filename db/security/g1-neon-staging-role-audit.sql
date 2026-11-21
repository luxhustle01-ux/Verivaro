-- G1 staging role post-bootstrap audit, READ ONLY, never an approval.
-- Do not confuse this catalog snapshot with independent DBA custody or authorization.
-- Designed for pinned vv_g1_staging_reader, AFTER separately approved bootstrap,
-- but BEFORE any Verivaro migrations. Missing/extra roles and role grants fail JS gate.
WITH expected(role_name) AS (
 VALUES ('vv_g1_staging_reader'),('vv_g1_staging_schema_owner'),
  ('vv_g1_staging_migration_executor'),('vv_g1_staging_ledger_custodian'),
  ('vv_g1_staging_migration_login')
),
observed AS (
 SELECT e.role_name,r.rolcanlogin AS can_login,
  r.rolsuper AS is_superuser,r.rolcreaterole AS can_create_roles,
  r.rolcreatedb AS can_create_databases,r.rolreplication AS can_replicate,
  r.rolbypassrls AS can_bypass_rls,r.rolinherit AS inherits_roles,
  CASE WHEN r.oid IS NULL THEN NULL
    ELSE pg_catalog.pg_has_role(r.rolname,'neon_superuser','MEMBER')
  END AS neon_admin_member,
  CASE WHEN r.oid IS NULL THEN NULL
    ELSE pg_catalog.has_database_privilege(r.rolname,current_database(),'CREATE')
  END AS can_create_in_database
 FROM expected e LEFT JOIN pg_catalog.pg_roles r ON r.rolname=e.role_name
),
role_memberships AS (
 SELECT member.rolname AS member_role,granted.rolname AS granted_role,
  m.inherit_option,m.set_option,m.admin_option
 FROM pg_catalog.pg_auth_members m
 JOIN pg_catalog.pg_roles member ON member.oid=m.member
 JOIN pg_catalog.pg_roles granted ON granted.oid=m.roleid
 WHERE member.rolname IN (SELECT role_name FROM expected)
    OR granted.rolname IN (SELECT role_name FROM expected)
)
SELECT current_database() AS database_name,current_user AS observer_role,
 current_setting('server_version_num')::integer AS postgres_version_num,
 (SELECT COALESCE(jsonb_agg(to_jsonb(observed) ORDER BY role_name),'[]'::jsonb)
  FROM observed) AS roles,
 (SELECT COALESCE(jsonb_agg(to_jsonb(role_memberships)
   ORDER BY member_role,granted_role),'[]'::jsonb) FROM role_memberships)
  AS memberships;
