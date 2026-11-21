-- G1 staging preflight. READ ONLY; never creates or changes roles, schemas or secrets.
-- Run only against the isolated PG16 Neon project under vv_g1_staging_reader.
-- Project identity must be verified separately by the operator/connector.
SELECT current_database() AS database_name,
 current_user AS observer_role,
 current_setting('server_version_num')::integer AS postgres_version_num,
 (SELECT count(*)::integer FROM pg_catalog.pg_roles WHERE rolname IN (
  'vv_g1_staging_schema_owner','vv_g1_staging_migration_executor',
  'vv_g1_staging_ledger_custodian','vv_g1_staging_migration_login'
 )) AS planned_migrator_role_collisions,
 (SELECT count(*)::integer FROM pg_catalog.pg_roles WHERE rolname LIKE 'verivaro_%')
  AS source_service_roles,
 (SELECT count(*)::integer FROM pg_catalog.pg_namespace WHERE nspname LIKE 'verivaro%')
  AS existing_app_schemas,
 (SELECT count(*)::integer FROM pg_catalog.pg_extension WHERE extname='pgcrypto')
  AS pgcrypto_installed_count,
 (SELECT count(*)::integer FROM pg_catalog.pg_roles WHERE rolname='vv_g1_staging_reader'
  AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
  AND NOT rolbypassrls AND NOT rolinherit AND NOT rolreplication)
  AS restricted_reader_valid,
 (SELECT count(*)::integer FROM pg_catalog.pg_auth_members m
  JOIN pg_catalog.pg_roles member ON member.oid=m.member
  WHERE member.rolname='vv_g1_staging_reader') AS reader_membership_count,
 pg_catalog.has_database_privilege('vv_g1_staging_reader',current_database(),'CREATE')
  AS reader_can_create_database_objects,
 pg_catalog.has_schema_privilege('vv_g1_staging_reader','public','CREATE')
  AS reader_can_create_public_objects;
