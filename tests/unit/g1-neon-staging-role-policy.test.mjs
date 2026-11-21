import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {G1_STAGING_ROLES,assertG1StagingMigrationPreflight,
 assertG1StagingMigrationRoleAudit}
 from '../../src/security/g1-neon-staging-role-policy.mjs';

const baseline=Object.freeze({
 database_name:'neondb',observer_role:G1_STAGING_ROLES.reader,
 postgres_version_num:160016,planned_migrator_role_collisions:0,
 source_service_roles:0,existing_app_schemas:0,
 pgcrypto_installed_count:0,restricted_reader_valid:1,
 reader_membership_count:0,reader_can_create_database_objects:false,
 reader_can_create_public_objects:false
});
const plainRole=(name)=>({
 role_name:name,can_login:name===G1_STAGING_ROLES.reader||name===G1_STAGING_ROLES.login,
 is_superuser:false,can_create_roles:false,can_create_databases:false,
 can_replicate:false,can_bypass_rls:false,inherits_roles:false,
 neon_admin_member:false,can_create_in_database:name===G1_STAGING_ROLES.owner
});
const edge=(member,granted)=>({
 member_role:member,granted_role:granted,
 inherit_option:false,set_option:true,admin_option:false
});
const after=()=>({
 database_name:'neondb',observer_role:G1_STAGING_ROLES.reader,
 postgres_version_num:160016,
 roles:Object.values(G1_STAGING_ROLES).map(plainRole),
 memberships:[
  edge(G1_STAGING_ROLES.executor,G1_STAGING_ROLES.owner),
  edge(G1_STAGING_ROLES.login,G1_STAGING_ROLES.executor)
 ]
});
const rejected=fn=>assert.throws(fn,/G1 staging role gate rejected/);

test('Neon PG16 clean preflight is advisory only, never migration approval',()=>{
 const result=assertG1StagingMigrationPreflight(baseline);
 assert.equal(result.isolatedPreflightVerified,true);
 assert.equal(result.privilegedBootstrapApproved,false);
 assert.equal(result.credentialsProvisioned,false);
 assert.equal(result.migrationAuthorized,false);
 assert.equal(result.productionApproved,false);
});

test('Neon preflight rejects cross-project, privileged observer, dirty and unknown states',()=>{
 for(const change of [
  {database_name:'postgres'},{observer_role:'neondb_owner'},
  {postgres_version_num:180007},{postgres_version_num:'160016'},
  {planned_migrator_role_collisions:1},{source_service_roles:21},
  {existing_app_schemas:1},{pgcrypto_installed_count:1},
  {restricted_reader_valid:0},{reader_membership_count:1},
  {reader_can_create_database_objects:true},{reader_can_create_public_objects:true},
  {planned_migrator_role_collisions:null},{restricted_reader_valid:undefined}
 ])rejected(()=>assertG1StagingMigrationPreflight({...baseline,...change}));
});

test('separate staged owner/executor/ledger/login catalogue roles enforce SET-only edges',()=>{
 const result=assertG1StagingMigrationRoleAudit(after());
 assert.equal(result.catalogueRoleSeparationVerified,true);
 assert.equal(result.approvedSetOnlyMemberships,2);
 assert.equal(result.credentialCustodyVerified,false);
 assert.equal(result.independentSignerVerified,false);
 assert.equal(result.migrationAuthorized,false);
 assert.equal(result.productionApproved,false);
});

test('role audit rejects missing, duplicate and escalated PostgreSQL principals',()=>{
 const change=(name,patch)=>({
  ...after(),roles:after().roles.map(r=>r.role_name===name?{...r,...patch}:r)
 });
 for(const name of Object.values(G1_STAGING_ROLES)){
  for(const patch of [
   {is_superuser:true},{can_create_roles:true},{can_create_databases:true},
   {can_replicate:true},{can_bypass_rls:true},{inherits_roles:true},
   {neon_admin_member:true},{can_create_in_database:null}
  ])rejected(()=>assertG1StagingMigrationRoleAudit(change(name,patch)));
 }
 rejected(()=>assertG1StagingMigrationRoleAudit(change(G1_STAGING_ROLES.login,{can_login:false})));
 rejected(()=>assertG1StagingMigrationRoleAudit(change(G1_STAGING_ROLES.owner,{can_login:true})));
 rejected(()=>assertG1StagingMigrationRoleAudit(change(G1_STAGING_ROLES.owner,{can_create_in_database:false})));
 rejected(()=>assertG1StagingMigrationRoleAudit(change(G1_STAGING_ROLES.reader,{can_create_in_database:true})));
 const d=after();
 rejected(()=>assertG1StagingMigrationRoleAudit({...d,roles:d.roles.slice(0,4)}));
 rejected(()=>assertG1StagingMigrationRoleAudit({...d,roles:[...d.roles.slice(0,4),d.roles[0]]}));
 rejected(()=>assertG1StagingMigrationRoleAudit({...d,observer_role:'neondb_owner'}));
 rejected(()=>assertG1StagingMigrationRoleAudit({...d,roles:null}));
});

test('role audit rejects unsolicited memberships, inheritance, ADMIN, missing edges',()=>{
 const d=after();
 rejected(()=>assertG1StagingMigrationRoleAudit({...d,memberships:d.memberships.slice(0,1)}));
 rejected(()=>assertG1StagingMigrationRoleAudit({...d,memberships:[...d.memberships,edge('neondb_owner',G1_STAGING_ROLES.owner)]}));
 // Exact live Neon PG16 catalog behavior: the powerful database owner is
 // recorded as an ADMIN-option member of the SQL-created reader. This does
 // NOT give the reader privileges but fails the strict custody gate.
 rejected(()=>assertG1StagingMigrationRoleAudit({...d,memberships:[
  ...d.memberships,{
   member_role:'neondb_owner',granted_role:G1_STAGING_ROLES.reader,
   inherit_option:false,set_option:false,admin_option:true
  }
 ]}));
 rejected(()=>assertG1StagingMigrationRoleAudit({...d,memberships:[edge(G1_STAGING_ROLES.reader,G1_STAGING_ROLES.owner),d.memberships[1]]}));
 rejected(()=>assertG1StagingMigrationRoleAudit({...d,memberships:[d.memberships[0],d.memberships[0]]}));
 for(const patch of [
  {inherit_option:true},{set_option:false},{admin_option:true},
  {set_option:null},{member_role:null},{granted_role:'neon_superuser'}
 ])rejected(()=>assertG1StagingMigrationRoleAudit({
  ...d,memberships:[{...d.memberships[0],...patch},d.memberships[1]]
 }));
});

test('readiness and audit files are non-mutating SQL observations',async()=>{
 for(const path of ['db/security/g1-neon-staging-preflight.sql',
  'db/security/g1-neon-staging-role-audit.sql']){
  const sql=(await readFile(path,'utf8')).replace(/--[^\n]*/g,'');
  assert.match(sql.trim(),/^(SELECT|WITH)\s/i);
  assert.doesNotMatch(sql,/\b(CREATE|ALTER|DROP|TRUNCATE|INSERT|UPDATE|DELETE|GRANT|REVOKE|CALL)\s+/i);
  assert.match(sql,/current_user/);
  assert.match(sql,/pg_catalog/);
 }
});
