// Non-mutating G1 Neon staging assessment. Never authorizes role creation or migrations.
const reject=message=>{throw Error('G1 staging role gate rejected: '+message);};
export const G1_STAGING_ROLES=Object.freeze({
 reader:'vv_g1_staging_reader',
 owner:'vv_g1_staging_schema_owner',
 executor:'vv_g1_staging_migration_executor',
 custodian:'vv_g1_staging_ledger_custodian',
 login:'vv_g1_staging_migration_login'
});
const names=Object.freeze(Object.values(G1_STAGING_ROLES));
const number=x=>Number.isInteger(x)&&x>=0;
const bool=x=>typeof x==='boolean';
const all=(object,fields)=>object&&typeof object==='object'&&!Array.isArray(object)&&
 fields.every(field=>Object.hasOwn(object,field));
const preflightFields=[
 'database_name','observer_role','postgres_version_num',
 'planned_migrator_role_collisions','source_service_roles','existing_app_schemas',
 'pgcrypto_installed_count','restricted_reader_valid','reader_membership_count',
 'reader_can_create_database_objects','reader_can_create_public_objects'
];
export function assertG1StagingMigrationPreflight(observation){
 if(!all(observation,preflightFields))reject('missing or malformed preflight observation');
 if(observation.database_name!=='neondb'||
    observation.observer_role!==G1_STAGING_ROLES.reader||
    !Number.isInteger(observation.postgres_version_num)||
    observation.postgres_version_num<160000||
    observation.postgres_version_num>=170000)
  reject('wrong database, observer or PostgreSQL major version');
 for(const key of ['planned_migrator_role_collisions','source_service_roles',
   'existing_app_schemas','pgcrypto_installed_count','reader_membership_count'])
  if(!number(observation[key])||observation[key]!==0)
   reject('dirty or ambiguous staging baseline: '+key);
 if(observation.restricted_reader_valid!==1||
    observation.reader_can_create_database_objects!==false||
    observation.reader_can_create_public_objects!==false)
  reject('reader identity or access contract broken');
 return Object.freeze({
  isolatedPreflightVerified:true,postgresMajor:16,
  privilegedBootstrapApproved:false,credentialsProvisioned:false,
  migrationAuthorized:false,productionApproved:false
 });
}
// Post-bootstrap, pre-migration verification for a separate, deliberately
// approved staged operator. This checks PostgreSQL catalogue data only; it
// cannot attest to independently controlled keys, TLS or DBA identities.
export function assertG1StagingMigrationRoleAudit(observation){
 if(!all(observation,['database_name','observer_role','postgres_version_num',
      'roles','memberships'])||!Array.isArray(observation.roles)||
    !Array.isArray(observation.memberships)||observation.roles.length!==names.length||
    observation.database_name!=='neondb'||
    observation.observer_role!==G1_STAGING_ROLES.reader||
    !Number.isInteger(observation.postgres_version_num)||
    observation.postgres_version_num<160000||observation.postgres_version_num>=170000)
  reject('missing or wrong-source role audit');
 const seen=new Set();
 for(const row of observation.roles){
  if(!all(row,['role_name','can_login','is_superuser','can_create_roles',
    'can_create_databases','can_replicate','can_bypass_rls','inherits_roles',
    'neon_admin_member','can_create_in_database'])||
    !names.includes(row.role_name)||seen.has(row.role_name))
   reject('missing, duplicated or unapproved role');
  seen.add(row.role_name);
  for(const k of ['can_login','is_superuser','can_create_roles',
    'can_create_databases','can_replicate','can_bypass_rls','inherits_roles',
    'neon_admin_member','can_create_in_database'])
   if(!bool(row[k]))reject('unknown role attribute: '+k);
  if(row.can_login!==(row.role_name===G1_STAGING_ROLES.login||
      row.role_name===G1_STAGING_ROLES.reader)||
     row.is_superuser||row.can_create_roles||row.can_create_databases||
     row.can_replicate||row.can_bypass_rls||row.inherits_roles||
     row.neon_admin_member||
     row.can_create_in_database!==(row.role_name===G1_STAGING_ROLES.owner))
   reject('escalated role or database grants: '+row.role_name);
 }
 if(seen.size!==names.length)reject('incomplete role inventory');
 const approved=[
  [G1_STAGING_ROLES.executor,G1_STAGING_ROLES.owner],
  [G1_STAGING_ROLES.login,G1_STAGING_ROLES.executor]
 ];
 if(observation.memberships.length!==approved.length)
  reject('unexpected global role membership');
 const edges=new Set();
 for(const edge of observation.memberships){
  if(!all(edge,['member_role','granted_role','inherit_option',
      'set_option','admin_option'])||
     typeof edge.member_role!=='string'||typeof edge.granted_role!=='string'||
     !bool(edge.inherit_option)||!bool(edge.set_option)||!bool(edge.admin_option)||
     edge.inherit_option!==false||edge.set_option!==true||
     edge.admin_option!==false)
    reject('unsafe or ambiguous membership options');
  const key=edge.member_role+'>'+edge.granted_role;
  if(edges.has(key)||!approved.some(([a,b])=>a===edge.member_role&&b===edge.granted_role))
   reject('unapproved membership edge');
  edges.add(key);
 }
 if(edges.size!==approved.length)reject('incomplete SET-only membership chain');
 return Object.freeze({
  catalogueRoleSeparationVerified:true,approvedSetOnlyMemberships:2,
  readerPrivilegesUnaffected:true,credentialCustodyVerified:false,
  independentSignerVerified:false,migrationAuthorized:false,
  productionApproved:false
 });
}
