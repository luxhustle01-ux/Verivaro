// Fail-closed privilege inventory for production migration planning.
// SQL keyword scanning is advisory: a database reviewer must verify each DDL.
const problem=msg=>{throw Error('migration role policy rejected: '+msg);};
const allowed=/^db\/migrations\/[0-9]{4}_[a-z0-9_]+\.sql$/;
export function inventoryPrivilegedMigrations(migrations){
 if(!Array.isArray(migrations)||migrations.length===0||migrations.length>500)
  problem('missing or oversized catalogue');
 const findings=[];
 let expected=1;
 for(const m of migrations){
  if(!m||!allowed.test(m.path)||parseInt(m.path.slice(14,18),10)!==expected||
   typeof m.source!=='string'||!m.source)problem('untrusted migration input or order');
  // Drop SQL comments; this intentionally errs on the side of review-required.
  const sql=m.source.replace(/--[^\r\n]*/g,' ');
  const classes=[];
  for(const [name,re] of [
   ['ROLE_DDL',/\b(?:CREATE|ALTER|DROP)\s+ROLE\b/i],
   ['ROLE_MEMBERSHIP',/\bGRANT\s+[a-z_][a-z_0-9]*\s+TO\s+[a-z_][a-z_0-9]*/i],
   ['EXTENSION_DDL',/\b(?:CREATE|ALTER|DROP)\s+EXTENSION\b/i],
   ['SYSTEM_ADMIN',/\b(?:ALTER\s+SYSTEM|CREATE\s+DATABASE|CREATE\s+TABLESPACE)\b/i]
  ])if(re.test(sql))classes.push(name);
  if(classes.length)findings.push({version:expected,path:m.path,classes});
  expected++;
 }
 return Object.freeze({
  fileCount:migrations.length,privilegedFiles:findings,
  requiresSeparatelyApprovedBootstrap:findings.length>0,
  productionAutomaticApplyApproved:false,
  serviceRolesMayRunMigrations:false
 });
}
// Role names are fixed to the separately reviewed bootstrap contract. All
// supplied role attributes MUST be explicit observations; an absent field is
// neither a safe default nor independent permission evidence.
export const PRODUCTION_ROLES=Object.freeze({
 schemaOwner:'vv_production_schema_owner',
 executor:'vv_production_migration_executor',
 ledgerCustodian:'vv_production_ledger_custodian',
 runtime:'verivaro_runtime',
 mandatoryAttributes:Object.freeze([
  'NOSUPERUSER','NOCREATEDB','NOCREATEROLE','NOREPLICATION',
  'NOBYPASSRLS','NOINHERIT'
 ]),
 runtimeMustNotBeMember:true
});
const ROLE_PROPERTIES=Object.freeze([
 'superuser','createRole','createDb','bypassRls','replication',
 'inherit','canLogin','canCreateInDatabase'
]);
const isRole=r=>r&&typeof r==='object'&&!Array.isArray(r)&&
 typeof r.name==='string'&&ROLE_PROPERTIES.every(p=>typeof r[p]==='boolean');

// This routine is *only* a fail-closed, read-only catalogue snapshot policy.
// Application credentials, external signer custody and trusted provenance
// must be approved independently. It never authorises a staging SQL write.
export function validateRoleSnapshot({owner,executor,custodian,application,memberships}={}){
 const expected=[
  [owner,PRODUCTION_ROLES.schemaOwner],
  [executor,PRODUCTION_ROLES.executor],
  [custodian,PRODUCTION_ROLES.ledgerCustodian],
  [application,PRODUCTION_ROLES.runtime]
 ];
 if(expected.some(([r,name])=>!isRole(r)||r.name!==name))
  problem('missing or wrongly identified role inventory');
 if(new Set(expected.map(([r])=>r.name)).size!==expected.length)
  problem('role principal collision');
 for(const [r,name] of expected){
  if(r.superuser||r.createRole||r.createDb||r.bypassRls||
     r.replication||r.inherit||r.canLogin||
     r.canCreateInDatabase!==(name===PRODUCTION_ROLES.schemaOwner))
   problem('privileged or unverified role attributes: '+name);
 }
 // The only allowed grant touching the four protected principals is
 // executor -> schema owner with SET TRUE, INHERIT FALSE, ADMIN FALSE.
 // A caller must supply a COMPLETE inbound and outbound membership inventory;
 // a boolean "can SET" assertion is insufficient to prove no hidden edge.
 if(!Array.isArray(memberships)||memberships.length!==1)
  problem('unverified or unexpected role membership inventory');
 const e=memberships[0];
 if(!e||typeof e!=='object'||Array.isArray(e)||
    e.member!==PRODUCTION_ROLES.executor||
    e.grantedRole!==PRODUCTION_ROLES.schemaOwner||
    e.inherit!==false||e.set!==true||e.admin!==false)
  problem('unsafe or incomplete SET-only membership');
 return Object.freeze({
  roleSeparationVerified:true,ownerLoginDisabled:true,
  executorLoginDisabledUntilProvisioned:true,
  ledgerCustodianSeparated:true,
  independentlyWitnessed:false,
  productionApproval:false
 });
}
