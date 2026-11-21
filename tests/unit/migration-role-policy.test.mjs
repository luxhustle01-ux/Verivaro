import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {inventoryPrivilegedMigrations,PRODUCTION_ROLES,validateRoleSnapshot}
 from '../../src/security/migration-role-policy.mjs';

const source='BEGIN;\nCREATE ROLE scoped_reader NOLOGIN;\nCOMMIT;';
test('privileged role changes are excluded from automatic least privilege rollout',()=>{
 const report=inventoryPrivilegedMigrations([{path:'db/migrations/0001_sample.sql',source}]);
 assert.equal(report.requiresSeparatelyApprovedBootstrap,true);
 assert.equal(report.productionAutomaticApplyApproved,false);
 assert.deepEqual(report.privilegedFiles[0].classes,['ROLE_DDL']);
});
test('pure schema changes require further review but have no detected role bootstrap commands',()=>{
 const report=inventoryPrivilegedMigrations([
  {path:'db/migrations/0001_sample.sql',source:'BEGIN;\nCREATE TABLE test(id integer);\nCOMMIT;'}]);
 assert.equal(report.requiresSeparatelyApprovedBootstrap,false);
 assert.equal(report.productionAutomaticApplyApproved,false);
});
test('actual registered migration chain retains privileged role DDL, proving restricted first install cannot be falsely approved',async()=>{
 const lock=JSON.parse(await readFile('db/migration-lock.json','utf8'));
 const files=await Promise.all(lock.migrations.map(async row=>({
  path:row.path,source:await readFile(row.path,'utf8')
 })));
 const report=inventoryPrivilegedMigrations(files);
 assert.equal(report.fileCount,63);
 assert.equal(report.requiresSeparatelyApprovedBootstrap,true);
 assert.ok(report.privilegedFiles.some(f=>f.path==='db/migrations/0007_dual_recovery.sql'&&f.classes.includes('ROLE_DDL')));
});
const attrs={
 superuser:false,createRole:false,createDb:false,bypassRls:false,
 replication:false,inherit:false,canLogin:false,canCreateInDatabase:false
};
const owner={...attrs,name:PRODUCTION_ROLES.schemaOwner,canCreateInDatabase:true};
const executor={...attrs,name:PRODUCTION_ROLES.executor};
const custodian={...attrs,name:PRODUCTION_ROLES.ledgerCustodian};
const application={...attrs,name:PRODUCTION_ROLES.runtime};
const edge={member:PRODUCTION_ROLES.executor,grantedRole:PRODUCTION_ROLES.schemaOwner,
 inherit:false,set:true,admin:false};
const good={owner,executor,custodian,application,memberships:[edge]};
const forbidden=change=>assert.throws(()=>validateRoleSnapshot({...good,...change}),
 /migration role policy rejected/);

test('production role policy enforces all four distinct NOLOGIN and NOINHERIT identities',()=>{
 const result=validateRoleSnapshot(good);
 assert.equal(result.roleSeparationVerified,true);
 assert.equal(result.ledgerCustodianSeparated,true);
 assert.equal(result.independentlyWitnessed,false);
 assert.equal(result.productionApproval,false);
 assert.ok(Object.isFrozen(PRODUCTION_ROLES.mandatoryAttributes));
 for(const key of ['owner','executor','custodian','application'])
  for(const attr of ['superuser','createRole','createDb','bypassRls',
   'replication','inherit','canLogin']){
   forbidden({[key]:{...good[key],[attr]:true}});
  }
});

test('role policy fails closed on missing, null, malformed or impersonated fields',()=>{
 for(const key of ['owner','executor','custodian','application']){
  forbidden({[key]:null});
  forbidden({[key]:{...good[key],name:'neondb_owner'}});
  for(const attr of ['superuser','createRole','createDb','bypassRls',
   'replication','inherit','canLogin','canCreateInDatabase']){
   forbidden({[key]:{...good[key],[attr]:undefined}});
   forbidden({[key]:{...good[key],[attr]:null}});
  }
 }
 forbidden({owner:{...owner,canCreateInDatabase:false}});
 for(const key of ['executor','custodian','application'])
  forbidden({[key]:{...good[key],canCreateInDatabase:true}});
 forbidden({owner:{...owner,name:PRODUCTION_ROLES.executor}});
 forbidden({application:{...application,name:'random_runtime'}});
});

test('role policy rejects creator ADMIN edges and all unexpected memberships',()=>{
 forbidden({memberships:undefined});
 forbidden({memberships:null});
 forbidden({memberships:[]});
 forbidden({memberships:[edge,edge]});
 forbidden({memberships:[edge,{member:'neondb_owner',grantedRole:PRODUCTION_ROLES.runtime,
  inherit:false,set:false,admin:true}]});
 forbidden({memberships:[{...edge,member:PRODUCTION_ROLES.runtime}]});
 forbidden({memberships:[{...edge,grantedRole:PRODUCTION_ROLES.ledgerCustodian}]});
 for(const changed of [
  {inherit:true},{set:false},{admin:true},{inherit:undefined},
  {set:null},{admin:undefined},{set:'true'}
 ])forbidden({memberships:[{...edge,...changed}]});
});

test('role validation returns no authorisation to apply migrations',()=>{
 const value=validateRoleSnapshot(good);
 assert.ok(Object.isFrozen(value));
 assert.equal(value.productionApproval,false);
 assert.equal(value.independentlyWitnessed,false);
 assert.equal(Object.hasOwn(value,'migrationAuthorized'),false);
});
