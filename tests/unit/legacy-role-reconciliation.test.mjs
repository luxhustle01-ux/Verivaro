import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {createLegacyReconciliationPlan,privilegedBootstrapSql,LEGACY_ROLE_DECLARATIONS,
 AUDITED_G1_LEDGER_HEAD,assertExistingInstallReconciliation} from '../../src/security/legacy-role-reconciliation.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
async function source(){
 const lock=JSON.parse(await readFile('db/migration-lock.json','utf8'));
 return Promise.all(lock.migrations.map(async m=>({path:m.path,bytes:await readFile(m.path)})));
}
let cached;
async function plan(){return cached??=createLegacyReconciliationPlan(await source());}
test('all 63 immutable migrations are reconciled without losing file provenance',async()=>{
 const result=await plan();
 assert.equal(result.migrations.length,63);
 assert.equal(result.serviceRoles.length,21);
 assert.equal(new Set(result.serviceRoles).size,21);
 assert.equal(result.ledgerHead,'7a5dccee57dcdd9b9f7f63074077a2be6db6ac4987d29f62f0259721481ecc55');
 assert.equal(result.initialInstallApproved,false);
 assert.equal(result.existingInstallBackfillApproved,false);
 assert.equal(result.independentlySigned,false);
 for(const row of result.migrations){
  assert.match(row.sourceSha256,/^[a-f0-9]{64}$/);
  assert.match(row.transformedSha256,/^[a-f0-9]{64}$/);
  assert.equal(row.strippedRoles.length,LEGACY_ROLE_DECLARATIONS.filter(x=>x[0]===row.version).length);
  if(!row.strippedRoles.length)assert.equal(row.transformedSha256,row.sourceSha256);
  else{
   assert.notEqual(row.transformedSha256,row.sourceSha256);
   assert.doesNotMatch(row.transformedSql,/^CREATE ROLE /m);
  }
 }
});
test('all privileged roles are explicitly provisioned before restricted migrations',async()=>{
 const p=await plan();
 const sql=privilegedBootstrapSql(p,{ownerRole:'vv_ci_reconcile_schema_owner',
  executorRole:'vv_ci_reconcile_executor',loginRole:'vv_ci_reconcile_login'});
 for(const name of p.serviceRoles)
  assert.equal(sql.split('CREATE ROLE '+name+' ').length,2,name);
 assert.match(sql,/WITH INHERIT FALSE, SET TRUE/);
 assert.doesNotMatch(sql,/SUPERUSER\s*;/);
 assert.throws(()=>privilegedBootstrapSql(p,{ownerRole:'verivaro_runtime',
  executorRole:'vv_ci_reconcile_executor',loginRole:'vv_ci_reconcile_login'}),
  /privileged migration reconciliation rejected/);
});
test('role statement substitution refuses tamper, duplication, drift and unreviewed privilege',async()=>{
 const rows=await source();
 const altered=(no,mutator)=>rows.map((r,i)=>i===no-1?{...r,bytes:Buffer.from(mutator(r.bytes.toString()))}:r);
 const fixture=rows[3].bytes.toString('utf8');
 for(const mod of [
   text=>text.replace('CREATE ROLE verivaro_runtime','CREATE ROLE verivaro_superuser'),
   text=>text.replace('CREATE ROLE verivaro_runtime','CREATE ROLE verivaro_runtime'),
   text=>text.replace('CREATE ROLE verivaro_runtime','CREATE ROLE verivaro_runtime WITH SUPERUSER'),
   text=>text.replace('COMMIT;', 'CREATE ROLE new_elevated NOLOGIN;\nCOMMIT;'),
   text=>text.replace('CREATE ROLE verivaro_runtime','CREATE ROLE verivaro_runtime\nCREATE ROLE verivaro_runtime')
 ]){const mutated=altered(4,mod);
  if(mutated[3].bytes.equals(rows[3].bytes))continue;
  assert.throws(()=>createLegacyReconciliationPlan(mutated),/privileged migration reconciliation rejected/);
 }
 assert.throws(()=>createLegacyReconciliationPlan(altered(3,s=>s.replace(
  'CREATE EXTENSION pgcrypto','CREATE EXTENSION untrusted'))),
  /privileged migration reconciliation rejected/);
 assert.throws(()=>createLegacyReconciliationPlan(rows.slice(1)),
  /privileged migration reconciliation rejected/);
});
test('existing install requires 63 exact history entries, safe global role attributes and external signoff',async()=>{
 const p=await plan();
 const history=p.migrations.map(m=>m.sourceSha256);
 const roles=p.serviceRoles.map(name=>({name,login:false,superuser:false,inherit:false,
  createRole:false,createDb:false,replication:false,bypassRls:false,unexpectedMembership:false}));
 const input={observedHistory:history,expectedHistory:history,roleInventory:roles};
 assert.throws(()=>assertExistingInstallReconciliation(input),
  /independent existing-install release review not provided/);
 const result=assertExistingInstallReconciliation({...input,approvedExistingInstall:true});
 assert.equal(result.productionApproved,false);
 for(const bad of [
  {observedHistory:history.slice(1)},
  {observedHistory:history.map((h,i)=>i===30?'f'.repeat(64):h)},
  {roleInventory:roles.slice(1)},
  {roleInventory:roles.map((r,i)=>i===0?{...r,createRole:true}:r)},
  {roleInventory:roles.map((r,i)=>i===0?{...r,unexpectedMembership:true}:r)}
 ])assert.throws(()=>assertExistingInstallReconciliation({...input,...bad,approvedExistingInstall:true}),
  /privileged migration reconciliation rejected/);
});


test('role-bootstrap SQL refuses fabricated roles and forged approval plans',async()=>{
 const p=await plan(),options={ownerRole:'vv_ci_reconcile_schema_owner',
  executorRole:'vv_ci_reconcile_executor',loginRole:'vv_ci_reconcile_login'};
 const sql=privilegedBootstrapSql(p,options);
 assert.equal(p.ledgerHead,AUDITED_G1_LEDGER_HEAD);
 assert.equal(sql.match(/CREATE ROLE /g).length,23);
 assert.ok(Object.isFrozen(p.serviceRoles));
 assert.ok(Object.isFrozen(p.migrations));
 assert.ok(Object.isFrozen(p.migrations[3].strippedRoles));
 assert.ok(Object.isFrozen(LEGACY_ROLE_DECLARATIONS[0]));
 assert.throws(()=>{p.serviceRoles[0]='evil';},TypeError);
 assert.throws(()=>{LEGACY_ROLE_DECLARATIONS[0][1]='evil';},TypeError);
 for(const tampered of [
  {...p,serviceRoles:['vv_ci_extra; DROP DATABASE verivaro_test; --',...p.serviceRoles.slice(1)]},
  {...p,serviceRoles:[...p.serviceRoles].reverse()},
  {...p,ledgerHead:'f'.repeat(64)},
  {...p,migrations:[]}
 ])assert.throws(()=>privilegedBootstrapSql(tampered,options),
  /privileged migration reconciliation rejected/);
 assert.doesNotMatch(sql,/DROP DATABASE/);
});

test('existing-install inventory rejects unknown memberships and malformed digest',async()=>{
 const p=await plan(),history=p.migrations.map(m=>m.sourceSha256);
 const roles=p.serviceRoles.map(name=>({name,login:false,superuser:false,inherit:false,
  createRole:false,createDb:false,replication:false,bypassRls:false,unexpectedMembership:false}));
 const input={observedHistory:history,expectedHistory:history,roleInventory:roles,approvedExistingInstall:true};
 for(const patch of [
  {roleInventory:roles.map((r,i)=>i===0?{...r,unexpectedMembership:undefined}:r)},
  {roleInventory:roles.map((r,i)=>i===0?{...r,unexpectedMembership:null}:r)},
  {roleInventory:roles.map((r,i)=>i===0?{...r,unexpectedMembership:true}:r)},
  {expectedHistory:history.map((h,i)=>i===0?'not-sha256':h),
   observedHistory:history.map((h,i)=>i===0?'not-sha256':h)}
 ])assert.throws(()=>assertExistingInstallReconciliation({...input,...patch}),
  /privileged migration reconciliation rejected/);
 assert.equal(assertExistingInstallReconciliation(input).productionApproved,false);
});
