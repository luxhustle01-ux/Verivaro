import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createExpectedLedger} from '../../scripts/ci-migration-ledger.mjs';
import {restrictedReconcileSql,assertInterruptedUpgradeState} from '../../scripts/rehearse-privileged-migration-reconciliation.mjs';
import {ADDITIONAL_SIGNED_PATHS} from '../../scripts/migration-release-cli.mjs';

test('restricted SQL enforces explicit executor/owner transaction boundaries',()=>{
 const items=createExpectedLedger([{version:1,path:'db/migrations/0001_sample.sql',sha256:'2'.repeat(64)}]);
 const sql=restrictedReconcileSql(items,1,'BEGIN;\nCREATE TABLE public.sandbox(id integer);\nCOMMIT;');
 assert.match(sql,/^SET ROLE vv_ci_reconcile_executor;\nBEGIN;\n/);
 assert.match(sql,/\\else\nSET LOCAL ROLE vv_ci_reconcile_schema_owner;\n/);
 assert.match(sql,/SET LOCAL ROLE vv_ci_reconcile_executor;\nINSERT INTO verivaro_migration.history/);
 assert.ok(sql.indexOf('CREATE TABLE public.sandbox')<sql.indexOf('INSERT INTO verivaro_migration.history'));
 assert.ok(sql.endsWith('RESET ROLE;\n'));
 assert.doesNotMatch(sql,/SET ROLE postgres|SUPERUSER|CREATEROLE/);
});
test('signed source bundle covers the privileged bootstrap, migrator and acceptance process',()=>{
 const paths=[
  'db/security/privileged-service-role-bootstrap.sql',
  'db/security/verify-installed-migration-state.sql',
  'src/security/legacy-role-reconciliation.mjs',
  'scripts/rehearse-privileged-migration-reconciliation.mjs',
  'scripts/rehearse-migration-signing-acceptance.mjs',
  'db/tests/least_privilege_migrator.sql',
  'docs/engineering/G1_PRIVILEGED_BOOTSTRAP_AND_SIGNING_ACCEPTANCE_20261121.md',
  'docs/engineering/G1_INDEPENDENT_SIGNING_ACCEPTANCE_20261121.json'
 ];
 for(const path of paths)assert.ok(ADDITIONAL_SIGNED_PATHS.includes(path),'unsigned sensitive control '+path);
 assert.equal(ADDITIONAL_SIGNED_PATHS.length,17);
 assert.equal(new Set(ADDITIONAL_SIGNED_PATHS).size,17);
});
test('independent acceptance register never asserts completed external signing or production release',async()=>{
 const register=JSON.parse(await readFile('docs/engineering/G1_INDEPENDENT_SIGNING_ACCEPTANCE_20261121.json'));
 assert.equal(register.releaseApprovalStatus,'NOT_APPROVED');
 assert.equal(register.productionReleaseApproved,false);
 assert.equal(register.signedReleaseProduced,false);
 assert.equal(register.witnessPersistedOutsideRepository,false);
 assert.equal(register.independentReviewCompleted,false);
 assert.equal(register.requirements.length,9);
 for(const r of register.requirements){
  assert.equal(r.state,'NOT_VERIFIED');
  assert.ok(r.required.length>50);
 }
 assert.equal(register.approvalEvidence.length,0);
});

test('staged upgrade rejects any partial commit, leftover DDL or altered seeded data',()=>{
 const good={historyCount:'62',changedTableAbsent:'t',
  sourceFingerprint:'a'.repeat(32),restoredFingerprint:'a'.repeat(32)};
 assert.equal(assertInterruptedUpgradeState(good).dataPreserved,true);
 for(const partial of [
  {historyCount:'63'},{changedTableAbsent:'f'},
  {sourceFingerprint:'bad'},{restoredFingerprint:'b'.repeat(32)}
 ])assert.throws(()=>assertInterruptedUpgradeState({...good,...partial}),
  /restricted reconciliation rehearsal failed/);
});

test('staging interruption is performed by a separately scoped CI controller, never elevated executor',async()=>{
 const sql=await readFile('scripts/rehearse-privileged-migration-reconciliation.mjs','utf8');
 assert.match(sql,/pg_stat_activity WHERE pid=/);
 assert.match(sql,/datname=.*UPGRADE_TARGET/);
 assert.match(sql,/usename=.*LOGIN/);
 assert.match(sql,/pg_terminate_backend/);
 assert.match(sql,/VV_STAGE_READY_/);
 assert.match(sql,/privilegedCIControllerTerminationVerified:true/);
 assert.match(sql,/restrictedMigratorGrantedSignalPrivilege:false/);
 assert.doesNotMatch(sql,/GRANT pg_signal_backend TO/);
});
