import test from 'node:test';
import assert from 'node:assert/strict';
import {assertDisposableDatabase,unwrapTransactionalMigration,createExpectedLedger,
 createMigrationSql,checkLedgerRows} from '../../scripts/ci-migration-ledger.mjs';
const fixtures=[{version:1,path:'db/migrations/0001_sample.sql',sha256:'1'.repeat(64)},
 {version:2,path:'db/migrations/0002_sample.sql',sha256:'2'.repeat(64)}];
const items=createExpectedLedger(fixtures);
const source='-- Versioned SQL\nBEGIN;\nCREATE TABLE public.test_only(id integer);\nCOMMIT;\n';
test('ledger catalogues chain immutable sha256, path, and version',()=>{
 assert.equal(items[0].previous_hash,'0'.repeat(64));
 assert.match(items[1].entry_hash,/^[a-f0-9]{64}$/);
 assert.equal(items[1].previous_hash,items[0].entry_hash);
 assert.notEqual(createExpectedLedger([{...fixtures[0],sha256:'3'.repeat(64)},fixtures[1]])[1].entry_hash,items[1].entry_hash);
 assert.throws(()=>createExpectedLedger([fixtures[1]]),/CI migration ledger rejected/);
});
test('source wraps exactly one transaction and rejects unsupported forms',()=>{
 assert.match(unwrapTransactionalMigration(source),/CREATE TABLE/);
 for(const bad of ['SELECT 1;','BEGIN;\nSELECT 1;\nCOMMIT;\nCOMMIT;',
  'BEGIN;\nCOMMIT;\nSELECT 1;', 'BEGIN;\n\\i /tmp/foo\nCOMMIT;',
  'BEGIN;\nBEGIN;\nCOMMIT;']){
  assert.throws(()=>unwrapTransactionalMigration(bad),/CI migration ledger rejected/);
 }
});
test('generated transaction locks, checks source, records before commit, and injects backend kill only when requested',()=>{
 const script=createMigrationSql(items,1,source,{abort:true});
 assert.match(script,/BEGIN;\nSELECT pg_advisory_xact_lock/);
 assert.match(script,/migration ledger contents do not match repository baseline/);
 assert.match(script,/\\if :vv_skip/);
 assert.match(script,/\\gset/);
 assert.ok(script.indexOf('CREATE TABLE public.test_only')<script.indexOf('INSERT INTO verivaro_migration.history'));
 assert.ok(script.indexOf('INSERT INTO verivaro_migration.history')<script.indexOf('pg_terminate_backend'));
 assert.ok(script.indexOf('pg_terminate_backend')<script.lastIndexOf('COMMIT;'));
 assert.doesNotMatch(createMigrationSql(items,1,source),/pg_terminate_backend/);
});
test('full ledger verification fails closed on missing, changed or reordered entries',()=>{
 const rows=items.map(e=>[e.version,e.path,e.sha256,e.previous_hash,e.entry_hash].join('|'));
 assert.equal(checkLedgerRows(items,rows).verifiedVersions,2);
 for(const changed of [[],[rows[1]],rows.slice().reverse(),[rows[0].replace('1'.repeat(64),'3'.repeat(64)),rows[1]]])
  assert.throws(()=>checkLedgerRows(items,changed),/CI migration ledger rejected/);
});
test('CI migrator refuses production and remote database environment overrides',()=>{
 const good={GITHUB_ACTIONS:'true',VV_CI_PG_MIGRATOR:'1',PGHOST:'localhost',PGPORT:'5432',
  PGUSER:'postgres',PGPASSWORD:'ci-only',PGDATABASE:'verivaro_test'};
 assert.doesNotThrow(()=>assertDisposableDatabase(good));
 for(const changed of [{PGDATABASE:'production'},{PGHOST:'db.prod.example'},
  {PGUSER:'application'},{PGPASSWORD:'real-secret'},{PGHOSTADDR:'10.0.0.3'},
  {DATABASE_URL:'postgresql://example.com/prod'},{GITHUB_ACTIONS:'false'},
  {VV_CI_PG_MIGRATOR:'0'},{PGOPTIONS:'-c search_path=public'}]){
   assert.throws(()=>assertDisposableDatabase({...good,...changed}),/CI migration ledger rejected/);
 }
});
