import test from 'node:test';
import assert from 'node:assert/strict';
import {auditRepositoryMigrationChain,verifyMigrationChainSnapshot,gitBlobSha1}
 from '../../src/security/migration-chain-audit.mjs';

const baseline='a'.repeat(40);
const name=i=>'db/migrations/'+String(i).padStart(4,'0')+'_sample.sql';
function fixture(){
 const files=Object.create(null);
 files[name(1)]=Buffer.from("BEGIN;\nSELECT 1;\nCOMMIT;\n");
 files[name(2)]=Buffer.from("BEGIN;\nSELECT 2;\nCOMMIT;\n");
 const migrations=[1,2].map(i=>({
  number:i,path:name(i),gitBlobSha1:gitBlobSha1(files[name(i)]),
  byteLength:files[name(i)].length
 }));
 const manifest={schemaVersion:1,manifestType:'VERIVARO_P0B_MIGRATION_CHAIN',
  baselineCommit:baseline,hashAlgorithm:'git-blob-sha1',
  sourceScope:'repository-migrations-only',productionMigrationApproved:false,
  independentlySigned:false,migrations};
 const cmd=i=>'          node scripts/ci-migration-ledger.mjs apply '+name(i)+'\n';
 const workflowText='name: test\njobs:\n  test:\n    steps:\n'+
  '      - name: Check migrations\n        run: |\n'+
  '          node scripts/verify-migration-chain.mjs\n'+
  '      - name: Init ledger\n        run: |\n          node scripts/ci-migration-ledger.mjs init\n'+
  '      - name: Apply schema and adversarial checks\n        run: |\n'+
  cmd(1)+cmd(2)+
  '          node scripts/ci-migration-ledger.mjs verify\n'+
  '          psql -X -v ON_ERROR_STOP=1 -f db/tests/full_security_gate.sql\n';
 return {files,manifest,workflowText};
}
const verify=f=>verifyMigrationChainSnapshot(f);

test('actual repository migration preflight locks every migration in full CI order',async()=>{
 const result=await auditRepositoryMigrationChain();
 assert.equal(result.checkedCount,63);
 assert.equal(result.first,'db/migrations/0001_tenant_foundation.sql');
 assert.equal(result.last,'db/migrations/0063_ocr_transcription_corrections.sql');
 assert.equal(result.independentSignoff,false);
 assert.equal(result.productionMigrationApproved,false);
});
test('Git blob hash uses exact bytes and canonical header',()=>{
 assert.equal(gitBlobSha1(Buffer.from('hello\n')),
  'ce013625030ba8dba906f756967f9e9ca394464a');
 assert.notEqual(gitBlobSha1(Buffer.from('hello\n')),
  gitBlobSha1(Buffer.from('hello')));
});
test('synthetic complete ordered chain verifies without granting deployment approval',()=>{
 const f=fixture(),r=verify(f);
 assert.equal(r.checkedCount,2);
 assert.equal(r.productionMigrationApproved,false);
 assert.equal(r.independentSignoff,false);
});
test('modified migration, removed file and unexpected migration all reject',()=>{
 for(const mutate of [
  f=>{f.files[name(1)]=Buffer.from('DROP TABLE verivaro.tenants;');},
  f=>{delete f.files[name(2)];},
  f=>{f.files[name(3)]=Buffer.from('SELECT 3;');},
  f=>{f.manifest.migrations[0].gitBlobSha1='0'.repeat(40);},
  f=>{f.manifest.migrations[0].byteLength++;},
  f=>{f.manifest.migrations[1].number=3;},
  f=>{f.manifest.migrations[0].path='../outside.sql';}
 ]){
  const f=fixture();mutate(f);
  assert.throws(()=>verify(f),/migration chain preflight rejected/);
 }
});
test('reordered, skipped, duplicate and unapproved CI application reject',()=>{
 const cmd=i=>'          node scripts/ci-migration-ledger.mjs apply '+name(i)+'\n';
 for(const change of [
  s=>s.replace(cmd(1)+cmd(2),cmd(2)+cmd(1)),
  s=>s.replace(cmd(2),''),
  s=>s.replace(cmd(2),cmd(2)+cmd(2)),
  s=>s.replace(cmd(1),'          psql -f '+name(1)+'\n'),
  s=>s.replace('node scripts/verify-migration-chain.mjs','echo not checked'),
  s=>s.replace('psql -X -v ON_ERROR_STOP=1 -f db/tests/full_security_gate.sql','echo no final audit')
 ]){
  const f=fixture();f.workflowText=change(f.workflowText);
  assert.throws(()=>verify(f),/migration chain preflight rejected/);
 }
});
test('manifest cannot claim independent signoff or production approval',()=>{
 for(const change of [
  f=>{f.manifest.independentlySigned=true;},
  f=>{f.manifest.productionMigrationApproved=true;},
  f=>{f.manifest.hashAlgorithm='sha256';},
  f=>{f.manifest.baselineCommit='main';}
 ]){
  const f=fixture();change(f);
  assert.throws(()=>verify(f),/migration chain preflight rejected/);
 }
});
