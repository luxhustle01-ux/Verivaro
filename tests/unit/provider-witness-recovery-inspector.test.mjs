import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {mkdtemp,mkdir,rm,writeFile,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {encodeWitnessGenesis,openReferenceWitnessJournal} from '../../src/security/provider-witness-journal.mjs';
import {openReferenceWitnessReceiptPublisher} from '../../src/security/provider-witness-publisher-reference.mjs';
import {createUnsignedWitnessAuditStatement,canonicalWitnessAuditStatement} from '../../src/security/provider-witness-audit-receipt.mjs';
import {inspectReferenceWitnessRecoveryConsistency} from '../../src/security/provider-witness-recovery-inspector.mjs';

const scope={issuer:'https://issuer.example.invalid',audience:'verivaro-internal'};
const first={sequence:1,digest:'1'.repeat(64)},second={sequence:2,digest:'2'.repeat(64)};
const issuedAt='2026-11-21T00:00:00.000Z';
async function lab(t){
 const root=await mkdtemp(join(tmpdir(),'vv-reconcile-'));
 t.after(()=>rm(root,{recursive:true,force:true}));
 const journalDirectory=join(root,'journal'),publisherDirectory=join(root,'publisher');
 await mkdir(journalDirectory,{mode:0o700});
 await mkdir(publisherDirectory,{mode:0o700});
 const genesis=encodeWitnessGenesis({...scope,checkpoint:first});
 const journalPath=join(journalDirectory,'witness-journal.jsonl');
 const receiptPath=join(publisherDirectory,'signed-witness-receipt.json');
 await writeFile(journalPath,genesis.bytes,{mode:0o600});
 const keys=generateKeyPairSync('ed25519');
 const statement=(checkpoint,count,headHash)=>createUnsignedWitnessAuditStatement({
  ...scope,checkpoint,count,headHash,issuedAt
 });
 const receipt=s=>({statement:s,
  signature:sign(null,canonicalWitnessAuditStatement(s),keys.privateKey).toString('base64url')
 });
 const initial=receipt(statement(first,1,genesis.headHash));
 await writeFile(receiptPath,JSON.stringify(initial)+'\n',{mode:0o600});
 const originalFloor={count:1,headHash:genesis.headHash};
 const config=floor=>({journalDirectory,publisherDirectory,...scope,
  trustedPublicKey:keys.publicKey,trustedFloor:floor??originalFloor});
 async function advanceJournal(){
  const journal=await openReferenceWitnessJournal({...scope,directory:journalDirectory,
   trustedHead:genesis.headHash});
  await journal.compareAndSwap({...scope,previous:first,next:second});
  const state=await journal.audit();
  await journal.close();
  return state;
 }
 async function advancePublisher(state){
  const pub=await openReferenceWitnessReceiptPublisher({
   directory:publisherDirectory,...scope,trustedPublicKey:keys.publicKey,
   trustedFloor:originalFloor,
   signStatement:bytes=>sign(null,bytes,keys.privateKey).toString('base64url')
  });
  const previous=await pub.read(scope);
  await pub.compareAndSwap({...scope,previous,
   statement:statement(state.checkpoint,state.count,state.headHash)});
  await pub.close();
 }
 return {root,journalDirectory,publisherDirectory,journalPath,receiptPath,
  keys,initial,statement,receipt,originalFloor,config,advanceJournal,advancePublisher,
  inspect:floor=>inspectReferenceWitnessRecoveryConsistency(config(floor))};
}
test('matching genesis evidence reports manual review, never automatic recovery',async t=>{
 const f=await lab(t),r=await f.inspect();
 assert.equal(r.status,'MANUAL_REVIEW_REQUIRED');
 assert.equal(r.evidenceConsistentAtInspection,true);
 assert.equal(r.automaticRecoveryPermitted,false);
 assert.deepEqual(r.authenticatedHead.checkpoint,first);
 assert.deepEqual(r.writerLocks,{journal:false,publisher:false});
 assert.deepEqual(r.pendingPublisherFiles,[]);
});
test('fully advanced evidence requires separately updated trusted freshness floor',async t=>{
 const f=await lab(t),after=await f.advanceJournal();
 await f.advancePublisher(after);
 await assert.rejects(f.inspect(),/inconsistent/);
 const r=await f.inspect({count:after.count,headHash:after.headHash});
 assert.equal(r.authenticatedHead.count,2);
 assert.deepEqual(r.authenticatedHead.checkpoint,second);
 assert.equal(r.automaticRecoveryPermitted,false);
});
test('journal-ahead signed publisher disagreement fails closed',async t=>{
 const f=await lab(t),after=await f.advanceJournal();
 await assert.rejects(f.inspect(),/inconsistent/);
 await assert.rejects(f.inspect({count:after.count,headHash:after.headHash}),/inconsistent/);
});
test('publisher-ahead signed journal disagreement fails closed',async t=>{
 const f=await lab(t),fake={checkpoint:second,count:2,headHash:'a'.repeat(64)};
 await f.advancePublisher(fake);
 await assert.rejects(f.inspect(),/inconsistent/);
 await assert.rejects(f.inspect({count:2,headHash:fake.headHash}),/inconsistent/);
});
test('signed receipt with correct count and head but conflicting checkpoint fails',async t=>{
 const f=await lab(t),after=await f.advanceJournal();
 const invalid=f.receipt(f.statement(first,after.count,after.headHash));
 await writeFile(f.receiptPath,JSON.stringify(invalid)+'\n',{mode:0o600});
 await assert.rejects(f.inspect({count:after.count,headHash:after.headHash}),/inconsistent/);
});
test('forged signature and wrong signed audience are both rejected',async t=>{
 const f=await lab(t);
 await writeFile(f.receiptPath,JSON.stringify({
  ...f.initial,signature:'a'.repeat(86)
 })+'\n',{mode:0o600});
 await assert.rejects(f.inspect(),/inconsistent/);
 const wrong=f.receipt(createUnsignedWitnessAuditStatement({
  ...scope,audience:'other',checkpoint:first,count:1,
  headHash:f.originalFloor.headHash,issuedAt
 }));
 await writeFile(f.receiptPath,JSON.stringify(wrong)+'\n',{mode:0o600});
 await assert.rejects(f.inspect(),/inconsistent/);
});
test('journal rollback and truncation fail against independently updated floor',async t=>{
 const f=await lab(t),original=await readFile(f.journalPath);
 const after=await f.advanceJournal();
 await f.advancePublisher(after);
 const floor={count:after.count,headHash:after.headHash};
 await writeFile(f.journalPath,original);
 await assert.rejects(f.inspect(floor),/inconsistent/);
 await writeFile(f.journalPath,original.subarray(0,-8));
 await assert.rejects(f.inspect(floor),/inconsistent/);
});
test('existing locks and pending receipt evidence are reported, never cleared',async t=>{
 const f=await lab(t);
 const pending=join(f.publisherDirectory,'.receipt-deadbeef.pending');
 const jLock=join(f.journalDirectory,'.witness-writer.lock');
 const pLock=join(f.publisherDirectory,'.receipt-publisher.lock');
 await writeFile(pending,'unconfirmed publication',{mode:0o600});
 await writeFile(jLock,'reserved\n',{mode:0o600});
 await writeFile(pLock,'reserved\n',{mode:0o600});
 const r=await f.inspect();
 assert.deepEqual(r.writerLocks,{journal:true,publisher:true});
 assert.deepEqual(r.pendingPublisherFiles,['.receipt-deadbeef.pending']);
 assert.equal(r.automaticRecoveryPermitted,false);
 assert.equal((await readFile(pending,'utf8')),'unconfirmed publication');
});
test('unexpected journal evidence causes denial without any file modification',async t=>{
 const f=await lab(t),extra=join(f.journalDirectory,'unknown.record');
 await writeFile(extra,'forensic evidence',{mode:0o600});
 await assert.rejects(f.inspect(),/inconsistent/);
 assert.equal(await readFile(extra,'utf8'),'forensic evidence');
});
test('invalid floors, wrong audience and shared directories are all denied',async t=>{
 const f=await lab(t);
 await assert.rejects(f.inspect({count:0,headHash:f.originalFloor.headHash}),/inconsistent/);
 await assert.rejects(inspectReferenceWitnessRecoveryConsistency({
  ...f.config(),publisherDirectory:f.journalDirectory
 }),/inconsistent/);
 await assert.rejects(inspectReferenceWitnessRecoveryConsistency({
  ...f.config(),audience:'other'
 }),/inconsistent/);
});
