import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {encodeWitnessGenesis,verifyWitnessJournal,openReferenceWitnessJournal} from '../../src/security/provider-witness-journal.mjs';

const scope={issuer:'https://issuer.example.invalid',audience:'verivaro-internal'};
const first={sequence:1,digest:'1'.repeat(64)};
const second={sequence:2,digest:'2'.repeat(64)};
const third={sequence:3,digest:'3'.repeat(64)};
async function fixture(t){
 const root=await mkdtemp(join(tmpdir(),'vv-journal-'));
 const directory=join(root,'witness');await mkdir(directory,{mode:0o700});
 const genesis=encodeWitnessGenesis({...scope,checkpoint:first});
 const path=join(directory,'witness-journal.jsonl');
 await writeFile(path,genesis.bytes,{mode:0o600});
 t.after(()=>rm(root,{recursive:true,force:true}));
 return {directory,path,head:genesis.headHash,genesis};
}
test('single-writer CAS produces fsynced chained records, denies replay and can restart at externally trusted head',async t=>{
 const f=await fixture(t);
 const journal=await openReferenceWitnessJournal({...scope,directory:f.directory,trustedHead:f.head});
 assert.deepEqual(await journal.read(scope),first);
 assert.deepEqual(await journal.compareAndSwap({...scope,previous:first,next:second}),second);
 await assert.rejects(journal.compareAndSwap({...scope,previous:first,next:second}),/conflict/);
 const snapshot=await journal.audit();
 assert.equal(snapshot.count,2);
 assert.deepEqual(snapshot.checkpoint,second);
 const bytes=await readFile(f.path);
 assert.deepEqual(verifyWitnessJournal(bytes,{...scope,trustedHead:snapshot.headHash}).checkpoint,second);
 await journal.close();
 await assert.rejects(openReferenceWitnessJournal({...scope,directory:f.directory,trustedHead:f.head}),/integrity/);
 const reopened=await openReferenceWitnessJournal({...scope,directory:f.directory,trustedHead:snapshot.headHash});
 assert.deepEqual(await reopened.read(scope),second);
 assert.deepEqual(await reopened.compareAndSwap({...scope,previous:second,next:third}),third);
 await reopened.close();
});
test('concurrent CAS contenders never both commit the same predecessor',async t=>{
 const f=await fixture(t);
 const journal=await openReferenceWitnessJournal({...scope,directory:f.directory,trustedHead:f.head});
 t.after(()=>journal.close().catch(()=>{}));
 const attempts=await Promise.allSettled(Array.from({length:16},()=>journal.compareAndSwap({...scope,previous:first,next:second})));
 assert.equal(attempts.filter(r=>r.status==='fulfilled').length,1);
 assert.equal(attempts.filter(r=>r.status==='rejected').length,15);
 assert.deepEqual(await journal.read(scope),second);
 assert.equal((await journal.audit()).count,2);
});
test('different stale predecessors and rollback attempts never advance the witness',async t=>{
 const f=await fixture(t);
 const journal=await openReferenceWitnessJournal({...scope,directory:f.directory,trustedHead:f.head});
 t.after(()=>journal.close().catch(()=>{}));
 await assert.rejects(journal.compareAndSwap({...scope,previous:second,next:third}),/conflict/);
 await assert.rejects(journal.compareAndSwap({...scope,previous:first,next:first}),/integrity/);
 await assert.rejects(journal.compareAndSwap({...scope,previous:second,next:first}),/integrity/);
 await assert.rejects(journal.compareAndSwap({issuer:scope.issuer,audience:'other',previous:first,next:second}),/integrity/);
 assert.deepEqual(await journal.read(scope),first);
 assert.equal((await journal.audit()).count,1);
});
test('tampering, truncation, reordered/repeated records and unanchored snapshot rollbacks fail verification',async t=>{
 const f=await fixture(t);
 const journal=await openReferenceWitnessJournal({...scope,directory:f.directory,trustedHead:f.head});
 await journal.compareAndSwap({...scope,previous:first,next:second});
 const head=(await journal.audit()).headHash;
 await journal.close();
 const good=await readFile(f.path);
 assert.equal(verifyWitnessJournal(good,{...scope,trustedHead:head}).count,2);
 const raw=good.toString('utf8'),rows=raw.trimEnd().split('\n');
 const variants=[
  Buffer.from(rows[0]+'\n'),
  Buffer.from(rows[1]+'\n'+rows[0]+'\n'),
  Buffer.from(rows[0]+'\n'+rows[1]+'\n'+rows[1]+'\n'),
  Buffer.from(raw.slice(0,-4)),
  Buffer.from(raw.replace('"digest":"2222','"digest":"9999')),
  Buffer.from(raw.replace('"index":1','"index":0')),
  Buffer.from(raw.replace('"previousHash":"','"previousHash":"a')),
  Buffer.from(raw+'\n')
 ];
 for(const bytes of variants)assert.throws(()=>verifyWitnessJournal(bytes,{...scope,trustedHead:head}),/integrity/);
 assert.throws(()=>verifyWitnessJournal(good,{...scope,trustedHead:f.head}),/integrity/);
});
test('on-disk mutation during active lease latches journal denial; no recovery by reversing file tamper',async t=>{
 const f=await fixture(t);
 const journal=await openReferenceWitnessJournal({...scope,directory:f.directory,trustedHead:f.head});
 t.after(()=>journal.close().catch(()=>{}));
 const original=await readFile(f.path);
 await writeFile(f.path,Buffer.from(original.toString('utf8').replace('"index":0','"index":1')));
 await assert.rejects(journal.read(scope),/integrity/);
 await writeFile(f.path,original);
 await assert.rejects(journal.read(scope),/integrity/);
 await assert.rejects(journal.compareAndSwap({...scope,previous:first,next:second}),/integrity/);
});
test('active writer lock rejects concurrent writer processes and missing independent head fails closed',async t=>{
 const f=await fixture(t);
 const journal=await openReferenceWitnessJournal({...scope,directory:f.directory,trustedHead:f.head});
 await assert.rejects(openReferenceWitnessJournal({...scope,directory:f.directory,trustedHead:f.head}));
 await journal.close();
 await assert.rejects(openReferenceWitnessJournal({...scope,directory:f.directory,trustedHead:'a'.repeat(64)}),/integrity/);
});
