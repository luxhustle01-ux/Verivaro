import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {mkdtemp,mkdir,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {encodeWitnessGenesis} from '../../src/security/provider-witness-journal.mjs';
import {openReceiptGuardedReferenceWitness} from '../../src/security/provider-witness-anchor-gate.mjs';
import {canonicalWitnessAuditStatement,createUnsignedWitnessAuditStatement} from '../../src/security/provider-witness-audit-receipt.mjs';

const scope={issuer:'https://issuer.example.invalid',audience:'verivaro-internal'};
const first={sequence:1,digest:'1'.repeat(64)};
const second={sequence:2,digest:'2'.repeat(64)};
const third={sequence:3,digest:'3'.repeat(64)};
function signingFixture(){
 const signer=generateKeyPairSync('ed25519');
 const makeReceipt=(state,issuedAt='2026-11-21T01:00:00.000Z')=>{
  const statement=createUnsignedWitnessAuditStatement({...scope,
   checkpoint:state.checkpoint,count:state.count,headHash:state.headHash,issuedAt});
  return Object.freeze({statement,signature:sign(null,canonicalWitnessAuditStatement(statement),
   signer.privateKey).toString('base64url')});
 };
 return {signer,makeReceipt};
}
async function lab(t){
 const root=await mkdtemp(join(tmpdir(),'vv-anchor-'));
 const directory=join(root,'witness');
 await mkdir(directory,{mode:0o700});
 const genesis=encodeWitnessGenesis({...scope,checkpoint:first});
 const journalFile=join(directory,'witness-journal.jsonl');
 await writeFile(journalFile,genesis.bytes,{mode:0o600});
 t.after(()=>rm(root,{recursive:true,force:true}));
 const {signer,makeReceipt}=signingFixture();
 const genesisState={checkpoint:first,count:1,headHash:genesis.headHash};
 let current=makeReceipt(genesisState),mode='ok',writes=0,reads=0;
 const external={
  read:async()=>{reads++;return current;},
  compareAndSwap:async({issuer,audience,previous,statement})=>{
   writes++;
   assert.equal(issuer,scope.issuer);
   assert.equal(audience,scope.audience);
   if(mode==='reject')throw Error('external publication unavailable');
   if(previous.signature!==current.signature||
    statement.count!==current.statement.count+1)throw Error('external CAS conflict');
   const candidate=makeReceipt({
    checkpoint:statement.checkpoint,count:statement.count,
    headHash:statement.headHash
   },statement.issuedAt);
   current=candidate;
   if(mode==='ack-lost')throw Error('remote commit succeeded but acknowledgement lost');
   return current;
  }
 };
 const config=floor=>({directory,...scope,anchor:external,
  trustedPublicKey:signer.publicKey,
  trustedFloor:floor,ioTimeoutMs:1000,
  clock:()=>new Date('2026-11-21T01:01:00.000Z')
 });
 const initialFloor={count:1,headHash:genesis.headHash};
 return {
  directory,journalFile,config,initialFloor,external,makeReceipt,
  open:floor=>openReceiptGuardedReferenceWitness(config(floor??initialFloor)),
  getCurrent:()=>current,setCurrent:c=>{current=c;},
  setMode:m=>{mode=m;},writes:()=>writes,reads:()=>reads
 };
}
test('guard accepts independently pinned genesis and publishes next fsynced head before CAS acknowledgment',async t=>{
 const f=await lab(t),w=await f.open();
 assert.deepEqual(await w.read(scope),first);
 assert.deepEqual(await w.compareAndSwap({...scope,previous:first,next:second}),second);
 assert.equal(f.writes(),1);
 assert.deepEqual(await w.read(scope),second);
 const state=await w.audit(),receipt=f.getCurrent();
 assert.equal(state.headHash,receipt.statement.headHash);
 assert.equal(state.count,2);
 await w.close();
 await assert.rejects(f.open(),/anchor state unavailable/);
 const freshFloor={count:2,headHash:state.headHash};
 const recovered=await f.open(freshFloor);
 assert.deepEqual(await recovered.read(scope),second);
 await recovered.close();
});
test('validly signed stale anchor receipt fails at restart despite disk being current',async t=>{
 const f=await lab(t),oldReceipt=f.getCurrent(),w=await f.open();
 await w.compareAndSwap({...scope,previous:first,next:second});
 const fresh=await w.audit();
 await w.close();
 f.setCurrent(oldReceipt);
 await assert.rejects(f.open({count:fresh.count,headHash:fresh.headHash}),/anchor state unavailable/);
 assert.equal(f.getCurrent(),oldReceipt);
});
test('interrupted publication after local disk commit faults verifier and blocks unsafe restart',async t=>{
 const f=await lab(t),w=await f.open();
 f.setMode('reject');
 await assert.rejects(w.compareAndSwap({...scope,previous:first,next:second}),/anchor state unavailable/);
 assert.equal(f.writes(),1);
 await assert.rejects(w.read(scope),/anchor state unavailable/);
 await w.close();
 await assert.rejects(f.open(),/anchor state unavailable/);
 // A rejected remote publish MUST NOT roll back the journal automatically.
 const contents=await readFile(f.journalFile);
 assert.equal(contents.toString('utf8').trimEnd().split('\n').length,2);
});
test('remote publication committed but ACK lost never retries and needs independently updated floor to recover',async t=>{
 const f=await lab(t),w=await f.open();
 f.setMode('ack-lost');
 await assert.rejects(w.compareAndSwap({...scope,previous:first,next:second}),/anchor state unavailable/);
 assert.equal(f.writes(),1);
 await assert.rejects(w.compareAndSwap({...scope,previous:first,next:third}),/anchor state unavailable/);
 await w.close();
 await assert.rejects(f.open(),/anchor state unavailable/);
 const receipt=f.getCurrent();
 const updatedFloor={count:receipt.statement.count,headHash:receipt.statement.headHash};
 const recovered=await f.open(updatedFloor);
 assert.deepEqual(await recovered.read(scope),second);
 await recovered.close();
});
test('16 competing clients on the same guard cannot duplicate publication or acquire another disk writer',async t=>{
 const f=await lab(t),w=await f.open();
 await assert.rejects(f.open(),/anchor state unavailable/);
 const results=await Promise.allSettled(Array.from({length:16},()=>w.compareAndSwap({...scope,previous:first,next:second})));
 assert.equal(results.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(results.filter(x=>x.status==='rejected').length,15);
 assert.equal(f.writes(),1);
 assert.equal((await w.audit()).count,2);
 await w.close();
});
test('out-of-band remote advancement and tampering latch denial even when later repaired',async t=>{
 const f=await lab(t),w=await f.open();
 const original=f.getCurrent();
 f.setCurrent(f.makeReceipt({count:2,checkpoint:second,headHash:'b'.repeat(64)}));
 await assert.rejects(w.read(scope),/anchor state unavailable/);
 f.setCurrent(original);
 await assert.rejects(w.read(scope),/anchor state unavailable/);
 await w.close();
});
test('forged signatures, wrong externally pinned head and invalid receipt floors reject startup',async t=>{
 const f=await lab(t),original=f.getCurrent();
 const attacker=generateKeyPairSync('ed25519');
 const forgery={statement:original.statement,
  signature:sign(null,canonicalWitnessAuditStatement(original.statement),attacker.privateKey).toString('base64url')};
 f.setCurrent(forgery);
 await assert.rejects(f.open(),/anchor state unavailable/);
 f.setCurrent(original);
 await assert.rejects(f.open({count:1,headHash:'a'.repeat(64)}),/anchor state unavailable/);
 await assert.rejects(f.open({count:0,headHash:f.initialFloor.headHash}),/anchor state unavailable/);
});

test('stale client CAS before any write rejects safely without poisoning current authentication',async t=>{
 const f=await lab(t),w=await f.open();
 await assert.rejects(w.compareAndSwap({...scope,previous:second,next:third}),/conflict/);
 assert.equal(f.writes(),0);
 assert.deepEqual(await w.read(scope),first);
 assert.deepEqual(await w.compareAndSwap({...scope,previous:first,next:second}),second);
 await w.close();
});
