import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {generateKeyPairSync,sign} from 'node:crypto';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {request as httpsRequest} from 'node:https';
import {encodeWitnessGenesis,openReferenceWitnessJournal,verifyWitnessJournal} from '../../src/security/provider-witness-journal.mjs';
import {createHttpsProviderCheckpointWitness} from '../../src/security/provider-checkpoint-https-witness.mjs';
import {openLoopbackWitnessHttpsFixture} from '../fixtures/witness-loopback-server.mjs';
import {createUnsignedWitnessAuditStatement,canonicalWitnessAuditStatement,verifyExternallySignedWitnessAuditReceipt} from '../../src/security/provider-witness-audit-receipt.mjs';

const scope={issuer:'https://issuer.example.invalid',audience:'verivaro-internal'};
const first={sequence:1,digest:'1'.repeat(64)};
const second={sequence:2,digest:'2'.repeat(64)};
const third={sequence:3,digest:'3'.repeat(64)};
async function lab(t){
 const root=await mkdtemp(join(tmpdir(),'vv-network-cas-'));
 const directory=join(root,'journal');
 await mkdir(directory,{mode:0o700});
 const genesis=encodeWitnessGenesis({...scope,checkpoint:first});
 const journalPath=join(directory,'witness-journal.jsonl');
 await writeFile(journalPath,genesis.bytes,{mode:0o600});
 const certPath=join(root,'test-tls-cert.pem'),keyPath=join(root,'test-tls-key.pem');
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes',
  '-keyout',keyPath,'-out',certPath,'-subj','/CN=localhost',
  '-addext','subjectAltName=DNS:localhost','-days','1'],{stdio:'ignore'});
 const [cert,key]=await Promise.all([readFile(certPath),readFile(keyPath)]);
 const journal=await openReferenceWitnessJournal({...scope,directory,trustedHead:genesis.headHash});
 const server=await openLoopbackWitnessHttpsFixture({journal,...scope,key,cert,ca:cert,maxConcurrentRequests:32});
 const witness=createHttpsProviderCheckpointWitness({
  endpoint:server.endpoint,...scope,caPem:cert,clientCertPem:cert,clientKeyPem:key,
  allowLoopbackForTests:true,maxInFlight:32,requestTimeoutMs:1000
 });
 t.after(async()=>{
  witness.close();
  await server.close();
  await journal.close();
  await rm(root,{recursive:true,force:true});
 });
 return {journal,server,witness,genesis,journalPath,cert,key,root};
}
test('real mTLS network CAS advances file journal and old state cannot replay',async t=>{
 const f=await lab(t);
 assert.deepEqual(await f.witness.read(scope),first);
 assert.deepEqual(await f.witness.compareAndSwap({...scope,previous:first,next:second}),second);
 assert.deepEqual(await f.witness.read(scope),second);
 await assert.rejects(f.witness.compareAndSwap({...scope,previous:first,next:second}),/unavailable/);
 assert.equal((await f.journal.audit()).count,2);
});
test('16 competing HTTPS CAS operations commit exactly one durable journal entry',async t=>{
 const f=await lab(t);
 const attempts=await Promise.allSettled(Array.from({length:16},()=>f.witness.compareAndSwap({
  ...scope,previous:first,next:second
 })));
 assert.equal(attempts.filter(a=>a.status==='fulfilled').length,1);
 assert.equal(attempts.filter(a=>a.status==='rejected').length,15);
 assert.deepEqual(await f.witness.read(scope),second);
 const observed=await f.journal.audit();
 assert.equal(observed.count,2);
 assert.deepEqual(verifyWitnessJournal(await readFile(f.journalPath),
  {...scope,trustedHead:observed.headHash}).checkpoint,second);
});
test('unsupported methods, malformed canonical requests and missing client certificate are rejected',async t=>{
 const f=await lab(t);
 const ask=({method='POST',body='',key=f.key,cert=f.cert,headers={}})=>new Promise((resolve,reject)=>{
  const req=httpsRequest(f.server.endpoint,{
   method,ca:f.cert,key,cert,rejectUnauthorized:true,
   headers:{
    'Content-Type':'application/json','Accept':'application/json',
    'Accept-Encoding':'identity','Content-Length':Buffer.byteLength(body),...headers
   }
  },res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});
  req.on('error',reject);req.end(body);
 });
 const readBody=JSON.stringify({version:1,operation:'read',...scope});
 assert.equal(await ask({method:'GET',body:readBody}),400);
 assert.equal(await ask({body:readBody.replace('"version":1','"version":1,"version":1')}),400);
 assert.equal(await ask({body:JSON.stringify({...JSON.parse(readBody),audience:'other'})}),400);
 assert.equal(await ask({body:readBody,headers:{'Content-Type':'text/plain'}}),400);
 assert.equal(await ask({body:readBody,headers:{'Accept-Encoding':'gzip'}}),400);
 await assert.rejects(ask({body:readBody,key:null,cert:null}),/certificate|alert|handshake|socket/i);
 assert.deepEqual(await f.witness.read(scope),first);
});
test('tampering the disk hash chain permanently denies network reads and CAS',async t=>{
 const f=await lab(t);
 await f.witness.compareAndSwap({...scope,previous:first,next:second});
 const before=await readFile(f.journalPath);
 await writeFile(f.journalPath,Buffer.from(before.toString('utf8').replace('"digest":"2222','"digest":"9999')));
 await assert.rejects(f.witness.read(scope),/unavailable/);
 await writeFile(f.journalPath,before);
 await assert.rejects(f.witness.read(scope),/unavailable/);
 await assert.rejects(f.witness.compareAndSwap({...scope,previous:second,next:third}),/unavailable/);
});
test('audit head receipts need independent signature and a separately retained freshness floor',async t=>{
 const f=await lab(t);
 const independent=generateKeyPairSync('ed25519'),attacker=generateKeyPairSync('ed25519');
 const snapshot1=await f.journal.audit();
 const makeReceipt=snapshot=>{
  const statement=createUnsignedWitnessAuditStatement({
   ...scope,...snapshot,issuedAt:'2026-11-21T00:00:00.000Z'
  });
  const signature=sign(null,canonicalWitnessAuditStatement(statement),independent.privateKey).toString('base64url');
  return {statement,signature};
 };
 const old=makeReceipt(snapshot1);
 assert.equal(verifyExternallySignedWitnessAuditReceipt(old,{
  trustedPublicKey:independent.publicKey,...scope,minimumCount:1,
  expectedHeadHash:snapshot1.headHash
 }).count,1);
 await f.witness.compareAndSwap({...scope,previous:first,next:second});
 const snapshot2=await f.journal.audit(),newReceipt=makeReceipt(snapshot2);
 assert.equal(verifyExternallySignedWitnessAuditReceipt(newReceipt,{
  trustedPublicKey:independent.publicKey,...scope,minimumCount:2,
  expectedHeadHash:snapshot2.headHash
 }).count,2);
 assert.throws(()=>verifyExternallySignedWitnessAuditReceipt(old,{
  trustedPublicKey:independent.publicKey,...scope,minimumCount:2
 }),/verification/);
 assert.throws(()=>verifyExternallySignedWitnessAuditReceipt({
  ...newReceipt,signature:sign(null,canonicalWitnessAuditStatement(newReceipt.statement),attacker.privateKey).toString('base64url')
 },{trustedPublicKey:independent.publicKey,...scope,minimumCount:2}),/verification/);
 assert.throws(()=>verifyExternallySignedWitnessAuditReceipt({
  ...newReceipt,statement:{...newReceipt.statement,headHash:'a'.repeat(64)}
 },{trustedPublicKey:independent.publicKey,...scope,minimumCount:2}),/verification/);
 assert.throws(()=>verifyExternallySignedWitnessAuditReceipt(newReceipt,{
  trustedPublicKey:independent.publicKey,...scope,minimumCount:2,
  expectedHeadHash:'b'.repeat(64)
 }),/verification/);
});
