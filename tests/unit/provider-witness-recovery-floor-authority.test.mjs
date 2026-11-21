import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {mkdtemp,mkdir,rm,writeFile,readFile,readdir,unlink,rename,symlink} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {encodeReferenceRecoveryApprovalGenesis} from '../../src/security/provider-witness-recovery-consumption.mjs';
import {recoveryFloorAuthorityKeyId,createTrustedRecoveryFloorAuthorityKeySchedule} from '../../src/security/provider-witness-authority-key-schedule.mjs';
import {
 canonicalRecoveryFloorPublicationStatement,
 createUnsignedRecoveryFloorPublicationStatement,
 canonicalRecoveryFloorAuthorityStatement,
 verifySignedRecoveryFloorAuthority,
 openReferenceRecoveryFloorPublicationGate
} from '../../src/security/provider-witness-recovery-floor-publication.mjs';
import {
 encodeReferenceRecoveryFloorAuthorityGenesis,
 verifyReferenceRecoveryFloorAuthorityLog,
 openReferenceRecoveryFloorAuthority
} from '../../src/security/provider-witness-recovery-floor-authority.mjs';

const execAsync=promisify(execFile);
const scope={issuer:'https://issuer.example.invalid',audience:'verivaro-internal'};
const now='2026-11-21T04:00:00.000Z';
const testNonce='A'.repeat(43),otherNonce='B'.repeat(42)+'A';
const approvalId='1'.repeat(32),publicationId='2'.repeat(32),evidenceHash='3'.repeat(64);
const signedBytes=(bytes,key)=>sign(null,bytes,key).toString('base64url');
async function lab(t){
 const root=await mkdtemp(join(tmpdir(),'vv-authority-ref-'));
 t.after(()=>rm(root,{recursive:true,force:true}));
 const directory=join(root,'authority');
 await mkdir(directory,{mode:0o700});
 const custodians={primary:generateKeyPairSync('ed25519'),
  secondary:generateKeyPairSync('ed25519')};
 const authorityKeys=generateKeyPairSync('ed25519');
 const consumed=encodeReferenceRecoveryApprovalGenesis({...scope,serial:6});
 const prior={serial:6,headHash:consumed.headHash};
 const body={version:1,kind:'consume',...scope,serial:7,approvalId,
  evidenceHash,previousHash:consumed.headHash};
 const digest=createHash('sha256')
  .update('verivaro-g1-consumed-review-v1\0')
  .update(Buffer.from(JSON.stringify(body))).digest('hex');
 const next={serial:7,headHash:digest};
 const log=Buffer.concat([consumed.bytes,Buffer.from(JSON.stringify({
  ...body,hash:digest
 })+'\n')]);
 const genesis=encodeReferenceRecoveryFloorAuthorityGenesis({
  ...scope,initialFloor:prior
 });
 const path=join(directory,'recovery-floor-authority.jsonl');
 await writeFile(path,genesis.bytes,{mode:0o600});
 const trustedKeys={primary:custodians.primary.publicKey,
  secondary:custodians.secondary.publicKey};
 const config=(state=genesis.trustedAuthorityState)=>({
  directory,...scope,trustedAuthorityState:state,
  trustedAuthorityKey:authorityKeys.publicKey,
  trustedCustodianKeys:trustedKeys,
  signReceipt:bytes=>signedBytes(bytes,authorityKeys.privateKey),
  clock:()=>new Date(now),signTimeoutMs:500
 });
 const make=(overrides={})=>{
  const statement=createUnsignedRecoveryFloorPublicationStatement({
   ...scope,publicationId,previous:prior,next,approvalId,evidenceHash,
   issuedAt:'2026-11-21T03:00:00.000Z',
   expiresAt:'2026-11-21T05:00:00.000Z',...overrides
  });
  const bytes=canonicalRecoveryFloorPublicationStatement(statement);
  return {statement,signatures:[
   {role:'primary',signature:signedBytes(bytes,custodians.primary.privateKey)},
   {role:'secondary',signature:signedBytes(bytes,custodians.secondary.privateKey)}
  ]};
 };
 const open=(state=genesis.trustedAuthorityState)=>openReferenceRecoveryFloorAuthority(config(state));
 const gate=authority=>openReferenceRecoveryFloorPublicationGate({
  ...scope,trustedFloor:prior,trustedAuthorityKey:authorityKeys.publicKey,
  trustedCustodianKeys:trustedKeys,authority,ioTimeoutMs:600,
  clock:()=>new Date(now)
 });
 const request=(overrides={})=>({...scope,previous:prior,
  publication:make(),consumptionLog:log,requestNonce:testNonce,...overrides});
 return {root,directory,path,custodians,authorityKeys,
  prior,next,genesis,log,trustedKeys,config,make,open,gate,request};
}
test('real file-backed reference authority interoperates with signed publication gate',async t=>{
 const f=await lab(t),a=await f.open(),g=await f.gate(a);
 const initial=await a.read(scope,{requestNonce:testNonce});
 assert.deepEqual(verifySignedRecoveryFloorAuthority(initial,{
  ...scope,trustedAuthorityKey:f.authorityKeys.publicKey,
  expectedRequestNonce:testNonce,now
 }),f.prior);
 const receipt=await g.publish({publication:f.make(),consumptionLog:f.log});
 assert.equal(receipt.status,'REVIEW_FLOOR_PUBLISHED_ONLY');
 assert.equal(receipt.automaticRecoveryPermitted,false);
 assert.deepEqual(await g.audit(),f.next);
 const durable=await a.audit();
 assert.equal(durable.serial,7);
 assert.equal(durable.headHash,f.next.headHash);
 assert.equal(durable.count,2);
 g.close();await a.close();
 await assert.rejects(f.open(),/unavailable/);
 const reopened=await f.open({serial:durable.serial,
  headHash:durable.headHash,logHash:durable.logHash});
 assert.deepEqual(verifySignedRecoveryFloorAuthority(await reopened.read(scope,{requestNonce:testNonce}),{
  ...scope,trustedAuthorityKey:f.authorityKeys.publicKey,
  expectedRequestNonce:testNonce,now
 }),f.next);
 await reopened.close();
});

test('serial-bound signer rollover interoperates with real CAS and rejects old-key downgrade',async t=>{
 const f=await lab(t);
 const successor=generateKeyPairSync('ed25519');
 const schedule=createTrustedRecoveryFloorAuthorityKeySchedule({epochs:[
  {firstSerial:0,lastSerial:6,
   keyId:recoveryFloorAuthorityKeyId(f.authorityKeys.publicKey),
   publicKey:f.authorityKeys.publicKey},
  {firstSerial:7,lastSerial:null,
   keyId:recoveryFloorAuthorityKeyId(successor.publicKey),
   publicKey:successor.publicKey}
 ]});
 const signRotated=(bytes,statement)=>signedBytes(bytes,
  statement.serial<=6?f.authorityKeys.privateKey:successor.privateKey);
 const authority=await openReferenceRecoveryFloorAuthority({
  ...f.config(),trustedAuthorityKey:undefined,
  trustedAuthorityKeySchedule:schedule,signReceipt:signRotated
 });
 const gate=await openReferenceRecoveryFloorPublicationGate({
  ...scope,trustedFloor:f.prior,trustedAuthorityKeySchedule:schedule,
  trustedCustodianKeys:f.trustedKeys,authority,
  ioTimeoutMs:600,clock:()=>new Date(now)
 });
 const initial=await authority.read(scope,{requestNonce:testNonce});
 assert.deepEqual(verifySignedRecoveryFloorAuthority(initial,{
  ...scope,trustedAuthorityKeySchedule:schedule,
  expectedRequestNonce:testNonce,now
 }),f.prior);
 const result=await gate.publish({
  publication:f.make(),consumptionLog:f.log
 });
 assert.equal(result.status,'REVIEW_FLOOR_PUBLISHED_ONLY');
 assert.equal(result.automaticRecoveryPermitted,false);
 assert.deepEqual(await gate.audit(),f.next);
 const current=await authority.audit();
 gate.close();await authority.close();
 const fresh=await openReferenceRecoveryFloorAuthority({
  ...f.config({serial:current.serial,headHash:current.headHash,
   logHash:current.logHash}),trustedAuthorityKey:undefined,
  trustedAuthorityKeySchedule:schedule,signReceipt:signRotated
 });
 assert.deepEqual(verifySignedRecoveryFloorAuthority(
  await fresh.read(scope,{requestNonce:otherNonce}),{
   ...scope,trustedAuthorityKeySchedule:schedule,
   expectedRequestNonce:otherNonce,now
  }),f.next);
 await fresh.close();
});

test('wrong signer after a durable serial advance faults and retains forensic lock',async t=>{
 const f=await lab(t);
 const successor=generateKeyPairSync('ed25519');
 const schedule=createTrustedRecoveryFloorAuthorityKeySchedule({epochs:[
  {firstSerial:0,lastSerial:6,
   keyId:recoveryFloorAuthorityKeyId(f.authorityKeys.publicKey),
   publicKey:f.authorityKeys.publicKey},
  {firstSerial:7,lastSerial:null,
   keyId:recoveryFloorAuthorityKeyId(successor.publicKey),
   publicKey:successor.publicKey}
 ]});
 const authority=await openReferenceRecoveryFloorAuthority({
  ...f.config(),trustedAuthorityKey:undefined,
  trustedAuthorityKeySchedule:schedule,
  // A stale signer keeps signing with the retired key after serial 7.
  signReceipt:(bytes)=>signedBytes(bytes,f.authorityKeys.privateKey)
 });
 await assert.rejects(authority.compareAndSwap(f.request()),/unavailable/);
 assert.equal((await readFile(f.path,'utf8')).trimEnd().split('\n').length,2);
 await assert.rejects(authority.read(scope,{requestNonce:otherNonce}),/unavailable/);
 await authority.close();
 assert.ok((await readdir(f.directory)).includes('.recovery-floor-authority.lock'));
});

test('16 concurrent CAS requests permit exactly one durable authority commit',async t=>{
 const f=await lab(t),a=await f.open();
 const results=await Promise.allSettled(Array.from({length:16},
  ()=>a.compareAndSwap(f.request())));
 assert.equal(results.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(results.filter(x=>x.status==='rejected').length,15);
 assert.equal((await a.audit()).serial,7);
 assert.equal((await readFile(f.path,'utf8')).trimEnd().split('\n').length,2);
 await a.close();
});
test('two separately opened gate clients cannot jointly commit one head',async t=>{
 const f=await lab(t),a=await f.open();
 const first=await f.gate(a),second=await f.gate(a);
 const args={publication:f.make(),consumptionLog:f.log};
 const results=await Promise.allSettled([first.publish(args),second.publish(args)]);
 assert.equal(results.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(results.filter(x=>x.status==='rejected').length,1);
 assert.equal((await a.audit()).serial,7);
 first.close();second.close();await a.close();
});
test('two authorities cannot own the same private filesystem lease',async t=>{
 const f=await lab(t),a=await f.open();
 await assert.rejects(f.open(),/unavailable/);
 await a.close();
 const reopened=await f.open();
 assert.equal((await reopened.audit()).serial,6);
 await reopened.close();
});
test('malformed signed proposals, stale custodians and invalid previous head do not write',async t=>{
 const f=await lab(t),a=await f.open();
 await assert.rejects(a.compareAndSwap(f.request({
  previous:{serial:6,headHash:'a'.repeat(64)}
 })),/conflict/);
 await assert.rejects(a.compareAndSwap(f.request({
  publication:f.make({approvalId:'a'.repeat(32)})
 })),/invalid publication/);
 await assert.rejects(a.compareAndSwap(f.request({
  publication:{...f.make(),signatures:[
   {...f.make().signatures[0],signature:'a'.repeat(86)},
   f.make().signatures[1]
  ]}
 })),/invalid publication/);
 assert.equal((await a.audit()).serial,6);
 await a.compareAndSwap(f.request());
 await a.close();
});
test('interrupted fsync-to-ACK window faults, retains lock and never retries',async t=>{
 const f=await lab(t),a=await openReferenceRecoveryFloorAuthority({
  ...f.config(),enableTestFaultInjection:true,
  faultInjection:phase=>{
   if(phase==='after-fsync')throw Error('simulated lost acknowledgement');
  }
 });
 await assert.rejects(a.compareAndSwap(f.request()),/unavailable/);
 const bytes=await readFile(f.path);
 assert.equal(bytes.toString().trimEnd().split('\n').length,2);
 await assert.rejects(a.compareAndSwap(f.request()),/unavailable/);
 await a.close();
 assert.ok((await readdir(f.directory)).includes('.recovery-floor-authority.lock'));
 await assert.rejects(f.open(),/unavailable/);
});
test('actual child process crash after fsync preserves ambiguous commit and lock',async t=>{
 const f=await lab(t),temp=join(f.root,'child.json'),
  owner=join(f.root,'custodian-a.pem'),secondary=join(f.root,'custodian-b.pem'),
  signer=join(f.root,'authority.pem');
 await writeFile(owner,f.custodians.primary.publicKey.export({type:'spki',format:'pem'}),{mode:0o600});
 await writeFile(secondary,f.custodians.secondary.publicKey.export({type:'spki',format:'pem'}),{mode:0o600});
 await writeFile(signer,f.authorityKeys.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});
 await writeFile(temp,JSON.stringify({
  directory:f.directory,...scope,trustedAuthorityState:f.genesis.trustedAuthorityState,
  publication:f.make(),consumptionLog:f.log.toString('base64'),
  requestNonce:testNonce
 }),{mode:0o600});
 const child=String.raw`
import {readFileSync} from 'node:fs';
import {createPrivateKey,createPublicKey,sign} from 'node:crypto';
import {openReferenceRecoveryFloorAuthority} from './src/security/provider-witness-recovery-floor-authority.mjs';
try{
 const data=JSON.parse(readFileSync(process.env.VV_DATA));
 const keys={primary:createPublicKey(readFileSync(process.env.VV_PRIMARY)),
  secondary:createPublicKey(readFileSync(process.env.VV_SECONDARY))};
 const signer=createPrivateKey(readFileSync(process.env.VV_SIGNER));
 const a=await openReferenceRecoveryFloorAuthority({...data,
  trustedAuthorityKey:createPublicKey(signer),
  trustedCustodianKeys:keys,clock:()=>new Date('2026-11-21T04:00:00.000Z'),
  signReceipt:bytes=>sign(null,bytes,signer).toString('base64url'),
  enableTestFaultInjection:true,
  faultInjection:phase=>{if(phase==='after-fsync')process.exit(77);}
 });
 await a.compareAndSwap({...data,previous:{
  serial:6,headHash:data.publication.statement.previous.headHash
 },consumptionLog:Buffer.from(data.consumptionLog,'base64')});
 process.exit(78);
}catch{process.exit(79);}
`;
 await assert.rejects(execAsync(process.execPath,
  ['--input-type=module','-e',child],{cwd:process.cwd(),timeout:10000,
   env:{...process.env,VV_DATA:temp,VV_PRIMARY:owner,
    VV_SECONDARY:secondary,VV_SIGNER:signer}}),e=>e.code===77);
 const rows=(await readFile(f.path,'utf8')).trimEnd().split('\n');
 const last=JSON.parse(rows.at(-1));
 const state={serial:7,headHash:f.next.headHash,logHash:last.hash};
 assert.equal(verifyReferenceRecoveryFloorAuthorityLog(
  Buffer.from(rows.join('\n')+'\n'),{
   ...scope,trustedAuthorityState:state
  }).serial,7);
 await assert.rejects(f.open(state),/unavailable/);
 assert.ok((await readdir(f.directory)).includes('.recovery-floor-authority.lock'));
});
test('network partition before CAS fails closed without a commit',async t=>{
 const f=await lab(t),a=await f.open();
 let partitioned=true;
 const network={read:(...args)=>partitioned?
  Promise.reject(Error('partition')):a.read(...args),
  compareAndSwap:(...args)=>partitioned?
   Promise.reject(Error('partition')):a.compareAndSwap(...args)};
 await assert.rejects(f.gate(network),/unavailable/);
 partitioned=false;
 assert.equal((await a.audit()).serial,6);
 await a.close();
});
test('network partition after actual commit loses ACK, gate faults while floor advances',async t=>{
 const f=await lab(t),a=await f.open();
 const network={
  read:(...args)=>a.read(...args),
  compareAndSwap:async(...args)=>{
   await a.compareAndSwap(...args);
   throw Error('network partition after remote commit');
  }
 };
 const gate=await f.gate(network);
 await assert.rejects(gate.publish({
  publication:f.make(),consumptionLog:f.log
 }),/unavailable/);
 assert.equal((await a.audit()).serial,7);
 await assert.rejects(gate.audit(),/unavailable/);
 gate.close();await a.close();
 await assert.rejects(f.open(),/unavailable/);
});
test('out-of-band log mutation permanently faults and preserves lease',async t=>{
 const f=await lab(t),a=await f.open();
 const initial=await readFile(f.path);
 await writeFile(f.path,initial.subarray(0,initial.length-3));
 await assert.rejects(a.audit(),/unavailable/);
 await writeFile(f.path,initial);
 await assert.rejects(a.read(scope,{requestNonce:testNonce}),/unavailable/);
 await a.close();
 await assert.rejects(f.open(),/unavailable/);
});
test('valid signature returned by unavailable signer after deadline cannot acknowledge',async t=>{
 const f=await lab(t);
 let entered,finish;
 const started=new Promise(resolve=>{entered=resolve;});
 const a=await openReferenceRecoveryFloorAuthority({...f.config(),
  signTimeoutMs:35,signReceipt:(bytes,_statement,{signal})=>{
   entered({bytes,signal});
   return new Promise(resolve=>{finish=resolve;});
  }
 });
 const pending=a.read(scope,{requestNonce:testNonce});
 const invocation=await started;
 await assert.rejects(pending,/unavailable/);
 assert.equal(invocation.signal.aborted,true);
 finish(signedBytes(invocation.bytes,f.authorityKeys.privateKey));
 await new Promise(resolve=>setImmediate(resolve));
 await assert.rejects(a.audit(),/unavailable/);
 await a.close();
 assert.ok((await readdir(f.directory)).includes('.recovery-floor-authority.lock'));
});
test('stale, truncated and rehashed authority journal fail separately pinned state',async t=>{
 const f=await lab(t),a=await f.open(),initial=await readFile(f.path);
 await a.compareAndSwap(f.request());
 const current=await a.audit();
 await a.close();
 const floor={serial:current.serial,headHash:current.headHash,
  logHash:current.logHash};
 await writeFile(f.path,initial);
 await assert.rejects(f.open(floor),/unavailable/);
 await writeFile(f.path,initial.subarray(0,-4));
 await assert.rejects(f.open(),/unavailable/);
 const modified=Buffer.from(initial.toString().replace('"serial":6','"serial":5'));
 await writeFile(f.path,modified);
 await assert.rejects(f.open(),/unavailable/);
});
test('orphan evidence, stale lock and symlink do not acquire writer lease',async t=>{
 const f=await lab(t),extra=join(f.directory,'unexpected.pending');
 await writeFile(extra,'evidence',{mode:0o600});
 await assert.rejects(f.open(),/unavailable/);
 await unlink(extra);
 const lock=join(f.directory,'.recovery-floor-authority.lock');
 await writeFile(lock,'reserved\n',{mode:0o600});
 await assert.rejects(f.open(),/unavailable/);
 await unlink(lock);
 const other=join(f.root,'original.jsonl');
 await rename(f.path,other);
 await symlink(other,f.path);
 await assert.rejects(f.open(),/unavailable/);
});


test('reference authority rejects unchallenged reads and CAS before changing persistent data',async t=>{
 const f=await lab(t),a=await f.open(),bytes=await readFile(f.path);
 await assert.rejects(a.read(scope),/unavailable/);
 await assert.rejects(a.compareAndSwap(f.request({requestNonce:undefined})),/unavailable/);
 assert.equal((await readFile(f.path)).equals(bytes),true);
 const signed=await a.read(scope,{requestNonce:testNonce});
 assert.equal(signed.statement.requestNonce,testNonce);
 await a.close();
});

test('authority signs the exact read and CAS nonce with a short v2 expiry window',async t=>{
 const f=await lab(t),a=await f.open();
 const initial=await a.read(scope,{requestNonce:testNonce});
 assert.equal(initial.statement.version,2);
 assert.equal(initial.statement.domain,'verivaro-g1-review-floor-authority-v2');
 assert.equal(initial.statement.requestNonce,testNonce);
 assert.equal(initial.statement.expiresAt,'2026-11-21T04:00:10.000Z');
 const ack=await a.compareAndSwap(f.request({requestNonce:otherNonce}));
 assert.equal(ack.statement.requestNonce,otherNonce);
 assert.throws(()=>verifySignedRecoveryFloorAuthority(ack,{
  ...scope,trustedAuthorityKey:f.authorityKeys.publicKey,
  expectedRequestNonce:testNonce,now
 }),/rejected/);
 assert.deepEqual(verifySignedRecoveryFloorAuthority(ack,{
  ...scope,trustedAuthorityKey:f.authorityKeys.publicKey,
  expectedRequestNonce:otherNonce,now
 }),f.next);
 await a.close();
});
