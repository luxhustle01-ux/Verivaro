import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,open,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {issuer,audience,nonce,token,publicKey,privateKey} from '../fixtures/provider-fixture.mjs';
import {openFileProviderCheckpointStore} from '../../src/security/provider-checkpoint-store.mjs';
import {openWitnessBoundProviderVerifier} from '../../src/security/provider-checkpoint-witness.mjs';

const now=1800000000;
const record=c=>JSON.stringify({version:1,issuer,audience,sequence:c.sequence,digest:c.digest})+'\n';
function catalogue(authority,sequence,kid,key){
 const bytes=Buffer.from(JSON.stringify({version:1,issuer,audience,sequence,issuedAt:now,expiresAt:now+600,
  keys:[{kid,pem:key.export({type:'spki',format:'pem'})}]}));
 return {catalogue:bytes,signature:sign(null,bytes,authority.privateKey),
  checkpoint:{sequence,digest:createHash('sha256').update(bytes).digest('hex')}};
}
async function fixture(t,first){
 const directory=await mkdtemp(join(tmpdir(),'vv-witness-'));
 t.after(async()=>rm(directory,{recursive:true,force:true}));
 const filename=join(directory,'provider-keyset-checkpoint.json');
 const f=await open(filename,'wx',0o600);
 try{await f.writeFile(record(first.checkpoint));await f.sync();}finally{await f.close();}
 return {directory,filename};
}
function fakeWitness(initial,events=[]){
 let stored={...initial};
 return {
  read:async({issuer:iss,audience:aud})=>{
   assert.equal(iss,issuer);assert.equal(aud,audience);
   events.push('witness-read');return {...stored};
  },
  compareAndSwap:async({issuer:iss,audience:aud,previous,next})=>{
   assert.equal(iss,issuer);assert.equal(aud,audience);
   events.push('witness-commit');
   if(stored.sequence!==previous.sequence||stored.digest!==previous.digest)
    throw Error('witness compare-and-swap conflict');
   if(next.sequence<=stored.sequence)throw Error('witness sequence rollback');
   stored={...next};
   return {...stored};
  },
  inspect:()=>({...stored}),
  setForTest:c=>{stored={...c};}
 };
}
function config(store,witness,authority,first){
 return {store,witness,issuer,audience,authorityKey:authority.publicKey,requiredAcr:'fixture:mfa',
  catalogue:first.catalogue,signature:first.signature,now:()=>now};
}
test('independent witness catches local disk snapshot rollback on verifier restart',async t=>{
 const authority=generateKeyPairSync('ed25519'),other=generateKeyPairSync('rsa',{modulusLength:2048});
 const first=catalogue(authority,1,'fixture',publicKey),next=catalogue(authority,2,'next',other.publicKey);
 const {directory,filename}=await fixture(t,first);
 const witness=fakeWitness(first.checkpoint),store=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>store.close().catch(()=>{}));
 const v=await openWitnessBoundProviderVerifier(config(store,witness,authority,first));
 assert.equal((await v.verify(token(nonce(),{iat:now,auth_time:now,exp:now+300}))).issuer,issuer);
 await v.rotate(next.catalogue,next.signature,next.checkpoint);
 assert.deepEqual(await store.read(),next.checkpoint);
 assert.deepEqual(witness.inspect(),next.checkpoint);
 await assert.rejects(v.verify(token(nonce(),{iat:now,auth_time:now,exp:now+300})),/unsupported provider header/);
 await store.close();
 // Simulate rollback of ONLY local storage, without rewriting the separate
 // witness. The checkpoint directory is already single-owner-unlocked.
 await writeFile(filename,record(first.checkpoint));
 const rolledBack=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>rolledBack.close().catch(()=>{}));
 await assert.rejects(openWitnessBoundProviderVerifier(config(rolledBack,witness,authority,first)),/witness disagreement/);
 assert.deepEqual(witness.inspect(),next.checkpoint);
});
test('witness-before-disk ordering and fail-closed ambiguous second commit',async t=>{
 const authority=generateKeyPairSync('ed25519'),other=generateKeyPairSync('rsa',{modulusLength:2048});
 const first=catalogue(authority,1,'fixture',publicKey),next=catalogue(authority,2,'next',other.publicKey);
 const {directory}=await fixture(t,first),events=[];
 const witness=fakeWitness(first.checkpoint,events);
 const real=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>real.close().catch(()=>{}));
 const store={
  read:()=>real.read(),isOpen:()=>real.isOpen(),
  bindVerifier:()=>{
   const commit=real.bindVerifier();
   return async(prev,nextState)=>{
    events.push('disk-commit');
    return commit(prev,nextState);
   };
  }
 };
 const v=await openWitnessBoundProviderVerifier(config(store,witness,authority,first));
 await v.rotate(next.catalogue,next.signature,next.checkpoint);
 assert.ok(events.indexOf('witness-commit')<events.indexOf('disk-commit'));
 assert.deepEqual(await real.read(),next.checkpoint);
 await real.close();
 // An independent witness ahead of a restored old disk checkpoint must
 // block startup even when the old catalogue is correctly signed.
 const oldDirectory=await fixture(t,first);
 const stale=await openFileProviderCheckpointStore({directory:oldDirectory.directory,issuer,audience});
 t.after(()=>stale.close().catch(()=>{}));
 await assert.rejects(openWitnessBoundProviderVerifier(config(stale,witness,authority,first)),/witness disagreement/);
});
test('witness conflict or incomplete persistence blocks all further token checks',async t=>{
 const authority=generateKeyPairSync('ed25519'),other=generateKeyPairSync('rsa',{modulusLength:2048});
 const first=catalogue(authority,1,'fixture',publicKey),next=catalogue(authority,2,'next',other.publicKey);
 const {directory}=await fixture(t,first);
 const witness=fakeWitness(first.checkpoint);
 const real=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>real.close().catch(()=>{}));
 const store={read:()=>real.read(),isOpen:()=>real.isOpen(),
  bindVerifier:()=>{
   real.bindVerifier();
   return async()=>{throw Error('synthetic disk fsync failure');};
  }};
 const verifier=await openWitnessBoundProviderVerifier(config(store,witness,authority,first));
 await assert.rejects(verifier.rotate(next.catalogue,next.signature,next.checkpoint),/update unconfirmed/);
 await assert.rejects(verifier.verify(token(nonce(),{iat:now,auth_time:now,exp:now+300})),/unavailable/);
 assert.deepEqual(await real.read(),first.checkpoint);
 assert.deepEqual(witness.inspect(),next.checkpoint);
 await real.close();
 // Since the authoritative witness committed and local fsync failed, a new
 // process may not silently fall back to the previous signed catalogue.
 const restarted=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>restarted.close().catch(()=>{}));
 await assert.rejects(openWitnessBoundProviderVerifier(config(restarted,witness,authority,first)),/witness disagreement/);
});
test('requires an independently supplied witness and rejects stale external state at startup',async t=>{
 const authority=generateKeyPairSync('ed25519'),first=catalogue(authority,1,'fixture',publicKey);
 const {directory}=await fixture(t,first);
 const real=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>real.close().catch(()=>{}));
 await assert.rejects(openWitnessBoundProviderVerifier(config(real,undefined,authority,first)),/independent provider checkpoint witness required/);
 const stale=fakeWitness({sequence:0,digest:first.checkpoint.digest});
 await assert.rejects(openWitnessBoundProviderVerifier(config(real,stale,authority,first)),/witness disagreement/);
 // A failed pre-bind witness check must not permanently consume the store's
 // single authorised verifier lease.
 const accepted=await openWitnessBoundProviderVerifier(config(real,fakeWitness(first.checkpoint),authority,first));
 assert.equal((await accepted.verify(token(nonce(),{iat:now,auth_time:now,exp:now+300}))).issuer,issuer);
});

test('out-of-band witness advance denies a running verifier and latches denial',async t=>{
 const authority=generateKeyPairSync('ed25519'),first=catalogue(authority,1,'fixture',publicKey);
 const {directory}=await fixture(t,first);
 const witness=fakeWitness(first.checkpoint);
 const store=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>store.close().catch(()=>{}));
 const v=await openWitnessBoundProviderVerifier(config(store,witness,authority,first));
 const jwt=token(nonce(),{iat:now,auth_time:now,exp:now+300});
 assert.equal((await v.verify(jwt)).issuer,issuer);
 witness.setForTest({sequence:2,digest:'2'.repeat(64)});
 await assert.rejects(v.verify(jwt),/witness disagreement/);
 witness.setForTest(first.checkpoint);
 await assert.rejects(v.verify(jwt),/witness unavailable/);
});
test('witness read failure after startup permanently denies verification',async t=>{
 const authority=generateKeyPairSync('ed25519'),first=catalogue(authority,1,'fixture',publicKey);
 const {directory}=await fixture(t,first);
 const base=fakeWitness(first.checkpoint);
 let failReads=false;
 const witness={
  read:async scope=>{if(failReads)throw Error('unavailable witness storage');return base.read(scope);},
  compareAndSwap:args=>base.compareAndSwap(args)
 };
 const store=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>store.close().catch(()=>{}));
 const v=await openWitnessBoundProviderVerifier(config(store,witness,authority,first));
 const jwt=token(nonce(),{iat:now,auth_time:now,exp:now+300});
 assert.equal((await v.verify(jwt)).issuer,issuer);
 failReads=true;
 await assert.rejects(v.verify(jwt),/witness unavailable/);
 failReads=false;
 await assert.rejects(v.verify(jwt),/witness unavailable/);
});
test('a remote read racing an authorised rotation rejects the request without false rollback latch',async t=>{
 const authority=generateKeyPairSync('ed25519'),secondKey=generateKeyPairSync('rsa',{modulusLength:2048});
 const first=catalogue(authority,1,'fixture',publicKey),next=catalogue(authority,2,'next',secondKey.publicKey);
 const {directory}=await fixture(t,first);
 const base=fakeWitness(first.checkpoint);
 let suspend=false,finish;
 const witness={
  read:async scope=>{
   if(suspend)return new Promise(resolve=>{finish=()=>resolve(base.read(scope));});
   return base.read(scope);
  },
  compareAndSwap:args=>base.compareAndSwap(args)
 };
 const store=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>store.close().catch(()=>{}));
 const v=await openWitnessBoundProviderVerifier(config(store,witness,authority,first));
 suspend=true;
 const pending=v.verify(token(nonce(),{iat:now,auth_time:now,exp:now+300}));
 // Deadline-wrapped I/O dispatches asynchronously; allow the witness read
 // microtask to enter before asserting the deliberately suspended fixture.
 await Promise.resolve();
 assert.equal(typeof finish,'function');
 suspend=false;
 await v.rotate(next.catalogue,next.signature,next.checkpoint);
 finish();
 await assert.rejects(pending,/changed during verification/);
 assert.deepEqual(await store.read(),next.checkpoint);
 const newJwt=token(nonce(),{iat:now,auth_time:now,exp:now+300},{kid:'next'},secondKey.privateKey);
 assert.equal((await v.verify(newJwt)).issuer,issuer);
});

test('a rejected unsigned rotation does not fault the previously trusted witness',async t=>{
 const authority=generateKeyPairSync('ed25519'),first=catalogue(authority,1,'fixture',publicKey);
 const {directory}=await fixture(t,first);
 const witness=fakeWitness(first.checkpoint);
 const store=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>store.close().catch(()=>{}));
 const v=await openWitnessBoundProviderVerifier(config(store,witness,authority,first));
 await assert.rejects(v.rotate(Buffer.from('forged keyset'),Buffer.alloc(64),{sequence:2,digest:'2'.repeat(64)}),/keyset signature denied/);
 assert.deepEqual(witness.inspect(),first.checkpoint);
 const jwt=token(nonce(),{iat:now,auth_time:now,exp:now+300});
 assert.equal((await v.verify(jwt)).issuer,issuer);
});

test('never-settling witness reads time out and permanently fail closed',async t=>{
 const authority=generateKeyPairSync('ed25519'),first=catalogue(authority,1,'fixture',publicKey);
 const {directory}=await fixture(t,first),base=fakeWitness(first.checkpoint);
 let stall=false;
 const witness={
  read:scope=>stall?new Promise(()=>{}):base.read(scope),
  compareAndSwap:args=>base.compareAndSwap(args)
 };
 const store=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>store.close().catch(()=>{}));
 const v=await openWitnessBoundProviderVerifier({...config(store,witness,authority,first),checkpointIoTimeoutMs:40});
 stall=true;
 const jwt=token(nonce(),{iat:now,auth_time:now,exp:now+300});
 await assert.rejects(v.verify(jwt),/witness unavailable/);
 stall=false;
 await assert.rejects(v.verify(jwt),/witness unavailable/);
});
test('limits concurrent checkpoint reads without poisoning a healthy witness',async t=>{
 const authority=generateKeyPairSync('ed25519'),first=catalogue(authority,1,'fixture',publicKey);
 const {directory}=await fixture(t,first),base=fakeWitness(first.checkpoint);
 let blocked=false,release;
 const gate=new Promise(resolve=>{release=resolve;});
 const witness={
  read:scope=>blocked?gate.then(()=>base.read(scope)):base.read(scope),
  compareAndSwap:args=>base.compareAndSwap(args)
 };
 const store=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>store.close().catch(()=>{}));
 const v=await openWitnessBoundProviderVerifier({...config(store,witness,authority,first),
  maxConcurrentCheckpointReads:1,checkpointIoTimeoutMs:2000});
 blocked=true;
 const jwt=token(nonce(),{iat:now,auth_time:now,exp:now+300});
 const pending=v.verify(jwt);
 await assert.rejects(v.verify(jwt),/witness saturated/);
 release();
 assert.equal((await pending).issuer,issuer);
 blocked=false;
 assert.equal((await v.verify(jwt)).issuer,issuer);
});
test('stalled witness CAS denies future verification after rotation deadline',async t=>{
 const authority=generateKeyPairSync('ed25519'),second=generateKeyPairSync('rsa',{modulusLength:2048});
 const first=catalogue(authority,1,'fixture',publicKey),next=catalogue(authority,2,'next',second.publicKey);
 const {directory}=await fixture(t,first),base=fakeWitness(first.checkpoint);
 const witness={
  read:scope=>base.read(scope),
  compareAndSwap:()=>new Promise(()=>{})
 };
 const store=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>store.close().catch(()=>{}));
 const v=await openWitnessBoundProviderVerifier({...config(store,witness,authority,first),checkpointIoTimeoutMs:40});
 await assert.rejects(v.rotate(next.catalogue,next.signature,next.checkpoint),/update unconfirmed/);
 await assert.rejects(v.verify(token(nonce(),{iat:now,auth_time:now,exp:now+300})),/witness unavailable/);
 assert.deepEqual(await store.read(),first.checkpoint);
 assert.deepEqual(base.inspect(),first.checkpoint);
});
test('witness adapter must meet a finite startup deadline',async t=>{
 const authority=generateKeyPairSync('ed25519'),first=catalogue(authority,1,'fixture',publicKey);
 const {directory}=await fixture(t,first);
 const store=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>store.close().catch(()=>{}));
 const witness={read:()=>new Promise(()=>{}),compareAndSwap:()=>new Promise(()=>{})};
 await assert.rejects(openWitnessBoundProviderVerifier({...config(store,witness,authority,first),
  checkpointIoTimeoutMs:40}),/I\/O deadline exceeded/);
});
