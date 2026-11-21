import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:https';
import {execFileSync} from 'node:child_process';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {issuer,audience,nonce,token,privateKey,publicKey} from '../fixtures/provider-fixture.mjs';
import {openFileProviderCheckpointStore} from '../../src/security/provider-checkpoint-store.mjs';
import {openWitnessBoundProviderVerifier} from '../../src/security/provider-checkpoint-witness.mjs';
import {createHttpsProviderCheckpointWitness} from '../../src/security/provider-checkpoint-https-witness.mjs';

const now=1800000000;
const scope={issuer,audience};
const record=c=>JSON.stringify({version:1,issuer,audience,sequence:c.sequence,digest:c.digest})+'\n';
function keyset(authority,sequence,kid,key){
 const bytes=Buffer.from(JSON.stringify({version:1,issuer,audience,sequence,issuedAt:now,
  expiresAt:now+600,keys:[{kid,pem:key.export({type:'spki',format:'pem'})}]}));
 return {bytes,signature:sign(null,bytes,authority.privateKey),
  checkpoint:{sequence,digest:createHash('sha256').update(bytes).digest('hex')}};
}
const response=c=>JSON.stringify({version:1,issuer,audience,checkpoint:c,
 consistency:'linearizable',durability:'committed'});
const jwt1=()=>token(nonce(),{iat:now,auth_time:now,exp:now+300});
function jwt2(key){
 return token(nonce(),{iat:now,auth_time:now,exp:now+300},{kid:'second'},key);
}
async function lab(t){
 const dir=await mkdtemp(join(tmpdir(),'vv-recovery-'));
 t.after(async()=>rm(dir,{recursive:true,force:true}));
 const authority=generateKeyPairSync('ed25519'),secondKey=generateKeyPairSync('rsa',{modulusLength:2048});
 const first=keyset(authority,1,'fixture',publicKey);
 const second=keyset(authority,2,'second',secondKey.publicKey);
 const certificate=join(dir,'test-cert.pem'),keyfile=join(dir,'test-key.pem');
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes',
  '-keyout',keyfile,'-out',certificate,'-subj','/CN=localhost',
  '-addext','subjectAltName=DNS:localhost','-days','1'],{stdio:'ignore'});
 const [caPem,clientKeyPem]=await Promise.all([readFile(certificate),readFile(keyfile)]);
 const checkpointDir=join(dir,'checkpoint');
 const {mkdir}=await import('node:fs/promises');
 await mkdir(checkpointDir,{mode:0o700});
 const checkpointFile=join(checkpointDir,'provider-keyset-checkpoint.json');
 await writeFile(checkpointFile,record(first.checkpoint),{mode:0o600});
 let remote={...first.checkpoint},mode='healthy',calls=0,casCalls=0;
 const server=createServer({key:clientKeyPem,cert:caPem,ca:caPem,
  requestCert:true,rejectUnauthorized:true},async(req,res)=>{
  try{
   let raw='',length=0;
   for await(const chunk of req){length+=chunk.length;if(length>4096)throw Error('large request');raw+=chunk.toString('utf8');}
   const input=JSON.parse(raw);calls++;
   if(!req.socket.authorized||req.method!=='POST'||req.url!=='/v1/provider-checkpoint'||
    input.version!==1||input.issuer!==issuer||input.audience!==audience)throw Error('bad request');
   if(mode==='partition')return; // Deliberately never respond; native timeout must abort socket.
   if(input.operation==='read'){
    const observed=mode==='stale-read'?first.checkpoint:remote;
    res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});
    res.end(response(observed));return;
   }
   if(input.operation!=='compare-and-swap')throw Error('bad operation');
   casCalls++;
   if(mode==='reject-cas'||input.previous.sequence!==remote.sequence||
    input.previous.digest!==remote.digest){
    res.writeHead(409,{'Content-Type':'application/json','Cache-Control':'no-store'});
    res.end('{"error":"conflict"}');return;
   }
   if(input.next.sequence<=remote.sequence)throw Error('non-monotonic');
   remote={...input.next};
   if(mode==='commit-no-ack')return; // A durable remote commit; response lost in the partition.
   res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});
   res.end(response(remote));
  }catch{
   if(!res.headersSent&&!res.destroyed){res.writeHead(400);res.end();}
  }
 });
 await new Promise((resolve,reject)=>{
  server.once('error',reject);
  server.listen(0,'localhost',resolve);
 });
 t.after(async()=>{
  server.closeAllConnections();
  await new Promise(resolve=>server.close(resolve));
 });
 const witness=createHttpsProviderCheckpointWitness({
  endpoint:'https://localhost:'+server.address().port+'/v1/provider-checkpoint',
  issuer,audience,caPem,clientCertPem:caPem,clientKeyPem,
  allowLoopbackForTests:true,requestTimeoutMs:500,maxInFlight:4
 });
 t.after(()=>witness.close());
 async function openStore(){
  const store=await openFileProviderCheckpointStore({directory:checkpointDir,issuer,audience});
  t.after(()=>store.close().catch(()=>{}));return store;
 }
 async function openVerifier(store,keysetSnapshot=first){
  return openWitnessBoundProviderVerifier({
   store,witness,issuer,audience,authorityKey:authority.publicKey,
   requiredAcr:'fixture:mfa',catalogue:keysetSnapshot.bytes,
   signature:keysetSnapshot.signature,now:()=>now,
   checkpointIoTimeoutMs:1600
  });
 }
 return {first,second,secondKey,scope,witness,checkpointFile,
  openStore,openVerifier,remote:()=>({...remote}),setRemote:c=>{remote={...c};},
  setMode:v=>{mode=v;},calls:()=>calls,casCalls:()=>casCalls
 };
}

test('mTLS witnessed rotation persists both checkpoints and retires the old JWT across restart',async t=>{
 const f=await lab(t),store=await f.openStore(),v=await f.openVerifier(store);
 assert.equal((await v.verify(jwt1())).issuer,issuer);
 assert.deepEqual(await v.rotate(f.second.bytes,f.second.signature,f.second.checkpoint),f.second.checkpoint);
 assert.deepEqual(f.remote(),f.second.checkpoint);
 assert.deepEqual(await store.read(),f.second.checkpoint);
 assert.equal((await v.verify(jwt2(f.secondKey.privateKey))).issuer,issuer);
 await assert.rejects(v.verify(jwt1()),/unsupported provider header/);
 await store.close();
 const restarted=await f.openStore(),v2=await f.openVerifier(restarted,f.second);
 assert.equal((await v2.verify(jwt2(f.secondKey.privateKey))).issuer,issuer);
 await assert.rejects(v2.verify(jwt1()),/unsupported provider header/);
});
test('restoring an old local snapshot cannot resurrect a retired provider keyset',async t=>{
 const f=await lab(t),store=await f.openStore(),v=await f.openVerifier(store);
 await v.rotate(f.second.bytes,f.second.signature,f.second.checkpoint);
 await store.close();
 await writeFile(f.checkpointFile,record(f.first.checkpoint));
 const restored=await f.openStore();
 await assert.rejects(f.openVerifier(restored,f.first),/witness disagreement/);
 assert.deepEqual(f.remote(),f.second.checkpoint);
 assert.deepEqual(await restored.read(),f.first.checkpoint);
});
test('partitioned HTTPS read fails closed and a healed network never revives a faulted verifier',async t=>{
 const f=await lab(t),store=await f.openStore(),v=await f.openVerifier(store);
 assert.equal((await v.verify(jwt1())).issuer,issuer);
 f.setMode('partition');
 await assert.rejects(v.verify(jwt1()),/witness unavailable/);
 f.setMode('healthy');
 const before=f.calls();
 await assert.rejects(v.verify(jwt1()),/witness unavailable/);
 assert.equal(f.calls(),before,'faulted verifier must not query recovered transport');
 await store.close();
 const restarted=await f.openStore(),v2=await f.openVerifier(restarted);
 assert.equal((await v2.verify(jwt1())).issuer,issuer);
});
test('remote CAS committed without acknowledgement blocks unsafe local fallback and restart',async t=>{
 const f=await lab(t),store=await f.openStore(),v=await f.openVerifier(store);
 f.setMode('commit-no-ack');
 await assert.rejects(v.rotate(f.second.bytes,f.second.signature,f.second.checkpoint),
  /update unconfirmed/);
 assert.equal(f.casCalls(),1,'ambiguous CAS must never automatically retry');
 assert.deepEqual(f.remote(),f.second.checkpoint,'remote change may be durable despite timeout');
 assert.deepEqual(await store.read(),f.first.checkpoint,'local disk must remain unchanged');
 f.setMode('healthy');
 await assert.rejects(v.verify(jwt1()),/witness unavailable/);
 await store.close();
 const restarted=await f.openStore();
 await assert.rejects(f.openVerifier(restarted,f.first),/witness disagreement/);
});
test('remote CAS acknowledged but local checkpoint write fails: restart requires reconciliation',async t=>{
 const f=await lab(t),store=await f.openStore();
 const failingStore={
  read:args=>store.read(args),isOpen:()=>store.isOpen(),
  bindVerifier:()=>{
   store.bindVerifier();
   return async()=>{throw Error('simulated disk write fault');};
  }
 };
 const v=await f.openVerifier(failingStore);
 await assert.rejects(v.rotate(f.second.bytes,f.second.signature,f.second.checkpoint),
  /update unconfirmed/);
 assert.deepEqual(f.remote(),f.second.checkpoint);
 assert.deepEqual(await store.read(),f.first.checkpoint);
 await assert.rejects(v.verify(jwt1()),/witness unavailable/);
 await store.close();
 const restarted=await f.openStore();
 await assert.rejects(f.openVerifier(restarted,f.first),/witness disagreement/);
});
test('stale witness snapshot or CAS conflict cannot authenticate on divergent trust state',async t=>{
 const f=await lab(t),store=await f.openStore(),v=await f.openVerifier(store);
 f.setMode('reject-cas');
 await assert.rejects(v.rotate(f.second.bytes,f.second.signature,f.second.checkpoint),
  /update unconfirmed/);
 assert.deepEqual(f.remote(),f.first.checkpoint);
 assert.deepEqual(await store.read(),f.first.checkpoint);
 await assert.rejects(v.verify(jwt1()),/witness unavailable/);
 await store.close();
 f.setMode('healthy'); // Clear the injected CAS conflict before supervised restart.
 const recovered=await f.openStore(),v2=await f.openVerifier(recovered);
 await v2.rotate(f.second.bytes,f.second.signature,f.second.checkpoint);
 f.setMode('stale-read');
 await assert.rejects(v2.verify(jwt2(f.secondKey.privateKey)),/witness disagreement/);
 f.setMode('healthy');
 await assert.rejects(v2.verify(jwt2(f.secondKey.privateKey)),/witness unavailable/);
});
