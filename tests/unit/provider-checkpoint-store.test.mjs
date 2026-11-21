import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,chmod,symlink,unlink,rm,open} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {openFileProviderCheckpointStore,openFileBackedProviderVerifier} from '../../src/security/provider-checkpoint-store.mjs';
import {issuer,audience,publicKey,privateKey,nonce,token} from '../fixtures/provider-fixture.mjs';
const now=1800000000;
const record=x=>JSON.stringify({version:1,issuer,audience,sequence:x.sequence,digest:x.digest})+'\n';
function snapshot(authority,sequence,kid,key){
 const catalogue=Buffer.from(JSON.stringify({version:1,issuer,audience,sequence,issuedAt:now,expiresAt:now+600,keys:[{kid,pem:key.export({type:'spki',format:'pem'})}]}));
 return {catalogue,signature:sign(null,catalogue,authority.privateKey),checkpoint:{sequence,digest:createHash('sha256').update(catalogue).digest('hex')}};
}
async function seeded(t,first){
 const directory=await mkdtemp(join(tmpdir(),'vv-checkpoint-'));
 t.after(async()=>rm(directory,{recursive:true,force:true}));
 const path=join(directory,'provider-keyset-checkpoint.json');
 const h=await open(path,'wx',0o600);
 try{await h.writeFile(record(first.checkpoint));await h.sync();}finally{await h.close();}
 return {directory,path};
}
test('real disk persistence survives verifier restart and rejects retired keyset',async t=>{
 const authority=generateKeyPairSync('ed25519'),replacement=generateKeyPairSync('rsa',{modulusLength:2048});
 const first=snapshot(authority,1,'fixture',publicKey),second=snapshot(authority,2,'next',replacement.publicKey);
 const {directory}=await seeded(t,first);
 const store=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>store.close().catch(()=>{}));
 const input={store,issuer,audience,requiredAcr:'fixture:mfa',authorityKey:authority.publicKey,now:()=>now};
 const v=await openFileBackedProviderVerifier({...input,catalogue:first.catalogue,signature:first.signature});
 // Two independent in-memory verifiers attached to one disk lease would
 // permit a retired-key verifier to outlive a successful sibling rotation.
 await assert.rejects(openFileBackedProviderVerifier({...input,catalogue:first.catalogue,signature:first.signature}),/already bound/);
 await assert.rejects(store.compareAndSwap(first.checkpoint,{sequence:99,digest:'9'.repeat(64)}),/reserved for bound verifier/);
 assert.deepEqual(await store.read(),first.checkpoint);
 assert.equal(v.verify(token(nonce(),{iat:now,auth_time:now,exp:now+300})).issuer,issuer);
 assert.deepEqual(await v.rotate(second.catalogue,second.signature,second.checkpoint),second.checkpoint);
 assert.deepEqual(await store.read(),second.checkpoint);
 assert.throws(()=>v.verify(token(nonce(),{iat:now,auth_time:now,exp:now+300})),/key|kid|signature|denied|unsupported provider header/i);
 await store.close();
 assert.throws(()=>v.verify('any'),/closed/);
 const restarted=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>restarted.close().catch(()=>{}));
 await assert.rejects(openFileBackedProviderVerifier({store:restarted,issuer,audience,requiredAcr:'fixture:mfa',authorityKey:authority.publicKey,catalogue:first.catalogue,signature:first.signature,now:()=>now}),/keyset scope or freshness/);
 const newVerifier=await openFileBackedProviderVerifier({store:restarted,issuer,audience,requiredAcr:'fixture:mfa',authorityKey:authority.publicKey,catalogue:second.catalogue,signature:second.signature,now:()=>now});
 assert.equal(newVerifier.verify(token(nonce(),{iat:now,auth_time:now,exp:now+300},{kid:'next'},replacement.privateKey)).issuer,issuer);
});

test('parallel verifier creation on one store admits exactly one active owner',async t=>{
 const authority=generateKeyPairSync('ed25519');
 const first=snapshot(authority,1,'fixture',publicKey);
 const {directory}=await seeded(t,first);
 const store=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>store.close().catch(()=>{}));
 const opts={store,issuer,audience,requiredAcr:'fixture:mfa',authorityKey:authority.publicKey,now:()=>now,
  catalogue:first.catalogue,signature:first.signature};
 const attempts=await Promise.allSettled([openFileBackedProviderVerifier(opts),openFileBackedProviderVerifier(opts)]);
 assert.equal(attempts.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(attempts.filter(x=>x.status==='rejected'&&/already bound/.test(x.reason?.message)).length,1);
 const accepted=attempts.find(x=>x.status==='fulfilled').value;
 assert.equal(accepted.verify(token(nonce(),{iat:now,auth_time:now,exp:now+300})).issuer,issuer);
});
test('checkpoint CAS and live lock fail closed across instances',async t=>{
 const authority=generateKeyPairSync('ed25519'),first=snapshot(authority,1,'fixture',publicKey);
 const {directory}=await seeded(t,first);
 const a=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>a.close().catch(()=>{}));
 await assert.rejects(openFileProviderCheckpointStore({directory,issuer,audience}),/EEXIST|file already exists/);
 const second={sequence:2,digest:'2'.repeat(64)},other={sequence:3,digest:'3'.repeat(64)};
 await assert.rejects(a.compareAndSwap(first.checkpoint,first.checkpoint),/advance/);
 assert.deepEqual(await a.compareAndSwap(first.checkpoint,second),second);
 await assert.rejects(a.compareAndSwap(first.checkpoint,other),/conflict/);
 assert.deepEqual(await a.read(),second);
 await a.close();
 const reopened=await openFileProviderCheckpointStore({directory,issuer,audience});
 t.after(()=>reopened.close().catch(()=>{}));
 assert.deepEqual(await reopened.read(),second);
});
test('missing, forged, corrupted and unsafe checkpoint files deny initialization',async t=>{
 const authority=generateKeyPairSync('ed25519'),first=snapshot(authority,1,'fixture',publicKey);
 const {directory,path}=await seeded(t,first),args={directory,issuer,audience},lock=join(directory,'.provider-keyset-instance.lock');
 await chmod(path,0o644);
 await assert.rejects(openFileProviderCheckpointStore(args),/untrusted checkpoint file/);
 // Initialization deliberately leaves a stale lock on failure: operator intervention required.
 assert.equal((await readFile(lock,'utf8')).trim(),'locked');
 await unlink(lock);await chmod(path,0o600);
 await writeFile(path,record(first.checkpoint).replace('"version":1','"version":1,"version":1'));
 await assert.rejects(openFileProviderCheckpointStore(args),/invalid checkpoint record/);
 await unlink(lock);
 await writeFile(path,record(first.checkpoint));
 await unlink(path);
 await symlink(join(directory,'missing'),path);
 await assert.rejects(openFileProviderCheckpointStore(args));
});
