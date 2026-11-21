import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign,randomUUID} from 'node:crypto';
import {createRotatingProviderVerifier} from '../../src/security/provider-key-rotation.mjs';
import {createProviderEventReceiver} from '../../src/security/provider-events.mjs';
import {issuer,audience,publicKey,privateKey,nonce,token,subject} from '../fixtures/provider-fixture.mjs';
test('signed keyset rotation durably advances checkpoint before accepting new keys',async()=>{
 const authority=generateKeyPairSync('ed25519'),replacement=generateKeyPairSync('rsa',{modulusLength:2048});
 let now=1800000000;
 const fixedToken=(challenge,header={},key=privateKey)=>token(challenge,{iat:now,auth_time:now,exp:now+300},header,key);
 function snapshot(sequence,kid,key){
  const catalogue=Buffer.from(JSON.stringify({version:1,issuer,audience,sequence,issuedAt:now,expiresAt:now+600,keys:[{kid,pem:key.export({type:'spki',format:'pem'})}]}));
  return {catalogue,signature:sign(null,catalogue,authority.privateKey),checkpoint:{sequence,digest:createHash('sha256').update(catalogue).digest('hex')}};
 }
 const first=snapshot(1,'fixture',publicKey),second=snapshot(2,'next',replacement.publicKey);
 let durable={...first.checkpoint},writes=0;
 const persistCheckpoint=async(previous,next)=>{
  assert.deepEqual({...previous},durable);
  durable={...next};writes++;
  return {...durable};
 };
 const p=createRotatingProviderVerifier({issuer,audience,requiredAcr:'fixture:mfa',authorityKey:authority.publicKey,...first,now:()=>now,persistCheckpoint});
 assert.equal(p.verify(fixedToken(nonce())).issuer,issuer);
 await assert.rejects(p.rotate(second.catalogue,second.signature,first.checkpoint),/keyset scope or freshness/);
 await assert.rejects(p.rotate(second.catalogue,Buffer.alloc(64),second.checkpoint),/keyset signature denied/);
 assert.equal(writes,0);
 assert.deepEqual(await p.rotate(second.catalogue,second.signature,second.checkpoint),second.checkpoint);
 assert.equal(writes,1);assert.deepEqual(durable,second.checkpoint);
 assert.throws(()=>p.verify(fixedToken(nonce())));
 assert.equal(p.verify(fixedToken(nonce(),{kid:'next'},replacement.privateKey)).issuer,issuer);
 await assert.rejects(p.rotate(first.catalogue,first.signature,first.checkpoint),/rollback/);
 now+=601;assert.throws(()=>p.verify(fixedToken(nonce())));
 const noWriter=createRotatingProviderVerifier({issuer,audience,requiredAcr:'fixture:mfa',authorityKey:authority.publicKey,...first,now:()=>1800000000});
 await assert.rejects(noWriter.rotate(second.catalogue,second.signature,second.checkpoint),/durable checkpoint writer required/);
 assert.equal(noWriter.verify(token(nonce(),{iat:1800000000,auth_time:1800000000,exp:1800000300}),1800000000).issuer,issuer);
});
test('unconfirmed checkpoint persists a fail-closed keyset state; concurrent rotation is blocked',async()=>{
 const authority=generateKeyPairSync('ed25519'),replacement=generateKeyPairSync('rsa',{modulusLength:2048});
 const now=1800000000;
 const snapshot=(sequence,kid,key)=>{
  const catalogue=Buffer.from(JSON.stringify({version:1,issuer,audience,sequence,issuedAt:now,expiresAt:now+600,keys:[{kid,pem:key.export({type:'spki',format:'pem'})}]}));
  return {catalogue,signature:sign(null,catalogue,authority.privateKey),checkpoint:{sequence,digest:createHash('sha256').update(catalogue).digest('hex')}};
 };
 const first=snapshot(1,'fixture',publicKey),second=snapshot(2,'next',replacement.publicKey);
 let finish;
 const verifier=createRotatingProviderVerifier({issuer,audience,requiredAcr:'fixture:mfa',authorityKey:authority.publicKey,...first,now:()=>now,
  persistCheckpoint:()=>new Promise(resolve=>{finish=resolve;})});
 const pending=verifier.rotate(second.catalogue,second.signature,second.checkpoint);
 assert.equal(typeof finish,'function');
 assert.throws(()=>verifier.verify('not-a-token'),/unavailable/);
 await assert.rejects(verifier.rotate(second.catalogue,second.signature,second.checkpoint),/unavailable/);
 finish({...second.checkpoint});
 assert.deepEqual(await pending,second.checkpoint);
 const broken=createRotatingProviderVerifier({issuer,audience,requiredAcr:'fixture:mfa',authorityKey:authority.publicKey,...first,now:()=>now,
  persistCheckpoint:async()=>{throw Error('storage uncertain');}});
 await assert.rejects(broken.rotate(second.catalogue,second.signature,second.checkpoint),/update unconfirmed/);
 assert.throws(()=>broken.verify('not-a-token'),/unavailable/);
 await assert.rejects(broken.rotate(second.catalogue,second.signature,second.checkpoint),/unavailable/);
 const mismatched=createRotatingProviderVerifier({issuer,audience,requiredAcr:'fixture:mfa',authorityKey:authority.publicKey,...first,now:()=>now,
  persistCheckpoint:async()=>first.checkpoint});
 await assert.rejects(mismatched.rotate(second.catalogue,second.signature,second.checkpoint),/update unconfirmed/);
 assert.throws(()=>mismatched.verify('not-a-token'),/unavailable/);
});

test('signed keyset snapshots reject duplicate, escaped, and noncanonical JSON before trust',async()=>{
 const authority=generateKeyPairSync('ed25519'),now=1800000000;
 const base={version:1,issuer,audience,sequence:1,issuedAt:now,expiresAt:now+600,keys:[{kid:'fixture',pem:publicKey.export({type:'spki',format:'pem'})}]};
 const canonical=JSON.stringify(base);
 const signed=raw=>{
  const catalogue=Buffer.from(raw);
  return {catalogue,signature:sign(null,catalogue,authority.privateKey),
   checkpoint:{sequence:1,digest:createHash('sha256').update(catalogue).digest('hex')}};
 };
 const config={issuer,audience,requiredAcr:'fixture:mfa',authorityKey:authority.publicKey,now:()=>now};
 assert.equal(createRotatingProviderVerifier({...config,...signed(canonical)}).verify(token(nonce(),{iat:now,auth_time:now,exp:now+300})).issuer,issuer);
 const bad=[
  canonical.replace('"issuer":','"issuer":"https://shadow.invalid","issuer":'),
  canonical.replace('"issuer":','"\\u0069ssuer":"https://shadow.invalid","issuer":'),
  canonical.replace('"sequence":1','"sequence":1,"sequence":1'),
  ' '+canonical,
  canonical.replace('"version":1','"version":1.0'),
  canonical+' '
 ];
 for(const raw of bad){
  const payload=signed(raw);
  assert.throws(()=>createRotatingProviderVerifier({...config,...payload}),/noncanonical provider keyset/);
 }
 const first=signed(canonical);
 let writes=0;
 const verifier=createRotatingProviderVerifier({...config,...first,persistCheckpoint:async()=>{writes++;throw Error('unexpected write');}});
 const candidate=signed(canonical.replace('"sequence":1','"sequence":2,"sequence":2'));
 await assert.rejects(verifier.rotate(candidate.catalogue,candidate.signature,{sequence:2,digest:candidate.checkpoint.digest}),/noncanonical provider keyset/);
 assert.equal(writes,0);
});

test('signed lifecycle messages reject tampering, stale events, wrong audience and ambiguous payloads',async()=>{
 const kp=generateKeyPairSync('ed25519'),calls=[],now=Math.floor(Date.now()/1000);
 const receive=createProviderEventReceiver({issuer,audience,publicKey:kp.publicKey,db:{apply:async x=>{calls.push(x);return true;}},now:()=>now});
 const event={version:1,iss:issuer,aud:audience,event_id:randomUUID(),sub:subject,kind:'logout',iat:now};
 const encode=x=>Buffer.from(JSON.stringify(x)),sig=x=>sign(null,x,kp.privateKey);
 const b=encode(event);assert.equal(await receive(b,sig(b)),true);
 for(const x of [{...event,iat:now-241},{...event,aud:'other'},{...event,kind:'enable'},{...event,sub:''}]){
  const b=encode(x);await assert.rejects(receive(b,sig(b)));
 }
 const duplicate=Buffer.from(b.toString().replace('"version":1','"version":1,"version":1'));
 await assert.rejects(receive(duplicate,sig(duplicate)));await assert.rejects(receive(b,Buffer.alloc(64)));
 assert.equal(calls.length,1);
});
