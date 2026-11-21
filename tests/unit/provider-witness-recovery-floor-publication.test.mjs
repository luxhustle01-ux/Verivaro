import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {
 encodeReferenceRecoveryApprovalGenesis
} from '../../src/security/provider-witness-recovery-consumption.mjs';
import {
 createTrustedRecoveryFloorAuthorityKeySchedule,recoveryFloorAuthorityKeyId
} from '../../src/security/provider-witness-authority-key-schedule.mjs';
import {
 recoveryFloorKeyScheduleDigest,canonicalRecoveryFloorTrustPolicyStatement,
 createUnsignedRecoveryFloorTrustPolicyStatement,createTrustedRecoveryFloorTrustPolicy,
 trustedRecoveryFloorTrustPolicyCheckpoint
} from '../../src/security/provider-witness-authority-trust-policy.mjs';
import {
 canonicalRecoveryFloorPublicationStatement,
 createUnsignedRecoveryFloorPublicationStatement,
 canonicalRecoveryFloorAuthorityStatement,
 createUnsignedRecoveryFloorAuthorityStatement,
 verifyRecoveryFloorPublication,verifySignedRecoveryFloorAuthority,
 openReferenceRecoveryFloorPublicationGate
} from '../../src/security/provider-witness-recovery-floor-publication.mjs';

const scope={issuer:'https://issuer.example.invalid',audience:'verivaro-internal'};
const now='2026-11-21T04:00:00.000Z';
const testNonce='A'.repeat(43);
const anotherNonce='B'.repeat(42)+'A';
const approvalId='1'.repeat(32),publicationId='2'.repeat(32),evidenceHash='3'.repeat(64);
function lab(){
 const custodians={primary:generateKeyPairSync('ed25519'),
  secondary:generateKeyPairSync('ed25519')};
 const authorityKey=generateKeyPairSync('ed25519');
 const genesis=encodeReferenceRecoveryApprovalGenesis({...scope,serial:6});
 const prior={serial:6,headHash:genesis.headHash};
 const body={version:1,kind:'consume',...scope,serial:7,approvalId,
  evidenceHash,previousHash:genesis.headHash};
 const nextHash=createHash('sha256')
  .update('verivaro-g1-consumed-review-v1\0')
  .update(Buffer.from(JSON.stringify(body))).digest('hex');
 const next={serial:7,headHash:nextHash};
 const consumptionLog=Buffer.concat([genesis.bytes,
  Buffer.from(JSON.stringify({...body,hash:nextHash})+'\n')]);
 function make(overrides={},signKeys=custodians){
  const statement=createUnsignedRecoveryFloorPublicationStatement({
   ...scope,publicationId,previous:prior,next,approvalId,evidenceHash,
   issuedAt:'2026-11-21T03:00:00.000Z',
   expiresAt:'2026-11-21T05:00:00.000Z',...overrides
  });
  const bytes=canonicalRecoveryFloorPublicationStatement(statement);
  return {statement,signatures:[
   {role:'primary',signature:sign(null,bytes,signKeys.primary.privateKey).toString('base64url')},
   {role:'secondary',signature:sign(null,bytes,signKeys.secondary.privateKey).toString('base64url')}
  ]};
 }
 function signedHead(h,requestNonce=testNonce){
  const statement=createUnsignedRecoveryFloorAuthorityStatement({
   ...scope,...h,requestNonce,issuedAt:now,
   expiresAt:'2026-11-21T04:00:10.000Z'
  });
  return {statement,signature:sign(null,canonicalRecoveryFloorAuthorityStatement(statement),
   authorityKey.privateKey).toString('base64url')};
 }
 let remote={...prior},commits=0,dropAck=false,afterCommit,readHook;
 const authority={
  async read(request,{requestNonce}){
   if(readHook)await readHook();
   assert.deepEqual(request,scope);
   return signedHead(remote,requestNonce);
  },
  async compareAndSwap(request){
   if(request.issuer!==scope.issuer||request.audience!==scope.audience||
    request.previous.serial!==remote.serial||
    request.previous.headHash!==remote.headHash)
    throw Error('remote CAS conflict');
   verifyRecoveryFloorPublication(request.publication,{
    ...scope,expectedPrevious:remote,
    trustedCustodianKeys:{
     primary:custodians.primary.publicKey,
     secondary:custodians.secondary.publicKey
    },consumptionLog:request.consumptionLog,now
   });
   commits++;
   remote={...request.publication.statement.next};
   if(afterCommit)await afterCommit();
   if(dropAck)throw Error('lost remote ack');
   return signedHead(remote,request.requestNonce);
  }
 };
 const config=()=>({...scope,trustedFloor:prior,
  trustedAuthorityKey:authorityKey.publicKey,
  trustedCustodianKeys:{
   primary:custodians.primary.publicKey,secondary:custodians.secondary.publicKey
  },authority,clock:()=>new Date(now),ioTimeoutMs:650});
 const check=(envelope=make(),overrides={})=>verifyRecoveryFloorPublication(envelope,{
  ...scope,expectedPrevious:prior,consumptionLog,now,
  trustedCustodianKeys:{primary:custodians.primary.publicKey,
   secondary:custodians.secondary.publicKey},...overrides
 });
 return {prior,next,consumptionLog,custodians,authorityKey,authority,
  make,signedHead,config,check,setDropAck:v=>{dropAck=v;},
  setAfterCommit:v=>{afterCommit=v;},setReadHook:v=>{readHook=v;},
  current:()=>({...remote}),commits:()=>commits};
}
test('both independent custodian signatures verify exact consumed-review ledger',()=>{
 const f=lab(),r=f.check();
 assert.equal(r.decision,'REVIEW_FLOOR_ELIGIBLE_ONLY');
 assert.deepEqual({serial:r.serial,headHash:r.headHash},f.next);
 assert.equal(r.automaticRecoveryPermitted,false);
});
test('wrong or duplicated custodian signatures cannot publish',()=>{
 const f=lab(),e=f.make();
 for(const signatures of [
  [e.signatures[0]],
  [e.signatures[0],e.signatures[0]],
  [...e.signatures].reverse(),
  [{...e.signatures[0],signature:'a'.repeat(86)},e.signatures[1]]
 ])assert.throws(()=>f.check({...e,signatures}),/rejected/);
 assert.throws(()=>f.check(e,{trustedCustodianKeys:{
  primary:f.custodians.primary.publicKey,secondary:f.custodians.primary.publicKey
 }}),/rejected/);
});
test('forked, stale and tampered ledger evidence reject, even with signed publication',()=>{
 const f=lab();
 assert.throws(()=>f.check(f.make(),{consumptionLog:f.consumptionLog.subarray(0,-5)}),/rejected/);
 assert.throws(()=>f.check(f.make(),{expectedPrevious:{serial:6,headHash:'a'.repeat(64)}}),/rejected/);
 assert.throws(()=>f.check(f.make({next:{serial:7,headHash:'b'.repeat(64)}})),/rejected/);
 assert.throws(()=>f.check(f.make({approvalId:'a'.repeat(32)})),/rejected/);
});
test('changed scope, invalid validity and forged authority receipt fail closed',()=>{
 const f=lab();
 assert.throws(()=>f.check(f.make(),{audience:'other'}),/rejected/);
 assert.throws(()=>f.check(f.make(),{now:'2026-11-21T05:00:00.000Z'}),/rejected/);
 assert.throws(()=>f.make({expiresAt:'2026-11-23T04:00:00.000Z'}),/rejected/);
 const receipt=f.signedHead(f.prior);
 const tampered={...receipt,signature:'a'.repeat(86)};
 assert.throws(()=>verifySignedRecoveryFloorAuthority(tampered,{
  ...scope,trustedAuthorityKey:f.authorityKey.publicKey,
  expectedRequestNonce:testNonce,now
 }),/rejected/);
});
test('remote CAS publishes signed floor; fresh audit succeeds but old startup floor fails',async()=>{
 const f=lab(),gate=await openReferenceRecoveryFloorPublicationGate(f.config());
 const result=await gate.publish({publication:f.make(),consumptionLog:f.consumptionLog});
 assert.equal(result.status,'REVIEW_FLOOR_PUBLISHED_ONLY');
 assert.equal(result.automaticRecoveryPermitted,false);
 assert.deepEqual(await gate.audit(),f.next);
 assert.equal(f.commits(),1);
 gate.close();
 await assert.rejects(openReferenceRecoveryFloorPublicationGate(f.config()),/unavailable/);
 const fresh=await openReferenceRecoveryFloorPublicationGate({
  ...f.config(),trustedFloor:f.next
 });
 assert.deepEqual(await fresh.audit(),f.next);
 fresh.close();
});
test('16 competing local publish calls produce exactly one remote publication',async()=>{
 const f=lab(),gate=await openReferenceRecoveryFloorPublicationGate(f.config());
 const args={publication:f.make(),consumptionLog:f.consumptionLog};
 const results=await Promise.allSettled(Array.from({length:16},()=>gate.publish(args)));
 assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
 assert.equal(results.filter(r=>r.status==='rejected').length,15);
 assert.equal(f.commits(),1);
 gate.close();
});
test('two gate instances cannot both promote one externally pinned floor',async()=>{
 const f=lab();
 const first=await openReferenceRecoveryFloorPublicationGate(f.config());
 const second=await openReferenceRecoveryFloorPublicationGate(f.config());
 const args={publication:f.make(),consumptionLog:f.consumptionLog};
 const results=await Promise.allSettled([first.publish(args),second.publish(args)]);
 assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
 assert.equal(results.filter(r=>r.status==='rejected').length,1);
 assert.equal(f.commits(),1);
 await assert.rejects(second.audit(),/unavailable/);
 first.close();second.close();
});
test('lost remote ACK after durable-style mock commit faults without retrying',async()=>{
 const f=lab(),gate=await openReferenceRecoveryFloorPublicationGate(f.config());
 f.setDropAck(true);
 await assert.rejects(gate.publish({
  publication:f.make(),consumptionLog:f.consumptionLog
 }),/unavailable/);
 assert.deepEqual(f.current(),f.next);
 assert.equal(f.commits(),1);
 await assert.rejects(gate.audit(),/unavailable/);
 await assert.rejects(gate.publish({
  publication:f.make(),consumptionLog:f.consumptionLog
 }),/unavailable/);
 assert.equal(f.commits(),1);
 gate.close();
});
test('remote commit completing only after timeout cannot be safely acknowledged',async()=>{
 const f=lab();
 let release,entered;
 const waiting=new Promise(r=>{release=r;});
 const signalled=new Promise(r=>{entered=r;});
 f.setAfterCommit(async()=>{entered();await waiting;});
 const gate=await openReferenceRecoveryFloorPublicationGate({
  ...f.config(),ioTimeoutMs:35
 });
 const pending=gate.publish({publication:f.make(),consumptionLog:f.consumptionLog});
 await signalled;
 await assert.rejects(pending,/unavailable/);
 release();
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(f.commits(),1);
 assert.deepEqual(f.current(),f.next);
 await assert.rejects(gate.audit(),/unavailable/);
 gate.close();
});
test('authority read changing after opening is detected as trust-floor drift',async()=>{
 const f=lab(),gate=await openReferenceRecoveryFloorPublicationGate(f.config());
 f.setReadHook(()=>{throw Error('remote unreachable');});
 await assert.rejects(gate.audit(),/unavailable/);
 f.setReadHook(null);
 await assert.rejects(gate.publish({
  publication:f.make(),consumptionLog:f.consumptionLog
 }),/unavailable/);
 gate.close();
});
test('invalid signed publication rejects safely before remote CAS',async()=>{
 const f=lab(),gate=await openReferenceRecoveryFloorPublicationGate(f.config());
 const invalid=f.make({approvalId:'f'.repeat(32)});
 await assert.rejects(gate.publish({
  publication:invalid,consumptionLog:f.consumptionLog
 }),/rejected/);
 assert.equal(f.commits(),0);
 assert.deepEqual(await gate.audit(),f.prior);
 gate.close();
});


test('signed v2 receipt requires matching nonce and rejects expiry, future time and v1 downgrade',()=>{
 const f=lab(),envelope=f.signedHead(f.prior,testNonce);
 const opts={...scope,trustedAuthorityKey:f.authorityKey.publicKey,
  expectedRequestNonce:testNonce,now};
 assert.deepEqual(verifySignedRecoveryFloorAuthority(envelope,opts),f.prior);
 assert.throws(()=>verifySignedRecoveryFloorAuthority(envelope,{
  ...opts,expectedRequestNonce:anotherNonce
 }),/rejected/);
 assert.throws(()=>verifySignedRecoveryFloorAuthority(envelope,{
  ...opts,now:'2026-11-21T04:00:10.000Z'
 }),/rejected/);
 assert.throws(()=>verifySignedRecoveryFloorAuthority(envelope,{
  ...opts,now:'2026-11-21T03:59:59.999Z'
 }),/rejected/);
 assert.throws(()=>verifySignedRecoveryFloorAuthority(envelope,{
  ...opts,now:'2026-11-21T04:00:09.000Z',maxReceiptAgeMs:8000
 }),/rejected/);
 const v1={statement:{version:1,domain:'verivaro-g1-review-floor-authority-v1',
  ...scope,...f.prior,issuedAt:now},signature:envelope.signature};
 assert.throws(()=>verifySignedRecoveryFloorAuthority(v1,opts),/rejected/);
});

test('a cached authenticated authority read fails against the next fresh random nonce',async()=>{
 const f=lab(),original=f.authority.read.bind(f.authority);
 let cached,reads=0;
 f.authority.read=async(...args)=>{
  reads++;
  if(!cached)cached=await original(...args);
  return cached;
 };
 await assert.rejects(openReferenceRecoveryFloorPublicationGate(f.config()),/unavailable/);
 assert.equal(reads,2);
 assert.equal(f.commits(),0);
});

test('a signed CAS receipt from an older request cannot acknowledge a new commit',async()=>{
 const f=lab(),original=f.authority.compareAndSwap.bind(f.authority);
 f.authority.compareAndSwap=async(...args)=>{
  await original(...args);
  // Authentically signed, but bound to the wrong challenge, so not an ACK.
  return f.signedHead(f.next,testNonce);
 };
 const gate=await openReferenceRecoveryFloorPublicationGate(f.config());
 await assert.rejects(gate.publish({
  publication:f.make(),consumptionLog:f.consumptionLog
 }),/unavailable/);
 assert.deepEqual(f.current(),f.next);
 assert.equal(f.commits(),1);
 await assert.rejects(gate.audit(),/unavailable/);
 gate.close();
});

test('an otherwise valid challenge-bound receipt fails the trusted maximum-age check',async()=>{
 const f=lab(),original=f.authority.read.bind(f.authority);
 let reads=0;
 const authority={...f.authority,read:async(...args)=>{
  const signed=await original(...args);
  reads++;
  return signed;
 }};
 await assert.rejects(openReferenceRecoveryFloorPublicationGate({
  ...f.config(),authority,
  clock:()=>new Date(reads>=1?'2026-11-21T04:00:11.000Z':now)
 }),/unavailable/);
 assert.equal(f.commits(),0);
});


function guardedFloorFixture(f,{revoke=false}={}){
 const governance=generateKeyPairSync('ed25519');
 const schedule=createTrustedRecoveryFloorAuthorityKeySchedule({epochs:[
  {firstSerial:0,lastSerial:null,
   keyId:recoveryFloorAuthorityKeyId(f.authorityKey.publicKey),
   publicKey:f.authorityKey.publicKey}
 ]});
 const statement=createUnsignedRecoveryFloorTrustPolicyStatement({
  ...scope,revision:2,minimumFloor:f.prior,
  scheduleDigest:recoveryFloorKeyScheduleDigest(schedule),
  revokedKeyIds:revoke?[recoveryFloorAuthorityKeyId(f.authorityKey.publicKey)]:[],
  issuedAt:'2026-11-21T03:00:00.000Z',
  expiresAt:'2026-11-21T05:00:00.000Z'
 });
 const bytes=canonicalRecoveryFloorTrustPolicyStatement(statement);
 const policy=createTrustedRecoveryFloorTrustPolicy({
  envelope:{statement,signature:sign(null,bytes,governance.privateKey).toString('base64url')},
  trustedGovernanceKey:governance.publicKey,
  trustedCheckpoint:{revision:2,digest:createHash('sha256').update(bytes).digest('hex')},
  trustedAuthorityKeySchedule:schedule,...scope,now
 });
 let latest=trustedRecoveryFloorTrustPolicyCheckpoint(policy),calls=0;
 const readFloorPolicyCheckpoint=async(request,{signal}={})=>{
  assert.deepEqual(request,scope);
  assert.equal(signal?.aborted,false);
  calls++;
  return {...latest};
 };
 const config=()=>({...f.config(),trustedAuthorityKey:undefined,
  trustedAuthorityKeySchedule:schedule,trustedFloorPolicy:policy,
  readFloorPolicyCheckpoint
 });
 return {config,policy,checkpoint:()=>({...latest}),calls:()=>calls,
  advance:()=>{latest={revision:latest.revision+1,digest:'f'.repeat(64)};}};
}

test('separately pinned floor policy checkpoint is re-read before/after every authority read',async()=>{
 const f=lab(),policy=guardedFloorFixture(f);
 const gate=await openReferenceRecoveryFloorPublicationGate(policy.config());
 assert.deepEqual(await gate.audit(),f.prior);
 assert.ok(policy.calls()>=6);
 policy.advance();
 await assert.rejects(gate.audit(),/unavailable/);
 // A stale policy cannot silently downgrade or recover after the mismatch.
 await assert.rejects(gate.publish({
  publication:f.make(),consumptionLog:f.consumptionLog
 }),/unavailable/);
 assert.equal(f.commits(),0);
 gate.close();
});

test('policy rollback during a successful remote CAS faults without automatic retry',async()=>{
 const f=lab(),policy=guardedFloorFixture(f);
 const gate=await openReferenceRecoveryFloorPublicationGate(policy.config());
 f.setAfterCommit(()=>policy.advance());
 await assert.rejects(gate.publish({
  publication:f.make(),consumptionLog:f.consumptionLog
 }),/unavailable/);
 assert.equal(f.commits(),1);
 assert.deepEqual(f.current(),f.next);
 await assert.rejects(gate.audit(),/unavailable/);
 gate.close();
});

test('revoked authority key at unchanged serial refuses startup despite valid nonce signature',async()=>{
 const f=lab(),policy=guardedFloorFixture(f,{revoke:true});
 await assert.rejects(openReferenceRecoveryFloorPublicationGate(policy.config()),
  /unavailable/);
 assert.equal(f.commits(),0);
});

test('floor trust policy cannot activate without external checkpoint reader and pinned key schedule',async()=>{
 const f=lab(),policy=guardedFloorFixture(f);
 const missing=policy.config();delete missing.readFloorPolicyCheckpoint;
 await assert.rejects(openReferenceRecoveryFloorPublicationGate(missing),/unavailable/);
 const legacy=policy.config();
 legacy.trustedAuthorityKey=f.authorityKey.publicKey;
 await assert.rejects(openReferenceRecoveryFloorPublicationGate(legacy),/unavailable/);
});


test('two separately opened policy-guarded gate instances cannot both win a mock remote CAS',async()=>{
 const f=lab(),policy=guardedFloorFixture(f);
 const first=await openReferenceRecoveryFloorPublicationGate(policy.config());
 const second=await openReferenceRecoveryFloorPublicationGate(policy.config());
 const args={publication:f.make(),consumptionLog:f.consumptionLog};
 const results=await Promise.allSettled([first.publish(args),second.publish(args)]);
 assert.equal(results.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(results.filter(x=>x.status==='rejected').length,1);
 assert.equal(f.commits(),1);
 first.close();second.close();
});
