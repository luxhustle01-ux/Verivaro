import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {
 createTrustedRecoveryFloorAuthorityKeySchedule,recoveryFloorAuthorityKeyId
} from '../../src/security/provider-witness-authority-key-schedule.mjs';
import {
 recoveryFloorKeyScheduleDigest,canonicalRecoveryFloorTrustPolicyStatement,
 createUnsignedRecoveryFloorTrustPolicyStatement,createTrustedRecoveryFloorTrustPolicy,
 inspectTrustedRecoveryFloorTrustPolicy,trustedRecoveryFloorTrustPolicyCheckpoint
} from '../../src/security/provider-witness-authority-trust-policy.mjs';
import {
 canonicalRecoveryFloorAuthorityStatement,createUnsignedRecoveryFloorAuthorityStatement,
 verifySignedRecoveryFloorAuthority
} from '../../src/security/provider-witness-recovery-floor-publication.mjs';

const scope={issuer:'https://issuer.example.invalid',audience:'verivaro-internal'};
const now='2026-11-21T04:00:00.000Z',nonce='A'.repeat(43);
const hex=x=>createHash('sha256').update(x).digest('hex');
const key=()=>generateKeyPairSync('ed25519');
function fixtures(){
 const old=key(),next=key(),governance=key(),rogue=key();
 const schedule=createTrustedRecoveryFloorAuthorityKeySchedule({epochs:[
  {firstSerial:0,lastSerial:6,keyId:recoveryFloorAuthorityKeyId(old.publicKey),publicKey:old.publicKey},
  {firstSerial:7,lastSerial:null,keyId:recoveryFloorAuthorityKeyId(next.publicKey),publicKey:next.publicKey}
 ]});
 const minimumFloor={serial:6,headHash:'a'.repeat(64)};
 const signed=(overrides={},signer=governance)=>{
  const statement=createUnsignedRecoveryFloorTrustPolicyStatement({
   ...scope,revision:2,scheduleDigest:recoveryFloorKeyScheduleDigest(schedule),
   minimumFloor,revokedKeyIds:[],
   issuedAt:'2026-11-21T03:00:00.000Z',
   expiresAt:'2026-11-21T05:00:00.000Z',...overrides
  });
  const bytes=canonicalRecoveryFloorTrustPolicyStatement(statement);
  const envelope={statement,signature:sign(null,bytes,signer.privateKey).toString('base64url')};
  const trustedCheckpoint={revision:statement.revision,digest:hex(bytes)};
  return {statement,envelope,trustedCheckpoint};
 };
 const trust=({envelope,trustedCheckpoint}=signed(),extra={})=>
  createTrustedRecoveryFloorTrustPolicy({
   envelope,trustedCheckpoint,trustedGovernanceKey:governance.publicKey,
   trustedAuthorityKeySchedule:schedule,...scope,now,...extra
  });
 const receipt=(serial,headHash,who)=>{
  const statement=createUnsignedRecoveryFloorAuthorityStatement({
   ...scope,serial,headHash,requestNonce:nonce,issuedAt:now,
   expiresAt:'2026-11-21T04:00:10.000Z'
  });
  const signature=sign(null,canonicalRecoveryFloorAuthorityStatement(statement),
   who.privateKey).toString('base64url');
  return {statement,signature};
 };
 const verify=(signedReceipt,policy)=>verifySignedRecoveryFloorAuthority(signedReceipt,{
  ...scope,trustedAuthorityKeySchedule:schedule,
  trustedFloorPolicy:policy,expectedRequestNonce:nonce,now
 });
 return {old,next,governance,rogue,schedule,minimumFloor,signed,trust,receipt,verify};
}
test('separate governance signature and pinned checkpoint bind non-revoked floor receipts',()=>{
 const f=fixtures(),policy=f.trust();
 assert.ok(Object.isFrozen(policy));
 assert.equal(policy.kind,'VERIVARO_G1_VERIFIED_FLOOR_TRUST_POLICY');
 const checkpoint=trustedRecoveryFloorTrustPolicyCheckpoint(policy);
 assert.equal(checkpoint.revision,2);
 assert.equal(checkpoint.digest,f.signed().trustedCheckpoint.digest);
 assert.deepEqual(f.verify(f.receipt(6,f.minimumFloor.headHash,f.old),policy),f.minimumFloor);
 assert.deepEqual(f.verify(f.receipt(7,'b'.repeat(64),f.next),policy),
  {serial:7,headHash:'b'.repeat(64)});
 assert.equal(inspectTrustedRecoveryFloorTrustPolicy(policy,{
  ...scope,trustedAuthorityKeySchedule:f.schedule,now,
  serial:6,headHash:f.minimumFloor.headHash
 }).automaticRecoveryPermitted,false);
 assert.throws(()=>f.verify(f.receipt(5,'c'.repeat(64),f.old),policy),/rejected/);
 assert.throws(()=>f.verify(f.receipt(6,'c'.repeat(64),f.old),policy),/rejected/);
});
test('separate policy revision can revoke a current key without changing floor serial',()=>{
 const f=fixtures(),revoked=f.signed({
  revision:3,revokedKeyIds:[recoveryFloorAuthorityKeyId(f.old.publicKey)]
 });
 const policy=f.trust(revoked);
 assert.equal(policy.revision,3);
 assert.throws(()=>f.verify(f.receipt(6,f.minimumFloor.headHash,f.old),policy),/rejected/);
 assert.deepEqual(f.verify(f.receipt(7,'b'.repeat(64),f.next),policy),
  {serial:7,headHash:'b'.repeat(64)});
 assert.throws(()=>f.verify(f.receipt(7,'b'.repeat(64),f.old),policy),/rejected/);
});
test('rejected governance signature, checkpoint rollback, future policy and expiry cannot become trusted',()=>{
 const f=fixtures(),signed=f.signed();
 const altered={statement:{...signed.statement,revision:3},signature:signed.envelope.signature};
 for(const [input,extra] of [
  [{envelope:altered,trustedCheckpoint:signed.trustedCheckpoint},{}],
  [{envelope:f.signed({},f.rogue).envelope,
    trustedCheckpoint:signed.trustedCheckpoint},{}],
  [{...signed,trustedCheckpoint:{revision:1,digest:signed.trustedCheckpoint.digest}},{}],
  [{...signed,trustedCheckpoint:{revision:2,digest:'f'.repeat(64)}},{}],
  [signed,{now:'2026-11-21T05:00:00.000Z'}],
  [signed,{now:'2026-11-21T02:59:59.999Z'}],
  [signed,{trustedGovernanceKey:f.old.publicKey}]
 ]){
  assert.throws(()=>f.trust(input,extra),/rejected/);
 }
 assert.throws(()=>trustedRecoveryFloorTrustPolicyCheckpoint({
  kind:'VERIVARO_G1_VERIFIED_FLOOR_TRUST_POLICY',
  revision:2,digest:signed.trustedCheckpoint.digest
 }),/rejected/);
});
test('rejects malformed, unsorted, foreign and unbound revocations',()=>{
 const f=fixtures(),oldId=recoveryFloorAuthorityKeyId(f.old.publicKey),
  nextId=recoveryFloorAuthorityKeyId(f.next.publicKey);
 for(const revokedKeyIds of [
  [oldId,oldId],['0'.repeat(64)],['f'.repeat(64)],
  [oldId,nextId].sort().reverse(),
  ['INVALID']
 ])assert.throws(()=>f.trust(f.signed({revokedKeyIds})),/rejected/);
 const alternative=key();
 const otherSchedule=createTrustedRecoveryFloorAuthorityKeySchedule({epochs:[
  {firstSerial:0,lastSerial:null,keyId:recoveryFloorAuthorityKeyId(alternative.publicKey),
   publicKey:alternative.publicKey}
 ]});
 assert.throws(()=>f.trust(f.signed(),{
  trustedAuthorityKeySchedule:otherSchedule
 }),/rejected/);
 assert.throws(()=>f.verify(f.receipt(6,f.minimumFloor.headHash,f.old),{
  kind:'VERIVARO_G1_VERIFIED_FLOOR_TRUST_POLICY',
  revision:2,digest:f.signed().trustedCheckpoint.digest
 }),/rejected/);
});
