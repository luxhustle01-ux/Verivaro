import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {
 encodeReferenceRecoveryApprovalGenesis
} from '../../src/security/provider-witness-recovery-consumption.mjs';
import {
 recoveryFloorAuthorityKeyId,createTrustedRecoveryFloorAuthorityKeySchedule
} from '../../src/security/provider-witness-authority-key-schedule.mjs';
import {
 recoveryFloorKeyScheduleDigest,
 canonicalRecoveryFloorTrustPolicyStatement,
 createUnsignedRecoveryFloorTrustPolicyStatement,
 createTrustedRecoveryFloorTrustPolicy,
 trustedRecoveryFloorTrustPolicyCheckpoint
} from '../../src/security/provider-witness-authority-trust-policy.mjs';
import {
 createUnsignedRecoveryFloorPublicationStatement,
 canonicalRecoveryFloorPublicationStatement
} from '../../src/security/provider-witness-recovery-floor-publication.mjs';
import {
 createReferenceAtomicRecoveryFloorModel
} from '../../src/security/provider-witness-reference-atomic-floor-model.mjs';

const scope={issuer:'https://issuer.example.invalid',audience:'verivaro-internal'};
const now='2026-11-21T04:00:00.000Z';
const clock=()=>new Date(now);
const approvalId='1'.repeat(32),publicationId='2'.repeat(32),
 evidenceHash='3'.repeat(64);
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const signature=(bytes,privateKey)=>sign(null,bytes,privateKey).toString('base64url');

function lab(){
 const authorityKeys={old:generateKeyPairSync('ed25519'),
  next:generateKeyPairSync('ed25519')};
 const custodians={primary:generateKeyPairSync('ed25519'),
  secondary:generateKeyPairSync('ed25519')};
 const governance=generateKeyPairSync('ed25519'),intruder=generateKeyPairSync('ed25519');
 const schedule=createTrustedRecoveryFloorAuthorityKeySchedule({epochs:[
  {firstSerial:0,lastSerial:6,
   keyId:recoveryFloorAuthorityKeyId(authorityKeys.old.publicKey),
   publicKey:authorityKeys.old.publicKey},
  {firstSerial:7,lastSerial:null,
   keyId:recoveryFloorAuthorityKeyId(authorityKeys.next.publicKey),
   publicKey:authorityKeys.next.publicKey}
 ]});
 const genesis=encodeReferenceRecoveryApprovalGenesis({...scope,serial:6});
 const previous={serial:6,headHash:genesis.headHash};
 const row={version:1,kind:'consume',...scope,serial:7,approvalId,
  evidenceHash,previousHash:previous.headHash};
 const next={serial:7,headHash:createHash('sha256')
  .update('verivaro-g1-consumed-review-v1\0')
  .update(Buffer.from(JSON.stringify(row))).digest('hex')};
 const consumptionLog=Buffer.concat([genesis.bytes,
  Buffer.from(JSON.stringify({...row,hash:next.headHash})+'\n')]);
 const statement=createUnsignedRecoveryFloorPublicationStatement({
  ...scope,publicationId,previous,next,approvalId,evidenceHash,
  issuedAt:'2026-11-21T03:00:00.000Z',expiresAt:'2026-11-21T05:00:00.000Z'
 });
 const bytes=canonicalRecoveryFloorPublicationStatement(statement);
 const publication={statement,signatures:[
  {role:'primary',signature:signature(bytes,custodians.primary.privateKey)},
  {role:'secondary',signature:signature(bytes,custodians.secondary.privateKey)}
 ]};
 const signPolicy=(overrides={},key=governance)=>{
  const statement=createUnsignedRecoveryFloorTrustPolicyStatement({
   ...scope,revision:2,scheduleDigest:recoveryFloorKeyScheduleDigest(schedule),
   minimumFloor:previous,revokedKeyIds:[],
   issuedAt:'2026-11-21T03:00:00.000Z',
   expiresAt:'2026-11-21T05:00:00.000Z',...overrides
  });
  const bytes=canonicalRecoveryFloorTrustPolicyStatement(statement);
  return {envelope:{statement,signature:signature(bytes,key.privateKey)},
   trustedNextCheckpoint:{revision:statement.revision,digest:digest(bytes)}};
 };
 const first=signPolicy();
 const initialPolicy=createTrustedRecoveryFloorTrustPolicy({
  envelope:first.envelope,trustedGovernanceKey:governance.publicKey,
  trustedCheckpoint:first.trustedNextCheckpoint,
  trustedAuthorityKeySchedule:schedule,...scope,now
 });
 const makeModel=()=>createReferenceAtomicRecoveryFloorModel({
  ...scope,initialFloor:previous,initialPolicy,
  trustedAuthorityKeySchedule:schedule,trustedGovernanceKey:governance.publicKey,
  trustedCustodianKeys:{
   primary:custodians.primary.publicKey,
   secondary:custodians.secondary.publicKey
  },clock
 });
 const request=(model,writerEpoch,overrides={})=>({
  writerEpoch,expectedPrevious:previous,
  expectedPolicyCheckpoint:model.snapshot().policyCheckpoint,
  publication,consumptionLog,...overrides
 });
 return {previous,next,publication,consumptionLog,initialPolicy,
  authorityKeys,schedule,governance,intruder,signPolicy,makeModel,request};
}

test('single-process model checks signed ledger, pinned policy and simulated writer fence at one commit',async()=>{
 const f=lab(),m=f.makeModel(),stale=m.acquireSimulatedWriter();
 const current=m.acquireSimulatedWriter();
 assert.ok(current>stale);
 assert.throws(()=>m.publish(f.request(m,stale)),/rejected/);
 assert.deepEqual(m.snapshot().floor,f.previous);
 const request=f.request(m,current);
 const pair=await Promise.allSettled([
  Promise.resolve().then(()=>m.publish(request)),
  Promise.resolve().then(()=>m.publish(request))
 ]);
 assert.equal(pair.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(pair.filter(x=>x.status==='rejected').length,1);
 const state=m.snapshot();
 assert.deepEqual(state.floor,f.next);
 assert.equal(state.publicationCount,1);
 assert.equal(state.automaticRecoveryPermitted,false);
 assert.throws(()=>m.publish(request),/rejected/);
});

test('simulated partition before commit denies and reconnect retains monotonic fence',()=>{
 const f=lab(),m=f.makeModel(),writer=m.acquireSimulatedWriter();
 m.setSimulatedPartition(writer,true);
 assert.throws(()=>m.publish(f.request(m,writer)),/rejected/);
 assert.equal(m.snapshot().publicationCount,0);
 m.setSimulatedPartition(writer,false);
 assert.equal(m.publish(f.request(m,writer)).status,'REFERENCE_REVIEW_FLOOR_COMMITTED_ONLY');
 const second=m.acquireSimulatedWriter();
 assert.throws(()=>m.publish(f.request(m,writer)),/rejected/);
 assert.equal(second,writer+1);
});

test('lost acknowledgement after model commit never rolls back or double commits',()=>{
 const f=lab(),m=f.makeModel(),writer=m.acquireSimulatedWriter();
 const request=f.request(m,writer,{simulateLostAck:true});
 assert.throws(()=>m.publish(request),/acknowledgement lost/);
 assert.deepEqual(m.snapshot().floor,f.next);
 assert.equal(m.snapshot().publicationCount,1);
 assert.throws(()=>m.publish(f.request(m,writer)),/rejected/);
 assert.equal(m.snapshot().publicationCount,1);
});

test('new signed policy can revoke current signer without floor increment; stale requests cannot publish',()=>{
 const f=lab(),m=f.makeModel(),writer=m.acquireSimulatedWriter();
 const stale=f.request(m,writer);
 const candidate=f.signPolicy({revision:3,
  revokedKeyIds:[recoveryFloorAuthorityKeyId(f.authorityKeys.old.publicKey)]});
 const advanced=m.replacePolicy({
  expectedPolicyCheckpoint:stale.expectedPolicyCheckpoint,
  ...candidate
 });
 assert.equal(advanced.revision,3);
 assert.equal(m.snapshot().floor.serial,6);
 assert.equal(m.snapshot().policyUpdateCount,1);
 assert.throws(()=>m.publish(stale),/rejected/);
 assert.throws(()=>m.publish(f.request(m,writer)),/rejected/);
 assert.equal(m.snapshot().publicationCount,0);
});

test('policy update after a valid publish must not accept unknown intermediate or future floor',()=>{
 const f=lab(),m=f.makeModel(),writer=m.acquireSimulatedWriter();
 m.publish(f.request(m,writer));
 const prior=m.snapshot().policyCheckpoint;
 for(const floor of [
  {serial:8,headHash:'f'.repeat(64)},
  {serial:7,headHash:'f'.repeat(64)}
 ]){
  const next=f.signPolicy({revision:3,minimumFloor:floor});
  assert.throws(()=>m.replacePolicy({
   expectedPolicyCheckpoint:prior,...next
  }),/rejected/);
 }
 const legal=f.signPolicy({revision:3,minimumFloor:f.next,
  revokedKeyIds:[recoveryFloorAuthorityKeyId(f.authorityKeys.old.publicKey)]});
 assert.equal(m.replacePolicy({
  expectedPolicyCheckpoint:prior,...legal
 }).revision,3);
 assert.equal(m.snapshot().policyUpdateCount,1);
});

test('governance revocation cannot be rolled back, skipped or signed by untrusted principal',()=>{
 const f=lab(),m=f.makeModel(),checkpoint=m.snapshot().policyCheckpoint;
 const revoked=f.signPolicy({revision:3,
  revokedKeyIds:[recoveryFloorAuthorityKeyId(f.authorityKeys.old.publicKey)]});
 m.replacePolicy({expectedPolicyCheckpoint:checkpoint,...revoked});
 const trusted=m.snapshot().policyCheckpoint;
 for(const candidate of [
  f.signPolicy({revision:4,revokedKeyIds:[]}),
  f.signPolicy({revision:5,revokedKeyIds:[
   recoveryFloorAuthorityKeyId(f.authorityKeys.old.publicKey)]}),
  f.signPolicy({revision:4,revokedKeyIds:[
   recoveryFloorAuthorityKeyId(f.authorityKeys.old.publicKey)]},f.intruder),
  f.signPolicy({revision:4,minimumFloor:{serial:5,headHash:'f'.repeat(64)},
   revokedKeyIds:[recoveryFloorAuthorityKeyId(f.authorityKeys.old.publicKey)]})
 ])assert.throws(()=>m.replacePolicy({
  expectedPolicyCheckpoint:trusted,...candidate
 }),/rejected/);
 assert.equal(m.snapshot().policyUpdateCount,1);
 assert.deepEqual(m.snapshot().policyCheckpoint,trusted);
});

test('authority-side model rejects forged custodian signature, stale checkpoint and invalid writer token',()=>{
 const f=lab(),m=f.makeModel(),writer=m.acquireSimulatedWriter(),
  good=f.request(m,writer);
 assert.throws(()=>m.publish({...good,writerEpoch:0}),/rejected/);
 assert.throws(()=>m.publish({...good,expectedPolicyCheckpoint:{
  revision:0,digest:'f'.repeat(64)
 }}),/rejected/);
 const bad={...good.publication,signatures:[
  {role:'primary',signature:'a'.repeat(86)},good.publication.signatures[1]
 ]};
 assert.throws(()=>m.publish({...good,publication:bad}),/rejected/);
 assert.equal(m.snapshot().publicationCount,0);
});
