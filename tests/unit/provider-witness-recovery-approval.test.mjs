import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {
 canonicalRecoveryReviewStatement,createUnsignedRecoveryReviewStatement,
 recoveryReviewEvidenceHash,verifyRecoveryReviewApproval
} from '../../src/security/provider-witness-recovery-approval.mjs';

const issuer='https://issuer.example.invalid',audience='verivaro-internal';
const floor={count:2,headHash:'b'.repeat(64)};
const approvalId='1'.repeat(32);
const now='2026-11-21T04:00:00.000Z';
const assessment=Object.freeze({
 status:'MANUAL_REVIEW_REQUIRED',evidenceConsistentAtInspection:true,
 automaticRecoveryPermitted:false,
 authenticatedHead:{count:2,headHash:floor.headHash,
  checkpoint:{sequence:2,digest:'2'.repeat(64)}},
 writerLocks:{journal:true,publisher:true},
 pendingPublisherFiles:['.receipt-01234567.pending']
});
function lab(){
 const keys={owner:generateKeyPairSync('ed25519'),security:generateKeyPairSync('ed25519')};
 const config=(override={})=>({
  assessment,issuer,audience,trustedFloor:floor,
  trustedReviewerKeys:{owner:keys.owner.publicKey,security:keys.security.publicKey},
  externalConsumedSerial:6,expectedApprovalId:approvalId,now,...override
 });
 const make=(overrides={},signKeys=keys)=>{
  const statement=createUnsignedRecoveryReviewStatement({
   issuer,audience,approvalId,serial:7,
   evidenceHash:recoveryReviewEvidenceHash(assessment,{issuer,audience,trustedFloor:floor}),
   issuedAt:'2026-11-21T03:00:00.000Z',
   expiresAt:'2026-11-21T05:00:00.000Z',...overrides
  });
  const bytes=canonicalRecoveryReviewStatement(statement);
  return {statement,signatures:[
   {role:'owner',signature:sign(null,bytes,signKeys.owner.privateKey).toString('base64url')},
   {role:'security',signature:sign(null,bytes,signKeys.security.privateKey).toString('base64url')}
  ]};
 };
 return {keys,config,make};
}
test('two distinct externally pinned signatures authenticate review evidence, not recovery',()=>{
 const f=lab(),approved=verifyRecoveryReviewApproval(f.make(),f.config());
 assert.equal(approved.decision,'EVIDENCE_REVIEW_SIGNATURES_VERIFIED');
 assert.equal(approved.automaticRecoveryPermitted,false);
 assert.equal(approved.manualReconciliationRequired,true);
 assert.equal(approved.serial,7);
 assert.notEqual(approved.reviewerFingerprints.owner,approved.reviewerFingerprints.security);
});
test('replayed approval serial fails after separately retained counter advances',()=>{
 const f=lab(),envelope=f.make();
 assert.equal(verifyRecoveryReviewApproval(envelope,f.config()).serial,7);
 assert.throws(()=>verifyRecoveryReviewApproval(envelope,f.config({externalConsumedSerial:7})),/denied/);
 assert.throws(()=>verifyRecoveryReviewApproval(envelope,f.config({externalConsumedSerial:5})),/denied/);
});
test('same approval with unchanged externally supplied serial is NOT replay safe by itself',()=>{
 const f=lab(),envelope=f.make();
 // Proves the explicit residual risk: no persistent replay register exists here.
 assert.equal(verifyRecoveryReviewApproval(envelope,f.config()).serial,7);
 assert.equal(verifyRecoveryReviewApproval(envelope,f.config()).serial,7);
});
test('missing, duplicated, reversed or role-swapped signatures are rejected',()=>{
 const f=lab(),e=f.make();
 for(const signatures of [
  e.signatures.slice(0,1),
  [e.signatures[0],e.signatures[0]],
  [...e.signatures].reverse(),
  [{...e.signatures[0],role:'security'},e.signatures[1]]
 ])assert.throws(()=>verifyRecoveryReviewApproval({...e,signatures},f.config()),/denied/);
});
test('same Ed25519 key reused as both reviewers is never independent approval',()=>{
 const f=lab(),e=f.make();
 assert.throws(()=>verifyRecoveryReviewApproval(e,f.config({
  trustedReviewerKeys:{owner:f.keys.owner.publicKey,security:f.keys.owner.publicKey}
 })),/denied/);
});
test('forged signature or statement changed after signing is denied',()=>{
 const f=lab(),e=f.make();
 const attacker=lab();
 assert.throws(()=>verifyRecoveryReviewApproval(
  {...e,signatures:[e.signatures[0],attacker.make().signatures[1]]},f.config()
 ),/denied/);
 assert.throws(()=>verifyRecoveryReviewApproval({
  ...e,statement:{...e.statement,serial:8}
 },f.config({externalConsumedSerial:7})),/denied/);
});
test('different expected approval ID, scope or floor rejects otherwise signed statement',()=>{
 const f=lab(),e=f.make();
 assert.throws(()=>verifyRecoveryReviewApproval(e,f.config({expectedApprovalId:'a'.repeat(32)})),/denied/);
 assert.throws(()=>verifyRecoveryReviewApproval(e,f.config({audience:'other'})),/denied/);
 assert.throws(()=>verifyRecoveryReviewApproval(e,f.config({
  trustedFloor:{...floor,headHash:'a'.repeat(64)}
 })),/denied/);
});
test('changes to checkpoint, writer locks and pending receipts invalidate evidence digest',()=>{
 const f=lab(),e=f.make();
 const variants=[
  {...assessment,authenticatedHead:{...assessment.authenticatedHead,
   checkpoint:{...assessment.authenticatedHead.checkpoint,digest:'3'.repeat(64)}}},
  {...assessment,writerLocks:{journal:false,publisher:true}},
  {...assessment,pendingPublisherFiles:[]}
 ];
 for(const changed of variants)assert.throws(()=>verifyRecoveryReviewApproval(
  e,f.config({assessment:changed})
 ),/denied/);
});
test('expired approval, future issue time and overly broad validity window are denied',()=>{
 const f=lab();
 assert.throws(()=>verifyRecoveryReviewApproval(f.make(),f.config({
  now:'2026-11-21T05:00:00.000Z'
 })),/denied/);
 assert.throws(()=>verifyRecoveryReviewApproval(f.make(),f.config({
  now:'2026-11-21T02:59:59.999Z'
 })),/denied/);
 assert.throws(()=>f.make({expiresAt:'2026-11-23T03:00:00.000Z'}),/denied/);
});
test('invalid or auto-authorizing assessment cannot be approved',()=>{
 const f=lab(),e=f.make();
 for(const bad of [
  {...assessment,automaticRecoveryPermitted:true},
  {...assessment,evidenceConsistentAtInspection:false},
  {...assessment,status:'RECOVERY_APPROVED'},
  {...assessment,pendingPublisherFiles:['../escape.pending']},
  {...assessment,pendingPublisherFiles:['.receipt-b.pending','.receipt-a.pending']}
 ])assert.throws(()=>verifyRecoveryReviewApproval(e,f.config({assessment:bad})),/denied/);
});
test('untrusted reviewer key type and malformed base64 signatures reject',()=>{
 const f=lab(),e=f.make();
 assert.throws(()=>verifyRecoveryReviewApproval(e,f.config({
  trustedReviewerKeys:{owner:'invalid key material',security:f.keys.security.publicKey}
 })),/denied/);
 assert.throws(()=>verifyRecoveryReviewApproval({
  ...e,signatures:[{...e.signatures[0],signature:'a'.repeat(86)},e.signatures[1]]
 },f.config()),/denied/);
});
test('unexpected statement fields, serial overflow and malformed timestamps reject',()=>{
 const f=lab(),e=f.make();
 assert.throws(()=>verifyRecoveryReviewApproval({
  ...e,statement:{...e.statement,permissions:['unlink-lock']}
 },f.config()),/denied/);
 assert.throws(()=>f.make({serial:0}),/denied/);
 assert.throws(()=>f.make({issuedAt:'tomorrow'}),/denied/);
});
