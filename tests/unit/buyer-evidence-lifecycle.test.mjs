import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {
 createSyntheticBuyerScenario,describeSyntheticBuyerLifecycle,
 assembleSyntheticBuyerHandover,runSyntheticBuyerDemo
} from '../../src/demo/buyer-evidence-lifecycle.mjs';
import {draftSnapshot,isCurrentSnapshot} from '../../packages/export/snapshot.mjs';
import {verifySubmissionPackage} from '../../src/security/submission-verifier.mjs';
import {evaluate} from '../../packages/domain/evidence.ts';

const sha=x=>createHash('sha256').update(x).digest('hex');
test('four actual domain decisions show missing, conflicting, provisional and verified',()=>{
 const stages=createSyntheticBuyerScenario();
 const values=stages.map(x=>evaluate(x.input));
 assert.deepEqual(values.map(v=>v.findings[0].status),[
  'missing','conflicting','provisional','verified-configured-checks'
 ]);
 assert.deepEqual(values.map(v=>v.ready),[false,false,false,true]);
 const report=describeSyntheticBuyerLifecycle(stages);
 assert.deepEqual(report.stages.map(x=>x.blockers),[1,1,1,0]);
 assert.deepEqual(report.changedRequirements,['req-serial']);
 assert.equal(report.initialDraftStaleAfterCorrection,true);
});
test('readiness never inherits an old certificate or pending review',()=>{
 const stages=createSyntheticBuyerScenario();
 const current=stages.at(-1).input;
 const old=draftSnapshot(stages[1].input);
 assert.equal(isCurrentSnapshot(current,old),false);
 const damaged=structuredClone(current);
 damaged.evidence[1].review='pending';
 assert.equal(evaluate(damaged).ready,false);
 const conflicting=structuredClone(current);
 conflicting.evidence[0].review='approved';
 assert.equal(evaluate(conflicting).ready,false);
});
test('blocked and forged-scope stages cannot produce a handover',async()=>{
 const stages=createSyntheticBuyerScenario();
 for(const stage of stages.slice(0,3))
  await assert.rejects(assembleSyntheticBuyerHandover(stage.input),/blocked/);
 const changed=structuredClone(stages.at(-1).input);
 changed.sources[2].projectId='different-project';
 await assert.rejects(assembleSyntheticBuyerHandover(changed),/scope mismatch/);
});
test('genuine packager and verifier agree on self-held synthetic hashes, not authenticity',async()=>{
 const stages=createSyntheticBuyerScenario();
 const built=await assembleSyntheticBuyerHandover(stages.at(-1).input);
 try{
  assert.equal(built.synthetic,true);
  assert.equal(built.independentDigestCustody,false);
  assert.equal(built.verification.integrityVerified,true);
  assert.equal(built.verification.authenticityVerified,false);
  assert.equal(built.verification.evidenceCount,1);
  assert.equal(built.archiveSha256,sha(built.archive));
  assert.deepEqual(verifySubmissionPackage(built.archive,{
   expectedPackageSha256:built.archiveSha256,
   expectedManifestSha256:built.manifestSha256
  }),built.verification);
 }finally{built.archive.fill(0);}
});
test('modified archive and externally mismatched digest fail independently',async()=>{
 const stages=createSyntheticBuyerScenario();
 const built=await assembleSyntheticBuyerHandover(stages.at(-1).input);
 try{
  const tampered=Buffer.from(built.archive);
  tampered[80]^=0x01;
  assert.throws(()=>verifySubmissionPackage(tampered,{
   expectedPackageSha256:built.archiveSha256,
   expectedManifestSha256:built.manifestSha256
  }),/verification failed/);
  assert.throws(()=>verifySubmissionPackage(built.archive,{
   expectedPackageSha256:'0'.repeat(64),
   expectedManifestSha256:built.manifestSha256
  }),/verification failed/);
 }finally{built.archive.fill(0);}
});
test('buyer demo report is deterministic, self-contained and never claims release or demand',async()=>{
 const x=await runSyntheticBuyerDemo(),y=await runSyntheticBuyerDemo();
 assert.deepEqual(x,y);
 assert.equal(x.dataClass,'SYNTHETIC_ONLY');
 assert.equal(x.commercialDemandValidated,false);
 assert.equal(x.operationalReleaseApproved,false);
 assert.equal(x.independentIdentityAndCustodyVerified,false);
 assert.equal(x.handover.authenticityVerified,false);
 assert.equal(x.handover.independentlyTrustedDigests,false);
 assert.equal(x.handover.integrityVerifiedAgainstSelfHeldDigests,true);
 assert.equal(x.lifecycle.stages.at(-1).ready,true);
});
