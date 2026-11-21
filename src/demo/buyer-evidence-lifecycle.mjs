// Reproducible synthetic acquisition demonstration.
// This is NOT a customer workflow, independent review, authenticated release,
// external custody, or evidence of market demand. No real data or I/O.
import {createHash} from 'node:crypto';
import {evaluate,impactedRequirements} from '../../packages/domain/evidence.ts';
import {draftSnapshot,isCurrentSnapshot} from '../../packages/export/snapshot.mjs';
import {createSubmissionPackage} from '../security/submission-package.mjs';
import {verifySubmissionPackage} from '../security/submission-verifier.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const scope=Object.freeze({
 tenantId:'11111111-1111-4111-8111-111111111111',
 projectId:'22222222-2222-4222-8222-222222222222'
});
const submissionId='33333333-3333-4333-8333-333333333333';
const evidenceId='44444444-4444-4444-8444-444444444444';
const quoted=s=>({sourceId:s.id,start:0,end:s.text.length,quote:s.text});
const makeSource=(id,documentId,revision,value,current=true)=>({
 ...scope,id,documentId,revision,text:value,
 scan:'clean',reviewed:true,current
});
function scenario(){
 const contract=makeSource('contract-v1','contract',1,'Required serial: HVAC-001');
 const incorrect=makeSource('certificate-v1','certificate',1,'HVAC-002');
 const corrected=makeSource('certificate-v2','certificate',2,'HVAC-001');
 const requirement={...scope,id:'req-serial',revision:1,approved:true,
  applicability:'applicable',mandatory:true,
  span:quoted(contract),criterion:{kind:'serial',expected:'HVAC-001'}};
 const badEvidence={...scope,id:'proof-v1',requirementId:requirement.id,
  requirementRevision:1,span:quoted(incorrect),kind:'serial',
  value:incorrect.text,review:'approved'};
 const freshEvidence={...scope,id:'proof-v2',requirementId:requirement.id,
  requirementRevision:1,span:quoted(corrected),kind:'serial',
  value:corrected.text,review:'pending'};
 const missing={scope,sources:[contract],requirements:[requirement],evidence:[]};
 const contradictory={scope,sources:[contract,incorrect],requirements:[requirement],
  evidence:[badEvidence]};
 const pending={scope,sources:[contract,{...incorrect,current:false},corrected],
  requirements:[requirement],evidence:[{...badEvidence,review:'rejected'},freshEvidence]};
 const reviewed={...pending,evidence:[{...badEvidence,review:'rejected'},
  {...freshEvidence,review:'approved'}]};
 return [
  {label:'No proof supplied',input:missing},
  {label:'Incorrect serial identified',input:contradictory},
  {label:'Corrected proof awaiting review',input:pending},
  {label:'Corrected proof approved',input:reviewed}
 ];
}
export function createSyntheticBuyerScenario(){
 // Fresh objects, no mutable shared fixture state across simulations.
 return structuredClone(scenario());
}
export function describeSyntheticBuyerLifecycle(stages=createSyntheticBuyerScenario()){
 if(!Array.isArray(stages)||stages.length!==4)throw Error('buyer demo requires four scenarios');
 const history=stages.map((stage,index)=>{
  const result=evaluate(stage.input),snapshot=draftSnapshot(stage.input);
  return Object.freeze({
   step:index+1,label:stage.label,
   ready:result.ready,blockers:result.blockers,
   coverage:result.coverage,
   findings:result.findings.map(x=>({
    requirementId:x.requirementId,status:x.status,
    blocker:x.blocker,reason:x.reason,
    sourceIds:[...x.sourceIds]
   })),
   draftDisposition:JSON.parse(snapshot.json).disposition,
   draftSha256:snapshot.sha256
  });
 });
 if(history[0].findings[0]?.status!=='missing'||
  history[1].findings[0]?.status!=='conflicting'||
  history[2].findings[0]?.status!=='provisional'||
  history[3].findings[0]?.status!=='verified-configured-checks'||
  history.slice(0,3).some(x=>x.ready)||history[3].ready!==true)
  throw Error('buyer demo safety transitions failed');
 const initial=draftSnapshot(stages[0].input);
 if(isCurrentSnapshot(stages[3].input,initial))throw Error('stale draft incorrectly current');
 return Object.freeze({
  stages:history,
  changedRequirements:impactedRequirements(stages[3].input,['certificate-v2']),
  initialDraftStaleAfterCorrection:true
 });
}
export async function assembleSyntheticBuyerHandover(input){
 const assessment=evaluate(input);
 if(!assessment.ready||assessment.blockers!==0||
  assessment.findings.some(x=>x.status!=='verified-configured-checks'))
  throw Error('synthetic handover blocked by unresolved evidence');
 const certificate=input.sources.find(x=>x.documentId==='certificate'&&x.current);
 if(!certificate||certificate.text!=='HVAC-001')throw Error('invalid synthetic certificate');
 const bytes=Buffer.from(certificate.text,'utf8');
 const item={id:evidenceId,bytes:bytes.length,sha256:sha(bytes),
  mediaType:'text/plain; charset=utf-8'};
 const manifest=JSON.stringify({
  version:1,tenantId:scope.tenantId,projectId:scope.projectId,
  summary:{status:'criteria_satisfied'},evidence:[item]
 });
 const manifestSha256=sha(Buffer.from(manifest,'utf8'));
 // This receipt is an explicitly synthetic stand-in. Real authorisation,
 // actor identity, custody and consent are NOT provided by this demo.
 const receipt={submissionId,sha256:manifestSha256,manifest,
  authorization:'internal owner-authorized download only',
  syntheticTestFixture:true};
 // The real package verifier requires a restricted receipt field set;
 // test-only metadata must remain outside the package itself.
 const {syntheticTestFixture:ignored,...fixtureReceipt}=receipt;
 const workflow={readSubmission:async()=>({...fixtureReceipt})};
 const retrieve=async()=>({data:Buffer.from(bytes),sha256:item.sha256,
  mediaType:item.mediaType});
 const build=createSubmissionPackage({workflow,retrieve});
 const archive=await build({
  tenantId:scope.tenantId,projectId:scope.projectId,submissionId,
  sha256:manifestSha256
 },{signal:new AbortController().signal});
 const archiveSha256=sha(archive);
 const verification=verifySubmissionPackage(archive,{
  expectedPackageSha256:archiveSha256,
  expectedManifestSha256:manifestSha256
 });
 if(verification.authenticityVerified!==false||
  verification.integrityVerified!==true||
  verification.evidenceCount!==1)
  throw Error('synthetic package verifier rejected generated handover');
 return Object.freeze({archive,archiveSha256,manifestSha256,
  verification,synthetic:true,independentDigestCustody:false});
}
export async function runSyntheticBuyerDemo(){
 const stages=createSyntheticBuyerScenario();
 const lifecycle=describeSyntheticBuyerLifecycle(stages);
 const handover=await assembleSyntheticBuyerHandover(stages.at(-1).input);
 try{
  return Object.freeze({
   product:'Verivaro',scenario:'Synthetic HVAC certificate discrepancy',
   source:'actual deterministic domain evaluator and package verifier',
   dataClass:'SYNTHETIC_ONLY',
   commercialDemandValidated:false,
   operationalReleaseApproved:false,
   independentIdentityAndCustodyVerified:false,
   lifecycle,
   handover:{
    archiveBytes:handover.archive.length,
    archiveSha256:handover.archiveSha256,
    manifestSha256:handover.manifestSha256,
    integrityVerifiedAgainstSelfHeldDigests:handover.verification.integrityVerified,
    authenticityVerified:handover.verification.authenticityVerified,
    independentlyTrustedDigests:false,
    submissionId:handover.verification.submissionId,
    evidenceCount:handover.verification.evidenceCount,
    description:'Synthetic authorisation stub; NOT a real approved submission'
   }
  });
 }finally{handover.archive.fill(0);}
}
