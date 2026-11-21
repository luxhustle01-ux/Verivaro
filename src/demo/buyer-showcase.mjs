// Read-only synthetic buyer presentation payload. No identity, release or network
// authority is asserted. Every decision comes from the actual domain/packager.
import {createSyntheticBuyerScenario,runSyntheticBuyerDemo} from './buyer-evidence-lifecycle.mjs';
const expected=['missing','conflicting','provisional','verified-configured-checks'];
export async function buildBuyerShowcasePayload(){
 const [report,scenario]=await Promise.all([
  runSyntheticBuyerDemo(),Promise.resolve(createSyntheticBuyerScenario())
 ]);
 const stages=report.lifecycle.stages.map((step,i)=>{
  const input=scenario[i].input;
  if(step.findings?.[0]?.status!==expected[i]||step.step!==i+1||
   typeof input.requirements?.[0]?.span?.quote!=='string')
   throw Error('synthetic showcase evaluation drift');
  const finding=step.findings[0];
  const sourceIds=new Set(finding.sourceIds);
  const sourceExcerpt=input.sources.filter(s=>sourceIds.has(s.id)).map(s=>({
   id:s.id,document:s.documentId,revision:s.revision,
   current:s.current,reviewed:s.reviewed,text:s.text
  }));
  const proofStates=input.evidence.map(e=>({
   id:e.id,sourceId:e.span.sourceId,value:e.value,review:e.review
  }));
  return {
   step:i+1,label:step.label,status:finding.status,
   ready:step.ready,blockers:step.blockers,coverage:step.coverage,
   reason:finding.reason,requirementId:finding.requirementId,
   requirementText:input.requirements[0].span.quote,
   sourceExcerpt,proofStates,draftDisposition:step.draftDisposition,
   draftSha256:step.draftSha256
  };
 });
 if(stages.some((s,i)=>s.status!==expected[i]||
  s.ready!==(i===3)||s.blockers!==(i===3?0:1))||
  report.handover.authenticityVerified!==false||
  report.handover.integrityVerifiedAgainstSelfHeldDigests!==true||
  report.commercialDemandValidated!==false)throw Error('synthetic showcase safety invariant failed');
 return Object.freeze({
  version:1,product:'Verivaro',dataClass:'SYNTHETIC_ONLY',
  scenario:'HVAC evidence discrepancy',releaseApproved:false,
  commercialDemandValidated:false,independentCustodyVerified:false,
  handover:{
   archiveSha256:report.handover.archiveSha256,
   manifestSha256:report.handover.manifestSha256,
   evidenceCount:report.handover.evidenceCount,
   byteCount:report.handover.archiveBytes,
   selfHeldHashIntegrity:report.handover.integrityVerifiedAgainstSelfHeldDigests,
   authenticityVerified:false,
   independentDigestCustody:false
  },
  stages,
  disclaimers:[
   'Synthetic data only. No real customer project or recipient.',
   'Ready means configured text checks passed; it is not compliance certification.',
   'The package uses a simulated authorization stub, not a real release.',
   'Hashes were generated and checked by the same process, not independent custody.'
  ]
 });
}
