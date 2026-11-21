import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {randomUUID,randomBytes,sign,createHash} from 'node:crypto';
import {createSubmissionPackage} from '../../src/security/submission-package.mjs';
import {verifySubmissionPackage} from '../../src/security/submission-verifier.mjs';
import {buildRejectionPreflight} from '../../src/security/rejection-preflight.mjs';
import {compareSubmissionGraph} from '../../src/security/change-impact.mjs';
import {local} from '../fixtures/provider-fixture.mjs';
import {canonicalPagedTextPdf} from '../../src/security/evidence-formats.mjs';
import {officeFixtures} from '../fixtures/office-evidence-fixture.mjs';
import {fixturePng} from '../fixtures/evidence-formats-fixture.mjs';
import {canonicalScannedPdf,readCanonicalScannedPdf} from '../../src/security/scanned-pdf.mjs';
import {canonicalMultipageScannedPdf} from '../../src/security/scanned-pdf-multipage.mjs';
import {createOcrPreview} from '../../src/security/ocr-preview.mjs';
import {createContractIQ} from '../../src/security/contractiq-extraction.mjs';
import {createEvidenceReader} from '../../src/security/evidence-retrieval.mjs';
import {createEvidenceIngestion,createIngestionDatabase} from '../../src/security/evidence-ingestion.mjs';
import {createEvidenceReleaseDatabase,ReleaseDenied,ReleaseConflict} from '../../src/security/evidence-release.mjs';
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_INGEST_PASSWORD)throw Error('disposable CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const cfg={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:4,connectionTimeoutMillis:3000,query_timeout:7000};
const verifier={publicKey:local.publicKey,issuer:'urn:verivaro:graph-fixture',audience:'api'},enc=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
function token(actor,sid){const n=Math.floor(Date.now()/1000),b=enc({alg:'RS256',typ:'JWT'})+'.'+enc({iss:verifier.issuer,aud:verifier.audience,sub:actor,sid,iat:n,nbf:n,exp:n+300});return b+'.'+sign('RSA-SHA256',Buffer.from(b),local.privateKey).toString('base64url');}
test('persistent graph independently reviews exact versions and links; contradictions and stale revisions block completion',{timeout:60000},async()=>{
 const admin=new Pool({...cfg,user:process.env.PGUSER,password:process.env.PGPASSWORD}),runtime=new Pool({...cfg,user:'vv_ci_runtime',password:process.env.VV_RUNTIME_PASSWORD}),ingestPool=new Pool({...cfg,user:'vv_ci_ingest',password:process.env.VV_INGEST_PASSWORD});
 const tenantId=randomUUID(),projectId=randomUUID(),foreignProject=randomUUID(),scope={tenantId,projectId},actors={};
 try{
  await admin.query('INSERT INTO verivaro.tenants(id,name) VALUES($1,$2)',[tenantId,'Graph fixture']);
  for(const p of [projectId,foreignProject])await admin.query('INSERT INTO verivaro.projects(id,tenant_id,name) VALUES($1,$2,$3)',[p,tenantId,'Graph project']);
  for(const [name,role] of [['owner','owner'],['author','contributor'],['reviewer','reviewer'],['reviewer2','reviewer'],['viewer','viewer'],['outsider','viewer']]){
   const a=randomUUID(),sid=randomUUID();
   await admin.query('INSERT INTO verivaro.memberships(tenant_id,actor_id,role) VALUES($1,$2,$3)',[tenantId,a,role]);
   await admin.query('INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role) VALUES($1,$2,$3,$4)',[tenantId,name==='outsider'?foreignProject:projectId,a,role]);
   await admin.query("INSERT INTO verivaro_private.identity_sessions(actor_id,session_id,expires_at) VALUES($1,$2,clock_timestamp()+interval '5 minutes')",[a,sid]);actors[name]={a,token:token(a,sid)};
  }
  await admin.query("INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role) VALUES($1,$2,$3,'contributor')",[tenantId,foreignProject,actors.author.a]);
  const contextKey=(await admin.query('SELECT key_bytes FROM verivaro_private.context_key WHERE singleton')).rows[0].key_bytes;
  const graphKey=randomBytes(32);
  const graph=createEvidenceReleaseDatabase(runtime,{expectedLogin:'vv_ci_runtime',verifier,contextKey,mode:'workflow'}),ingest=createEvidenceIngestion({db:createIngestionDatabase(ingestPool,{expectedLogin:'vv_ci_ingest',verifier,contextKey}),scan:async()=> 'clean',key:graphKey,keyId:'graph-fixture'});
  const as=(who,x={})=>({...scope,token:actors[who].token,...x});
  const status=async()=> (await graph.assessment(as('viewer'))).summary;
  assert.equal((await status()).status,'not_assessed');
  await assert.rejects(graph.assessment(as('outsider')),ReleaseDenied);
  const rule={requirementId:randomUUID(),versionId:randomUUID(),expectedRevision:0,title:'Equipment identifier',criterion:'Serial number must match the approved register.',applicability:'required'};
  await assert.rejects(graph.writeRequirement(as('viewer',rule)),ReleaseDenied);
  const result=await graph.writeRequirement(as('author',rule));assert.deepEqual(await graph.writeRequirement(as('author',rule)),result);
  await assert.rejects(graph.writeRequirement(as('author',{...rule,title:'changed'})),ReleaseConflict);
  assert.equal((await status()).status,'blocked');
  const approve={versionId:rule.versionId,decision:'approved',reason:'Criterion confirmed manually'};
  await assert.rejects(graph.reviewRequirement(as('author',approve)),ReleaseDenied);
  await graph.reviewRequirement(as('reviewer',approve));
  const signal=new AbortController().signal;
  const upload=(text,who='author',p=projectId)=>ingest(as(who,{projectId:p,data:Buffer.from(text),requestId:randomUUID(),signal}));
  const good=await upload('Serial A123'),bad=await upload('Serial B456'),foreign=await upload('Foreign evidence','author',foreignProject),self=await upload('Reviewer supplied evidence','reviewer');
  const link=(e)=>({versionId:rule.versionId,linkId:randomUUID(),evidenceId:e.id,sha256:e.sha256});
  await assert.rejects(graph.linkEvidence(as('author',link(foreign))),ReleaseDenied);
  const first=link(good);await graph.linkEvidence(as('author',first));assert.equal(await graph.linkEvidence(as('author',first)),first.linkId);
  assert.equal((await status()).status,'blocked');
  const pass={linkId:first.linkId,decision:'pass',reason:'Exact identifier matched'};
  await assert.rejects(graph.reviewLink(as('author',pass)),ReleaseDenied);
  await graph.reviewLink(as('reviewer',pass));assert.equal((await status()).status,'criteria_satisfied');
  const ready=buildRejectionPreflight(await graph.assessment(as('viewer')));assert.equal(ready.mandatoryCoveragePercent,100);assert.equal(ready.blockers,0);
  // Simulate storage corruption with trusted admin in disposable CI only;
  // restore exact envelope immediately even when assertion fails.
  const originalEnvelope=(await admin.query('SELECT envelope FROM verivaro_private.evidence_objects WHERE evidence_id=$1',[good.id])).rows[0].envelope;
  const broken=Buffer.from(originalEnvelope);broken[0]^=1;
  await admin.query('ALTER TABLE verivaro_private.evidence_objects DISABLE TRIGGER evidence_object_immutable');
  try{
   await admin.query('UPDATE verivaro_private.evidence_objects SET envelope=$2 WHERE evidence_id=$1',[good.id,broken]);
   const corrupt=await graph.assessment(as('viewer'));assert.equal(corrupt.requirements[0].state,'integrity_failure');assert.equal(corrupt.summary.status,'blocked');
   assert.equal(buildRejectionPreflight(corrupt).issues[0].code,'INTEGRITY_FAILURE');
  }finally{
   try{await admin.query('UPDATE verivaro_private.evidence_objects SET envelope=$2 WHERE evidence_id=$1',[good.id,originalEnvelope]);}finally{await admin.query('ALTER TABLE verivaro_private.evidence_objects ENABLE TRIGGER evidence_object_immutable');}
  }
  assert.equal((await status()).status,'criteria_satisfied');
  const submissionId=randomUUID(),prepared=await graph.prepareSubmission(as('author',{submissionId}));
  assert.deepEqual(await graph.prepareSubmission(as('author',{submissionId})),prepared);
  const submission={submissionId,sha256:prepared.sha256};
  const inspect=await graph.inspectSubmission(as('reviewer',submission));assert.equal(inspect.sha256,prepared.sha256);
  assert.equal(JSON.parse(inspect.manifest).evidence[0].id,good.id);
  const impactScope={tenantId:JSON.parse(inspect.manifest).tenantId,projectId:JSON.parse(inspect.manifest).projectId,submissionId};
  const impact=async()=>compareSubmissionGraph(inspect,await graph.assessment(as('viewer')),impactScope);
  assert.equal((await impact()).changedCount,0);
  await assert.rejects(graph.inspectSubmission(as('outsider',submission)),ReleaseDenied);
  await assert.rejects(graph.authorizeSubmission(as('owner',submission)),ReleaseDenied);
  await assert.rejects(graph.reviewSubmission(as('author',{...submission,decision:'approved',reason:'No self review'})),ReleaseDenied);
  const decision={...submission,decision:'approved',reason:'Reviewed the exact manifest and evidence'};
  assert.equal(await graph.reviewSubmission(as('reviewer',decision)),true);
  assert.equal(await graph.reviewSubmission(as('reviewer',decision)),true);
  assert.equal(await graph.authorizeSubmission(as('owner',submission)),true);
  assert.equal(await graph.authorizeSubmission(as('owner',submission)),true);
  const approvedPackage=await graph.readSubmission(as('owner',submission));assert.equal(approvedPackage.manifest,inspect.manifest);
  await assert.rejects(graph.readSubmission(as('author',submission)),ReleaseDenied);
  assert.equal((await graph.listSubmissions(as('owner')))[0].canDownload,true);
  // Exercise the complete real-DB, encrypted-ingestion to authenticated
  // two-actor review/owner-authorisation to byte-for-byte handover path.
  // The fake browser showcase does NOT substitute for this acceptance gate.
  const handoverReaderPool=new Pool({...cfg,user:'vv_ci_evidence_reader',password:process.env.VV_EVIDENCE_READER_PASSWORD});
  const handoverReader=createEvidenceReader(handoverReaderPool,{
   expectedLogin:'vv_ci_evidence_reader',verifier,contextKey,
   readKey:async keyId=>{assert.equal(keyId,'graph-fixture');return graphKey;}
  });
  const assemble=createSubmissionPackage({workflow:graph,retrieve:handoverReader});
  let handover,second;
  try{
   await assert.rejects(assemble(as('author',submission),{signal}),ReleaseDenied);
   await assert.rejects(assemble(as('owner',{...submission,projectId:foreignProject}),{signal}),ReleaseDenied);
   handover=await assemble(as('owner',submission),{signal});
   const expectedPackageSha256=createHash('sha256').update(handover).digest('hex');
   const verified=verifySubmissionPackage(handover,{
    expectedPackageSha256,expectedManifestSha256:prepared.sha256
   });
   assert.equal(verified.integrityVerified,true);
   assert.equal(verified.authenticityVerified,false);
   assert.equal(verified.evidenceCount,1);
   assert.equal(verified.evidenceBytes,Buffer.byteLength('Serial A123'));
   assert.equal(verified.submissionId,submissionId);
   const tampered=Buffer.from(handover);tampered[52]^=1;
   assert.throws(()=>verifySubmissionPackage(tampered,{
    expectedPackageSha256,expectedManifestSha256:prepared.sha256
   }),/verification failed/);
   tampered.fill(0);
   console.log('real_scoped_handover_package_integrity_gate_passed');
   // Cross-transaction TOCTOU: mutate the approved evidence graph only
   // after the packager has retrieved the real encrypted bytes but before
   // its final readSubmission authorisation check. No stale ZIP may escape.
   let graphMutatedDuringRetrieval=false;
   const racingPackager=createSubmissionPackage({
    workflow:graph,
    retrieve:async input=>{
     const object=await handoverReader(input);
     if(!graphMutatedDuringRetrieval){
      second=link(bad);
      await graph.linkEvidence(as('author',second));
      graphMutatedDuringRetrieval=true;
     }
     return object;
    }
   });
   await assert.rejects(racingPackager(as('owner',submission),{signal}),ReleaseConflict);
   assert.equal(graphMutatedDuringRetrieval,true);
   console.log('concurrent_graph_change_blocks_handover_gate_passed');
   const linkedImpact=await impact();assert.equal(linkedImpact.changedCount,1);assert.ok(linkedImpact.changes[0].reasons.includes('evidence_links_changed'));assert.equal(linkedImpact.currentStatus,'blocked');
   assert.equal((await status()).status,'blocked');
   await assert.rejects(graph.readSubmission(as('owner',submission)),ReleaseConflict);
   await assert.rejects(assemble(as('owner',submission),{signal}),ReleaseConflict);
  }finally{
   handover?.fill(0);
   await handoverReaderPool.end();
  }
  await graph.reviewLink(as('reviewer2',{linkId:second.linkId,decision:'fail',reason:'Conflicting identifier'}));
  const conflicting=await graph.assessment(as('owner'));assert.equal(conflicting.requirements[0].state,'conflict');assert.equal(conflicting.summary.blockers,1);assert.equal(buildRejectionPreflight(conflicting).issues[0].code,'CONFLICTING_EVIDENCE');
  const selfLink=link(self);await graph.linkEvidence(as('author',selfLink));
  await assert.rejects(graph.reviewLink(as('reviewer',{linkId:selfLink.linkId,decision:'pass',reason:'Own upload'})),ReleaseDenied);
  const next={...rule,versionId:randomUUID(),expectedRevision:1,criterion:'Updated register identifier must match.'};
  const competing=await Promise.allSettled([graph.writeRequirement(as('author',next)),graph.writeRequirement(as('author',{...next,versionId:randomUUID()}))]);
  assert.equal(competing.filter(x=>x.status==='fulfilled').length,1);assert.ok(competing.find(x=>x.status==='rejected').reason instanceof ReleaseConflict);
  const nextId=competing.find(x=>x.status==='fulfilled').value.versionId;
  await assert.rejects(graph.reviewRequirement(as('reviewer',approve)),ReleaseConflict);
  const changed=await graph.assessment(as('viewer'));assert.equal(changed.requirements[0].versionId,nextId);assert.deepEqual(changed.requirements[0].links,[]);assert.equal(changed.summary.verifiedRequired,0);
  const revisedImpact=await impact();assert.ok(revisedImpact.changes[0].reasons.includes('criterion_revision_changed'));assert.equal(revisedImpact.changes[0].currentState,'awaiting_rule_review');
  const uncertain={...rule,requirementId:randomUUID(),versionId:randomUUID(),applicability:'unknown'};
  await graph.writeRequirement(as('author',uncertain));await graph.reviewRequirement(as('reviewer',{...approve,versionId:uncertain.versionId}));
  const unknown=await graph.assessment(as('owner'));assert.equal(unknown.summary.blockers,2);assert.ok(unknown.requirements.some(x=>x.state==='unknown_applicability'));
  // Separate ready project for dependency/release regression; no other blockers.
  const dp=randomUUID();await admin.query('INSERT INTO verivaro.projects(id,tenant_id,name) VALUES($1,$2,$3)',[dp,tenantId,'Dependencies']);
  for(const [who,role] of [['owner','owner'],['author','contributor'],['reviewer','reviewer'],['reviewer2','reviewer'],['viewer','viewer']])await admin.query('INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role) VALUES($1,$2,$3,$4)',[tenantId,dp,actors[who].a,role]);
  const da=(who,x={})=>as(who,{projectId:dp,...x}),de=await upload('Dependency evidence','author',dp);
  const mk=()=>({...rule,requirementId:randomUUID(),versionId:randomUUID(),expectedRevision:0});
  const complete=async q=>{await graph.reviewRequirement(da('reviewer',{...approve,versionId:q.versionId}));const l={...link(de),versionId:q.versionId};await graph.linkEvidence(da('author',l));await graph.reviewLink(da('reviewer',{...pass,linkId:l.linkId}));};
  const root=mk(),dependent=mk(),leaf=mk();await graph.writeRequirement(da('author',root));await complete(root);
  const connect=async(q,pr)=>{await graph.writeRequirement(da('author',q));const edge={edgeId:randomUUID(),versionId:q.versionId,prerequisiteId:pr.requirementId};assert.equal(await graph.proposeDependency(da('author',edge)),edge.edgeId);assert.equal(await graph.proposeDependency(da('author',edge)),edge.edgeId);await assert.rejects(graph.reviewDependency(da('author',{...edge,decision:'approved',reason:'Self review'})),ReleaseDenied);await complete(q);const pending=await graph.assessment(da('viewer'));assert.equal(pending.requirements.find(x=>x.requirementId===q.requirementId).state,'dependency_blocked');await graph.reviewDependency(da('reviewer2',{...edge,decision:'approved',reason:'Pinned prerequisite assessed'}));return edge;};
  await connect(dependent,root);await connect(leaf,dependent);
  assert.equal((await graph.assessment(da('viewer'))).summary.status,'criteria_satisfied');
  const ds=await graph.prepareSubmission(da('author',{submissionId:randomUUID()}));await graph.reviewSubmission(da('reviewer',{...ds,decision:'approved',reason:'Dependency package'}));await graph.authorizeSubmission(da('owner',ds));await graph.readSubmission(da('owner',ds));
  const revised={...root,versionId:randomUUID(),expectedRevision:1};await graph.writeRequirement(da('author',revised));await complete(revised);
  const affected=await graph.assessment(da('viewer'));assert.equal(affected.summary.blockers,2);assert.equal(affected.requirements.find(x=>x.requirementId===root.requirementId).state,'satisfied');assert.equal(buildRejectionPreflight(affected).issues.filter(x=>x.code==='DEPENDENCY_BLOCKED').length,2);
  await assert.rejects(graph.readSubmission(da('owner',ds)),ReleaseConflict);await assert.rejects(graph.prepareSubmission(da('author',{submissionId:randomUUID()})),ReleaseConflict);
  const omit={...dependent,versionId:randomUUID(),expectedRevision:1};await graph.writeRequirement(da('author',omit));await assert.rejects(graph.reviewRequirement(da('reviewer',{...approve,versionId:omit.versionId})),ReleaseConflict);
  const candidates=await graph.dependencyRemovalCandidates(da('author'));
  assert.ok(candidates.some(x=>x.versionId===omit.versionId&&x.prerequisiteId===root.requirementId));
  assert.deepEqual(await graph.dependencyRemovalCandidates(da('viewer')),[]);
  const removal={versionId:omit.versionId,removalId:randomUUID(),prerequisiteId:root.requirementId,reason:'Revised criterion no longer depends on root'};
  await assert.rejects(graph.proposeDependencyRemoval(da('viewer',removal)),ReleaseDenied);
  await assert.rejects(graph.proposeDependencyRemoval(da('author',{...removal,prerequisiteId:randomUUID()})),ReleaseDenied);
  assert.equal(await graph.proposeDependencyRemoval(da('author',removal)),removal.removalId);
  assert.equal(await graph.proposeDependencyRemoval(da('author',removal)),removal.removalId);
  await assert.rejects(graph.proposeDependency(da('author',{versionId:omit.versionId,edgeId:randomUUID(),prerequisiteId:root.requirementId})),ReleaseConflict);
  await assert.rejects(graph.reviewRequirement(da('reviewer',{...approve,versionId:omit.versionId})),ReleaseConflict);
  await assert.rejects(graph.reviewDependencyRemoval(da('author',{removalId:removal.removalId,decision:'approved',reason:'Self'})),ReleaseDenied);
  const denial={removalId:removal.removalId,decision:'rejected',reason:'Clarify change'};
  assert.equal(await graph.reviewDependencyRemoval(da('reviewer2',denial)),true);
  await assert.rejects(graph.reviewDependencyRemoval(da('reviewer2',{...denial,decision:'approved'})),ReleaseConflict);
  await assert.rejects(graph.reviewRequirement(da('reviewer',{...approve,versionId:omit.versionId})),ReleaseConflict);
  const corrected={...omit,versionId:randomUUID(),expectedRevision:2,criterion:'Revised independent criterion'};
  await graph.writeRequirement(da('author',corrected));
  const removal2={...removal,versionId:corrected.versionId,removalId:randomUUID()};
  await graph.proposeDependencyRemoval(da('author',removal2));
  const accept={removalId:removal2.removalId,decision:'approved',reason:'Reviewed revised criterion and historical dependency'};
  assert.equal(await graph.reviewDependencyRemoval(da('reviewer2',accept)),true);
  assert.equal(await graph.reviewDependencyRemoval(da('reviewer2',accept)),true);
  await complete(corrected);
  const afterRemoval=await graph.assessment(da('viewer'));
  assert.equal(afterRemoval.requirements.find(x=>x.requirementId===dependent.requirementId).state,'satisfied');
  assert.equal(afterRemoval.requirements.find(x=>x.requirementId===dependent.requirementId).dependencyRemovals[0].decision,'approved');
  assert.equal(afterRemoval.requirements.find(x=>x.requirementId===leaf.requirementId).state,'dependency_blocked');
  await assert.rejects(graph.readSubmission(da('owner',ds)),ReleaseConflict);
  await assert.rejects(admin.query('DELETE FROM verivaro_private.requirement_dependency_removal_reviews WHERE removal_id=$1',[removal2.removalId]),e=>e.code==='42501');
  const newLeaf={...leaf,versionId:randomUUID(),expectedRevision:1};
  await connect(newLeaf,corrected);
  assert.equal((await graph.assessment(da('viewer'))).summary.status,'criteria_satisfied');
  const newSubmission=await graph.prepareSubmission(da('author',{submissionId:randomUUID()}));
  const newManifest=JSON.parse((await graph.inspectSubmission(da('owner',newSubmission))).manifest);
  assert.equal(newManifest.requirements.find(x=>x.requirementId===dependent.requirementId).dependencyRemovals[0].decision,'approved');
  const renewal={...corrected,versionId:randomUUID(),expectedRevision:3};
  await graph.writeRequirement(da('author',renewal));
  await assert.rejects(graph.reviewRequirement(da('reviewer',{...approve,versionId:renewal.versionId})),ReleaseConflict);
  const milestone={milestoneId:randomUUID(),revisionId:randomUUID(),expectedRevision:0,title:'Concealment',confirmed:true,localTime:'2030-11-20T13:00',timezone:'Australia/Melbourne',offsetMinutes:660};
  await assert.rejects(graph.writeMilestone(da('viewer',milestone)),ReleaseDenied);
  await assert.rejects(graph.writeMilestone(da('author',{...milestone,offsetMinutes:600})));
  const savedMilestone=await graph.writeMilestone(da('author',milestone));
  assert.deepEqual(await graph.writeMilestone(da('author',milestone)),savedMilestone);
  await assert.rejects(graph.writeMilestone(da('author',{...milestone,title:'Conflicting'})),ReleaseConflict);
  await assert.rejects(graph.writeMilestone(da('author',{...milestone,revisionId:randomUUID()})),ReleaseConflict);
  const capture={windowId:randomUUID(),versionId:revised.versionId,milestoneId:milestone.milestoneId,leadMinutes:60,irreversibility:'irreversible',reason:'Capture before concealment'};
  await assert.rejects(graph.proposeEvidenceWindow(da('viewer',capture)),ReleaseDenied);
  await assert.rejects(graph.proposeEvidenceWindow(da('author',{...capture,milestoneId:randomUUID()})),ReleaseDenied);
  await assert.rejects(graph.proposeEvidenceWindow(as('author',capture)),ReleaseDenied);
  assert.equal(await graph.proposeEvidenceWindow(da('author',capture)),capture.windowId);
  assert.equal(await graph.proposeEvidenceWindow(da('author',capture)),capture.windowId);
  assert.equal((await graph.proofLock(da('viewer'))).plan.tasks[0].status,'unapproved_rule');
  const wr={windowId:capture.windowId,decision:'approved',reason:'Lead time confirmed independently'};
  await assert.rejects(graph.reviewEvidenceWindow(da('author',wr)),ReleaseDenied);
  assert.equal(await graph.reviewEvidenceWindow(da('reviewer2',wr)),true);
  assert.equal(await graph.reviewEvidenceWindow(da('reviewer2',wr)),true);
  await assert.rejects(graph.reviewEvidenceWindow(da('reviewer2',{...wr,decision:'rejected'})),ReleaseConflict);
  const planned=await graph.proofLock(da('viewer'));
  assert.equal(planned.plan.tasks[0].deadline,'2030-11-20T01:00:00.000Z');
  assert.equal(planned.plan.tasks[0].status,'verified_now');
  assert.equal(planned.windows[0].reviewReason,wr.reason);
  const reschedule={...milestone,revisionId:randomUUID(),expectedRevision:1,localTime:'2030-11-21T13:00'};
  await graph.writeMilestone(da('author',reschedule));
  const rescheduled=await graph.proofLock(da('viewer'));
  assert.equal(rescheduled.plan.tasks[0].deadline,'2030-11-21T01:00:00.000Z');
  assert.equal(rescheduled.plan.tasks[0].history[0].deadline,'2030-11-20T01:00:00.000Z');
  assert.equal(rescheduled.plan.tasks[0].history[0].superseded,true);
  await graph.writeMilestone(da('author',{...reschedule,revisionId:randomUUID(),expectedRevision:2,confirmed:false,localTime:null,offsetMinutes:null}));
  assert.equal((await graph.proofLock(da('viewer'))).plan.tasks[0].status,'unknown_schedule');
  await assert.rejects(graph.proofLock(da('outsider')),ReleaseDenied);
  assert.deepEqual((await graph.proofLock(as('viewer'))).windows,[]);
  for(const table of ['prooflock_milestones','prooflock_windows','prooflock_window_reviews'])await assert.rejects(admin.query('DELETE FROM verivaro_private.'+table+' WHERE false'),e=>e.code==='42501');
  await graph.archiveProject(da('owner',{requestId:randomUUID(),revision:0}));
  await assert.rejects(graph.writeMilestone(da('author',{...milestone,revisionId:randomUUID(),expectedRevision:3})),ReleaseDenied);
  assert.equal((await graph.proofLock(da('viewer'))).assessment.archived,true);
  console.log('persistent_prooflock_scope_schedule_review_history_gate_passed');
  const c=await runtime.connect();try{await c.query('SET ROLE verivaro_runtime');await assert.rejects(c.query('SELECT * FROM verivaro_private.requirement_versions'),e=>e.code==='42501');}finally{c.release(true);}
  for(const table of ['requirement_versions','requirement_reviews','requirement_evidence_links','requirement_link_reviews'])await assert.rejects(admin.query('DELETE FROM verivaro_private.'+table+' WHERE false'),e=>e.code==='42501');
  // Real encrypted retrieval, extraction and persistent page provenance.
  const readerPool=new Pool({...cfg,user:'vv_ci_evidence_reader',password:process.env.VV_EVIDENCE_READER_PASSWORD});
  try{
   const retrieve=createEvidenceReader(readerPool,{expectedLogin:'vv_ci_evidence_reader',verifier,contextKey,readKey:async()=>graphKey});
   const extract=createContractIQ({retrieve,workflow:graph});
   const pdf=canonicalPagedTextPdf([Array(40).fill('Introduction'),['Equipment must carry ID.','Inspection is mandatory.']],{compressed:true});
   const obj=await ingest(as('author',{data:pdf,mediaType:'application/pdf',requestId:randomUUID(),signal}));
   const source=as('author',{evidenceId:obj.id,sha256:obj.sha256});
   const result=await extract(source,{signal});assert.deepEqual(result.candidates.map(c=>[c.line,c.page,c.algorithm]),[[41,2,'modal-line-v1'],[42,2,'obligation-line-v2']]);
   for(const c of result.candidates){
    const args={...source,requirementId:randomUUID(),versionId:randomUUID(),line:c.line,quoteSha256:c.quoteSha256,applicability:'unknown'};
    await extract(args,{signal,importLine:true});
    const saved=(await graph.assessment(as('viewer'))).requirements.find(q=>q.versionId===args.versionId);
    assert.equal(saved.source.page,2);assert.equal(saved.source.line,c.line);assert.equal(saved.source.algorithm,c.algorithm);
    await assert.rejects(graph.importSourceLine({...args,page:1,quote:c.quote,algorithm:c.algorithm}),ReleaseDenied);
   }
   const manual=await extract({...source,manual:true},{signal});
   const c=manual.candidates[0],args={...source,manual:true,requirementId:randomUUID(),versionId:randomUUID(),line:c.line,quoteSha256:c.quoteSha256,applicability:'unknown'};
   await extract(args,{signal,importLine:true});await extract(args,{signal,importLine:true});
   const saved=(await graph.assessment(as('viewer'))).requirements.find(q=>q.versionId===args.versionId);
   assert.equal(saved.ruleDecision,'pending');assert.equal(saved.source.algorithm,'manual-source-line-v1');assert.equal(saved.source.line,1);
   await assert.rejects(extract({...args,versionId:randomUUID(),requirementId:randomUUID()},{signal,importLine:true}),ReleaseConflict);
   await assert.rejects(extract({...source,token:actors.viewer.token},{signal}),ReleaseDenied);
   const auditBefore=await graph.trustproofPage(as('owner',{afterSequence:0,pageSize:256}));
   for(const [mediaType,data] of officeFixtures()){
    const o=await ingest(as('author',{data,mediaType,requestId:randomUUID(),signal}));
    const sc=as('author',{evidenceId:o.id,sha256:o.sha256});
    const recovered=await retrieve(sc);assert.deepEqual(recovered.data,data);recovered.data.fill(0);
    const result=await extract(sc,{signal});assert.equal(result.candidates.length,1);
    const c=result.candidates[0],args={...sc,requirementId:randomUUID(),versionId:randomUUID(),line:c.line,quoteSha256:c.quoteSha256,applicability:'unknown'};
    await assert.rejects(extract({...args,quoteSha256:'0'.repeat(64)},{signal,importLine:true}),ReleaseConflict);
    await extract({...args,location:{forged:true}},{signal,importLine:true});await extract(args,{signal,importLine:true});
    const saved=(await graph.assessment(as('viewer'))).requirements.find(q=>q.versionId===args.versionId);
    assert.deepEqual(saved.source.location,c.location);assert.equal(saved.ruleDecision,'pending');assert.equal(saved.source.algorithm,'office-source-span-v1');
    await assert.rejects(extract({...args,requirementId:randomUUID(),versionId:randomUUID()},{signal,importLine:true}),ReleaseConflict);
    await assert.rejects(graph.importSourceLine({...args,quote:c.quote,algorithm:c.algorithm,location:{forged:true}}),ReleaseDenied);
    await assert.rejects(extract({...sc,token:actors.viewer.token},{signal}),ReleaseDenied);
   }
   const png=fixturePng({width:100,height:60,pixels:Buffer.alloc(60*301)}),image=await ingest(as('author',{data:png,mediaType:'image/png',requestId:randomUUID(),signal}));
   const tsv=()=>Buffer.from('level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n1\t1\t0\t0\t0\t0\t0\t0\t100\t60\t-1\t\n2\t1\t1\t0\t0\t0\t10\t10\t80\t20\t-1\t\n3\t1\t1\t1\t0\t0\t10\t10\t80\t20\t-1\t\n4\t1\t1\t1\t1\t0\t10\t10\t80\t20\t-1\t\n5\t1\t1\t1\t1\t1\t10\t10\t30\t20\t96.25\tInspect\n5\t1\t1\t1\t1\t2\t45\t10\t45\t20\t62.75\tequipment.\n');
   const preview=createOcrPreview({retrieve,assessment:input=>graph.assessment(input),recognize:async()=>tsv(),importSource:input=>graph.importOcrSource(input)});
   const sc=as('author',{evidenceId:image.id,sha256:image.sha256}),out=await preview(sc,{signal}),r=out.regions[0];
   const draft={...sc,requirementId:randomUUID(),versionId:randomUUID(),ordinal:r.ordinal,quoteSha256:r.quoteSha256,regionDigest:r.regionDigest,applicability:'unknown',confirm:true};
   await assert.rejects(preview({...draft,confirm:false},{signal,importRegion:true}),ReleaseDenied);
   await assert.rejects(preview({...draft,regionDigest:'0'.repeat(64)},{signal,importRegion:true}),ReleaseConflict);
   await preview(draft,{signal,importRegion:true});await preview(draft,{signal,importRegion:true});
   const savedOcr=(await graph.assessment(as('viewer'))).requirements.find(q=>q.versionId===draft.versionId);
   assert.equal(savedOcr.ruleDecision,'pending');assert.equal(savedOcr.source.algorithm,'ocr-human-source-v1');assert.deepEqual(savedOcr.source.location.box,r.box);
   const review={versionId:draft.versionId,sha256:image.sha256,quoteSha256:r.quoteSha256,regionDigest:r.regionDigest,reason:'Compared image and text.',confirm:true};
   await assert.rejects(graph.reviewRequirement(as('reviewer2',{versionId:draft.versionId,decision:'approved',reason:'generic bypass'})),ReleaseDenied);
   await assert.rejects(graph.reviewOcrSource(as('author',review)),ReleaseDenied);
   await assert.rejects(graph.reviewOcrSource(as('reviewer2',{...review,regionDigest:'0'.repeat(64)})),ReleaseDenied);
   assert.equal(await graph.reviewOcrSource(as('reviewer2',review)),true);assert.equal(await graph.reviewOcrSource(as('reviewer2',review)),true);
   assert.match((await graph.assessment(as('viewer'))).requirements.find(q=>q.versionId===draft.versionId).ruleReason,/OCR transcription and criterion independently confirmed/);
   const imagePdf=canonicalScannedPdf(png),pdfObj=await ingest(as('author',{data:imagePdf,mediaType:'application/pdf',requestId:randomUUID(),signal}));
   const pdfSource=as('author',{evidenceId:pdfObj.id,sha256:pdfObj.sha256}),decoded=readCanonicalScannedPdf(imagePdf);
   const scanRecognize=createOcrPreview({retrieve,assessment:input=>graph.assessment(input),recognize:async raster=>{assert.deepEqual(raster,decoded.png);return tsv();},importSource:input=>graph.importOcrSource(input)});
   const pdfPreview=await scanRecognize(pdfSource,{signal}),candidate=pdfPreview.regions[0];
   assert.equal(pdfPreview.page,1);assert.equal(pdfPreview.rasterSha256,decoded.rasterSha256);
   const pdfDraft={...pdfSource,requirementId:randomUUID(),versionId:randomUUID(),ordinal:candidate.ordinal,quoteSha256:candidate.quoteSha256,regionDigest:candidate.regionDigest,applicability:'unknown',confirm:true};
   await scanRecognize({...pdfDraft,location:{page:99}},{signal,importRegion:true});
   const savedPdf=(await graph.assessment(as('viewer'))).requirements.find(q=>q.versionId===pdfDraft.versionId);
   assert.equal(savedPdf.source.location.page,1);assert.equal(savedPdf.source.location.rasterSha256,decoded.rasterSha256);
   await assert.rejects(graph.reviewRequirement(as('reviewer2',{versionId:pdfDraft.versionId,decision:'approved',reason:'bypass'})),ReleaseDenied);
   const pdfReview={versionId:pdfDraft.versionId,sha256:pdfObj.sha256,quoteSha256:candidate.quoteSha256,regionDigest:candidate.regionDigest,reason:'Confirmed exact PDF page image and transcription.',confirm:true};
   assert.equal(await graph.reviewOcrSource(as('reviewer2',pdfReview)),true);
   decoded.png.fill(0);
   const secondPixels=Buffer.alloc(60*301);secondPixels[1]=127;
   const multipage=canonicalMultipageScannedPdf([png,fixturePng({width:100,height:60,pixels:secondPixels})]),multiStored=await ingest(as('author',{data:multipage,mediaType:'application/pdf',requestId:randomUUID(),signal}));
   const multiSource=as('author',{evidenceId:multiStored.id,sha256:multiStored.sha256});
   const multiRecognize=createOcrPreview({retrieve,assessment:input=>graph.assessment(input),recognize:async()=>tsv(),importSource:input=>graph.importOcrSource(input)});
   const mp=await multiRecognize({...multiSource,page:2},{signal});
   assert.equal(mp.pageCount,2);assert.equal(mp.page,2);
   const mr=mp.regions[0],ma={...multiSource,page:2,requirementId:randomUUID(),versionId:randomUUID(),ordinal:mr.ordinal,quoteSha256:mr.quoteSha256,regionDigest:mr.regionDigest,applicability:'unknown',confirm:true};
   await assert.rejects(multiRecognize({...ma,page:1},{signal,importRegion:true}),ReleaseConflict);
   await multiRecognize(ma,{signal,importRegion:true});
   const storedMulti=(await graph.assessment(as('viewer'))).requirements.find(q=>q.versionId===ma.versionId);
   assert.equal(storedMulti.source.location.page,2);assert.equal(storedMulti.ruleDecision,'pending');
   const correction={correctionId:randomUUID(),versionId:ma.versionId,sha256:multiStored.sha256,quoteSha256:mr.quoteSha256,regionDigest:mr.regionDigest,expectedRevision:0,correctedText:'Inspect all equipment.',reason:'Original page includes the modifier all.',confirm:true};
   await assert.rejects(graph.proposeOcrCorrection(as('reviewer2',correction)),ReleaseDenied);
   await assert.rejects(graph.proposeOcrCorrection(as('author',{...correction,quoteSha256:'0'.repeat(64)})),ReleaseDenied);
   await graph.proposeOcrCorrection(as('author',correction));await graph.proposeOcrCorrection(as('author',correction));
   const pending=(await graph.assessment(as('author'))).requirements.find(q=>q.versionId===ma.versionId);
   assert.equal(pending.state,'awaiting_correction_review');assert.equal(pending.criterion,'Inspect equipment.');
   assert.equal(pending.source.correction.proposedText,correction.correctedText);assert.equal(pending.canProposeOcrCorrection,false);
   const cf={correctionId:correction.correctionId,decision:'rejected',reason:'Could not verify all from the original image.',confirm:true};
   await assert.rejects(graph.reviewOcrCorrection(as('author',cf)),ReleaseDenied);
   await assert.rejects(graph.reviewOcrSource(as('reviewer2',{versionId:ma.versionId,sha256:multiStored.sha256,quoteSha256:mr.quoteSha256,regionDigest:mr.regionDigest,reason:'Attempted bypass',confirm:true})),ReleaseDenied);
   await assert.rejects(graph.reviewOcrCorrection(as('reviewer2',{...cf,confirm:false})),ReleaseDenied);
   assert.equal(await graph.reviewOcrCorrection(as('reviewer2',cf)),true);
   const rejected=(await graph.assessment(as('author'))).requirements.find(q=>q.versionId===ma.versionId);
   assert.equal(rejected.state,'correction_rejected');assert.equal(rejected.canProposeOcrCorrection,true);
   const replacement={...correction,correctionId:randomUUID(),expectedRevision:1,correctedText:'Inspect equipment carefully.',reason:'Verified final wording on original page.'};
   await graph.proposeOcrCorrection(as('author',replacement));
   const approved={correctionId:replacement.correctionId,decision:'approved',reason:'Checked exact page and pixel region against correction.',confirm:true};
   assert.equal(await graph.reviewOcrCorrection(as('reviewer2',approved)),true);
   assert.equal(await graph.reviewOcrCorrection(as('reviewer2',approved)),true);
   const afterCorrection=(await graph.assessment(as('viewer'))).requirements.find(q=>q.versionId===ma.versionId);
   assert.equal(afterCorrection.criterion,replacement.correctedText);
   assert.equal(afterCorrection.source.correction.originalText,'Inspect equipment.');
   assert.equal(afterCorrection.source.correction.status,'approved');
   const finalReview={versionId:ma.versionId,sha256:multiStored.sha256,quoteSha256:mr.quoteSha256,regionDigest:mr.regionDigest,reason:'Confirmed corrected OCR wording and criterion.',confirm:true};
   assert.equal(await graph.reviewOcrSource(as('reviewer2',finalReview)),true);
   assert.equal((await graph.assessment(as('viewer'))).requirements.find(q=>q.versionId===ma.versionId).ruleDecision,'approved');
   const auditAfter=await graph.trustproofPage(as('owner',{afterSequence:0,pageSize:256}));
   assert.ok(auditAfter.entries.every(e=>e.sourceIntact));assert.deepEqual(auditAfter.entries.slice(0,auditBefore.entries.length),auditBefore.entries);
   await assert.rejects(admin.query('UPDATE verivaro_private.requirement_sources SET office_location=NULL WHERE false'),e=>e.code==='42501');
  }finally{await readerPool.end();}
  await graph.archiveProject(as('owner',{requestId:randomUUID(),revision:0}));
  await assert.rejects(graph.writeRequirement(as('author',{...rule,requirementId:randomUUID(),versionId:randomUUID()})),ReleaseDenied);
  assert.equal((await status()).status,'blocked');
  console.log('persistent_requirement_graph_and_readiness_gate_passed');console.log('rejection_preflight_storage_integrity_gate_passed');console.log('immutable_submission_approval_and_staleness_gate_passed');
 }finally{await Promise.all([admin.end(),runtime.end(),ingestPool.end()]);}
});
