/* Read-only, dependency-free viewer. Never interpret fixture text as HTML. */
'use strict';
const $=id=>document.getElementById(id);
const el=(tag,cls,value)=>{
 const n=document.createElement(tag);
 if(cls)n.className=cls;
 if(value!==undefined)n.textContent=String(value);
 return n;
};
const place=(id,...nodes)=>$(id).replaceChildren(...nodes);
let payload=null,index=0;
const statuses={
 missing:{label:'MISSING PROOF',style:'blocked'},
 conflicting:{label:'CONFLICTING EVIDENCE',style:'blocked'},
 provisional:{label:'AWAITING REVIEW',style:'pending'},
 'verified-configured-checks':{label:'CONFIGURED CHECKS PASSED',style:'verified'}
};
function metric(label,value){
 const n=el('div','small-metric'),v=el('strong','',value),l=el('span','',label);
 n.append(v,l);return n;
}
function render(){
 const stage=payload.stages[index],stat=statuses[stage.status],final=index===3;
 const nav=$('stageNav');
 [...nav.children].forEach((btn,i)=>{
  btn.setAttribute('aria-current',i===index?'step':'false');
  btn.disabled=false;
 });
 const body=$('stageBody'),pill=el('span','status-pill '+stat.style,stat.label);
 const heading=el('h3','stage-heading',stage.label);
 const reason=el('p','stage-reason',stage.reason);
 const metrics=el('div','detail-pair');
 metrics.append(metric('Mandatory blockers',stage.blockers),metric('Source-linked criterion',stage.requirementId));
 body.replaceChildren(pill,heading,reason,metrics);
 $('stepCounter').textContent=String(index+1)+' / 4';
 $('prevStage').disabled=index===0;
 $('nextStage').disabled=final;
 $('nextStage').textContent=final?'Final stage':'Next stage';
 const sources=stage.sourceExcerpt.map(s=>{
  const n=el('article','source-card'),
   top=el('div','source-head'),name=el('div','source-name',s.document+' · revision '+s.revision),
   state=el('span','source-state',s.current?'Current source':'Superseded source'),
   text=el('span','source-text',s.text),
   provenance=el('p','',s.id+' · '+(s.reviewed?'Reviewed fixture':'Unreviewed'));
  top.append(name,state);n.append(top,text,provenance);return n;
 });
 const evidence=stage.proofStates.map(p=>{
  const n=el('article','source-card'),
   top=el('div','source-head');
  top.append(el('div','source-name','Proof '+p.id),el('span','source-state',p.review.toUpperCase()));
  n.append(top,el('span','source-text',p.value),el('p','',p.sourceId+' · declared test review state'));
  return n;
 });
 place('evidenceList',...sources,...evidence);
 const ready=$('readiness');
 const flag=el('strong','readiness-flag'+(stage.ready?' ready':''),stage.ready?'Checks satisfied':'Not ready');
 const copy=el('p','summary-copy',stage.ready?
  'Configured exact-text check passed after synthetic reviewer approval. No production sign-off.':
  'Mandatory evidence is blocked until the documentary issue is resolved and reviewed.');
 const nums=el('div','readiness-grid');
 for(const [label,value] of [['Blockers',stage.blockers],['Coverage',Math.round(stage.coverage*100)+'%']]){
  const box=el('div');
  box.append(el('strong','',value),el('small','',label));nums.append(box);
 }
 ready.replaceChildren(flag,copy,nums);
 const handover=$('handoverResult');
 if(!final){
  handover.replaceChildren(
   el('p','', 'Unavailable while this synthetic stage has unresolved mandatory proof.'),
   el('p','hash-label','Draft disposition: '+stage.draftDisposition));
 }else{
  const h=payload.handover;
  handover.replaceChildren(
   el('p','integrity','Byte-integrity checked against self-held hashes'),
   el('p','',String(h.evidenceCount)+' synthetic evidence item · '+String(h.byteCount)+' archive bytes'),
   el('p','hash-label','Package SHA-256'),
   el('p','hash',h.archiveSha256),
   el('p','hash-label','Manifest SHA-256'),
   el('p','hash',h.manifestSha256),
   el('p','','Authenticity and independent trust NOT verified.'));
 }
}
function go(next){
 if(!payload||next<0||next>=payload.stages.length)return;
 index=next;render();
}
function validate(v){
 const statusesExpected=['missing','conflicting','provisional','verified-configured-checks'];
 if(!v||v.version!==1||v.dataClass!=='SYNTHETIC_ONLY'||
  v.releaseApproved!==false||v.commercialDemandValidated!==false||
  v.independentCustodyVerified!==false||
  !Array.isArray(v.stages)||v.stages.length!==4||
  !Array.isArray(v.disclaimers)||v.disclaimers.length<3||
  v.handover?.authenticityVerified!==false||
  v.handover?.independentDigestCustody!==false||
  v.handover?.selfHeldHashIntegrity!==true||
  !v.stages.every((s,i)=>s.step===i+1&&s.status===statusesExpected[i]&&
   s.ready===(i===3)&&s.blockers===(i===3?0:1)&&
   Array.isArray(s.sourceExcerpt)&&Array.isArray(s.proofStates)&&
   typeof s.reason==='string'))throw Error('Invalid synthetic fixture');
 return v;
}
async function init(){
 $('prevStage').addEventListener('click',()=>go(index-1));
 $('nextStage').addEventListener('click',()=>go(index+1));
 $('stageNav').addEventListener('click',event=>{
  const btn=event.target.closest('button[data-step]');
  if(btn)go(Number(btn.dataset.step));
 });
 try{
  const response=await fetch('/buyer-demo.json',{cache:'no-store',credentials:'omit'});
  if(!response.ok)throw Error('Local fixture unavailable');
  payload=validate(await response.json());
  const nav=$('stageNav');
  const labels=['Missing','Conflict','Review','Verified'];
  for(let i=0;i<4;i++){
   const btn=el('button','step-btn');btn.type='button';
   btn.dataset.step=String(i);
   btn.setAttribute('aria-label','Stage '+String(i+1)+': '+payload.stages[i].label);
   btn.append(el('span','',i+1),el('span','',labels[i]));
   nav.append(btn);
  }
  place('disclaimers',...payload.disclaimers.map(s=>el('li','',s)));
  $('loadState').textContent='REAL ENGINE · SYNTHETIC DATA';
  render();
 }catch(e){
  $('loadState').textContent='DEMO UNAVAILABLE';
  place('stageBody',el('p','error','Unable to verify the synthetic demonstration. No readiness claim can be shown.'));
  $('nextStage').disabled=true;$('prevStage').disabled=true;
 }
}
document.addEventListener('DOMContentLoaded',init);
