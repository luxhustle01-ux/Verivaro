// Offline G1 recovery REVIEW approval contract; never executes maintenance.
// Approval signatures, reviewer keys, expected ID and consumed serial must be
// governed outside the witness/publisher host. No private keys or registry here.
import {createHash,createPublicKey,verify} from 'node:crypto';

const HEX=/^[0-9a-f]{64}$/;
const IDENT=/^[0-9a-f]{32}$/;
const PENDING=/^\.receipt-[0-9a-f-]{1,64}\.pending$/;
const fail=()=>{throw Error('witness recovery review approval denied');};
const validScope=s=>typeof s==='string'&&s.length>0&&s.length<=512&&
 !/[\x00-\x1f\x7f]/.test(s);
const fields=(o,expected)=>o&&typeof o==='object'&&!Array.isArray(o)&&
 Object.keys(o).sort().join(',')===expected.split(',').sort().join(',');
const validCp=c=>fields(c,'sequence,digest')&&Number.isSafeInteger(c.sequence)&&
 c.sequence>=1&&typeof c.digest==='string'&&HEX.test(c.digest);
const iso=s=>typeof s==='string'&&Number.isFinite(Date.parse(s))&&
 new Date(s).toISOString()===s;
function validHead(h){
 return fields(h,'count,headHash,checkpoint')&&
 Number.isSafeInteger(h.count)&&h.count>=1&&h.count<=8192&&
 typeof h.headHash==='string'&&HEX.test(h.headHash)&&validCp(h.checkpoint);
}
function pendingNames(names){
 return Array.isArray(names)&&names.length<=32&&
 names.every(n=>typeof n==='string'&&PENDING.test(n))&&
 names.every((n,i)=>i===0||names[i-1]<n);
}
function assessmentBytes(assessment,{issuer,audience,trustedFloor}){
 if(!validScope(issuer)||!validScope(audience)||
  !fields(trustedFloor,'count,headHash')||
  !Number.isSafeInteger(trustedFloor.count)||trustedFloor.count<1||
  trustedFloor.count>8192||!HEX.test(trustedFloor.headHash)||
  !assessment||assessment.status!=='MANUAL_REVIEW_REQUIRED'||
  assessment.evidenceConsistentAtInspection!==true||
  assessment.automaticRecoveryPermitted!==false||
  !validHead(assessment.authenticatedHead)||
  !fields(assessment.writerLocks,'journal,publisher')||
  typeof assessment.writerLocks.journal!=='boolean'||
  typeof assessment.writerLocks.publisher!=='boolean'||
  !pendingNames(assessment.pendingPublisherFiles)||
  assessment.authenticatedHead.count!==trustedFloor.count||
  assessment.authenticatedHead.headHash!==trustedFloor.headHash)fail();
 const h=assessment.authenticatedHead;
 return Buffer.from(JSON.stringify({
  domain:'verivaro-g1-recovery-evidence-v1',issuer,audience,
  head:{count:h.count,headHash:h.headHash,
   checkpoint:{sequence:h.checkpoint.sequence,digest:h.checkpoint.digest}},
  writerLocks:{journal:assessment.writerLocks.journal,
   publisher:assessment.writerLocks.publisher},
  pendingPublisherFiles:[...assessment.pendingPublisherFiles]
 }),'utf8');
}
export function recoveryReviewEvidenceHash(assessment,scopeAndFloor){
 return createHash('sha256').update('verivaro-g1-review-evidence-v1\0')
  .update(assessmentBytes(assessment,scopeAndFloor)).digest('hex');
}
function validStatement(s){
 if(!fields(s,'version,domain,operation,issuer,audience,approvalId,serial,evidenceHash,issuedAt,expiresAt')||
  s.version!==1||s.domain!=='verivaro-g1-recovery-review-v1'||
  s.operation!=='REVIEW_ONLY'||!validScope(s.issuer)||!validScope(s.audience)||
  typeof s.approvalId!=='string'||!IDENT.test(s.approvalId)||
  !Number.isSafeInteger(s.serial)||s.serial<1||s.serial>Number.MAX_SAFE_INTEGER-1||
  typeof s.evidenceHash!=='string'||!HEX.test(s.evidenceHash)||
  !iso(s.issuedAt)||!iso(s.expiresAt))fail();
 const duration=Date.parse(s.expiresAt)-Date.parse(s.issuedAt);
 if(duration<=0||duration>24*60*60*1000)fail();
}
export function canonicalRecoveryReviewStatement(statement){
 validStatement(statement);
 return Buffer.from(JSON.stringify({
  version:1,domain:'verivaro-g1-recovery-review-v1',
  operation:'REVIEW_ONLY',issuer:statement.issuer,audience:statement.audience,
  approvalId:statement.approvalId,serial:statement.serial,
  evidenceHash:statement.evidenceHash,
  issuedAt:statement.issuedAt,expiresAt:statement.expiresAt
 }),'utf8');
}
export function createUnsignedRecoveryReviewStatement({
 issuer,audience,approvalId,serial,evidenceHash,issuedAt,expiresAt
}){
 const result={version:1,domain:'verivaro-g1-recovery-review-v1',
  operation:'REVIEW_ONLY',issuer,audience,approvalId,serial,evidenceHash,
  issuedAt,expiresAt};
 canonicalRecoveryReviewStatement(result);
 return Object.freeze(result);
}
function trustedKey(value){
 let key;
 try{key=value?.type==='public'?value:createPublicKey(value);}catch{fail();}
 if(key?.asymmetricKeyType!=='ed25519')fail();
 return key;
}
function signed(signature,bytes,key){
 if(typeof signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(signature))fail();
 const sig=Buffer.from(signature,'base64url');
 if(sig.length!==64||sig.toString('base64url')!==signature||
  !verify(null,bytes,key,sig))fail();
}
// This is a static eligibility check, NOT replay-preventing storage.
// A separately administered system must atomically consume the serial and ID
// before any human-authorised action. Replaying an old externalConsumedSerial
// would otherwise re-validate the exact same approval.
export function verifyRecoveryReviewApproval(envelope,{
 assessment,issuer,audience,trustedFloor,trustedReviewerKeys,
 externalConsumedSerial,expectedApprovalId,now
}={}){
 if(!validScope(issuer)||!validScope(audience)||
  !fields(trustedReviewerKeys,'owner,security')||
  !Number.isSafeInteger(externalConsumedSerial)||
  externalConsumedSerial<0||externalConsumedSerial>=Number.MAX_SAFE_INTEGER-1||
  typeof expectedApprovalId!=='string'||!IDENT.test(expectedApprovalId)||
  !iso(now)||!fields(envelope,'statement,signatures')||
  !Array.isArray(envelope.signatures)||envelope.signatures.length!==2)fail();
 const bytes=canonicalRecoveryReviewStatement(envelope.statement),s=envelope.statement;
 if(s.issuer!==issuer||s.audience!==audience||
  s.approvalId!==expectedApprovalId||
  s.serial!==externalConsumedSerial+1||
  s.evidenceHash!==recoveryReviewEvidenceHash(assessment,{issuer,audience,trustedFloor})||
  Date.parse(now)<Date.parse(s.issuedAt)||
  Date.parse(now)>=Date.parse(s.expiresAt))fail();
 const owner=trustedKey(trustedReviewerKeys.owner);
 const security=trustedKey(trustedReviewerKeys.security);
 const ownerDer=owner.export({type:'spki',format:'der'});
 const securityDer=security.export({type:'spki',format:'der'});
 if(ownerDer.equals(securityDer))fail();
 for(let i=0;i<2;i++){
  const sig=envelope.signatures[i],role=i===0?'owner':'security';
  if(!fields(sig,'role,signature')||sig.role!==role)fail();
  signed(sig.signature,bytes,i===0?owner:security);
 }
 return Object.freeze({
  decision:'EVIDENCE_REVIEW_SIGNATURES_VERIFIED',
  approvalId:s.approvalId,serial:s.serial,evidenceHash:s.evidenceHash,
  reviewerFingerprints:Object.freeze({
   owner:createHash('sha256').update(ownerDer).digest('hex'),
   security:createHash('sha256').update(securityDer).digest('hex')
  }),
  automaticRecoveryPermitted:false,
  manualReconciliationRequired:true
 });
}
