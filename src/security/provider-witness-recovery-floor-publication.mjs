// Reference coordination protocol for independently governed G1 review-floor
// publication. NO actual remote authority, signing custody or fencing service
// is implemented here. Caller must inject an independently authenticated and
// atomic compare-and-swap authority; never treat a local fake as production.
import {createHash,createPublicKey,verify,randomBytes} from 'node:crypto';
import {verifyReferenceRecoveryApprovalLog} from './provider-witness-recovery-consumption.mjs';
import {resolveTrustedRecoveryFloorAuthorityPublicKey} from './provider-witness-authority-key-schedule.mjs';
import {
 inspectTrustedRecoveryFloorTrustPolicy,
 trustedRecoveryFloorTrustPolicyCheckpoint
} from './provider-witness-authority-trust-policy.mjs';

const HEX=/^[a-f0-9]{64}$/;
const IDENT=/^[a-f0-9]{32}$/;
const NONCE=/^[A-Za-z0-9_-]{43}$/;
const validNonce=v=>typeof v==='string'&&NONCE.test(v)&&
 Buffer.from(v,'base64url').length===32&&
 Buffer.from(v,'base64url').toString('base64url')===v;
const freshNonce=()=>randomBytes(32).toString('base64url');
const fail=()=>Error('review floor publication unavailable');
const invalid=()=>Error('review floor publication rejected');
const scopeOk=s=>typeof s==='string'&&s.length>0&&s.length<=512&&!/[\x00-\x1f\x7f]/.test(s);
const keys=(v,s)=>v&&typeof v==='object'&&!Array.isArray(v)&&
 Object.keys(v).sort().join(',')===s.split(',').sort().join(',');
const iso=s=>typeof s==='string'&&Number.isFinite(Date.parse(s))&&
 new Date(s).toISOString()===s;
const validHead=h=>keys(h,'serial,headHash')&&
 Number.isSafeInteger(h.serial)&&h.serial>=0&&
 h.serial<Number.MAX_SAFE_INTEGER-2&&
 typeof h.headHash==='string'&&HEX.test(h.headHash);
const same=(a,b)=>a.serial===b.serial&&a.headHash===b.headHash;
function pubkey(k){
 let v;
 try{v=k?.type==='public'?k:createPublicKey(k);}catch{throw invalid();}
 if(v?.asymmetricKeyType!=='ed25519')throw invalid();
 return v;
}
function signature(sig,bytes,key){
 if(typeof sig!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(sig))throw invalid();
 const raw=Buffer.from(sig,'base64url');
 if(raw.length!==64||raw.toString('base64url')!==sig||
  !verify(null,bytes,key,raw))throw invalid();
}
function statementValid(s){
 if(!keys(s,'version,domain,operation,issuer,audience,publicationId,previous,next,approvalId,evidenceHash,issuedAt,expiresAt')||
  s.version!==1||s.domain!=='verivaro-g1-review-floor-publication-v1'||
  s.operation!=='PUBLISH_REVIEW_ONLY_FLOOR'||!scopeOk(s.issuer)||
  !scopeOk(s.audience)||typeof s.publicationId!=='string'||
  !IDENT.test(s.publicationId)||!validHead(s.previous)||!validHead(s.next)||
  s.next.serial!==s.previous.serial+1||
  typeof s.approvalId!=='string'||!IDENT.test(s.approvalId)||
  typeof s.evidenceHash!=='string'||!HEX.test(s.evidenceHash)||
  !iso(s.issuedAt)||!iso(s.expiresAt)||
  Date.parse(s.expiresAt)<=Date.parse(s.issuedAt)||
  Date.parse(s.expiresAt)-Date.parse(s.issuedAt)>24*60*60*1000)
  throw invalid();
}
export function canonicalRecoveryFloorPublicationStatement(s){
 statementValid(s);
 return Buffer.from(JSON.stringify({
  version:1,domain:'verivaro-g1-review-floor-publication-v1',
  operation:'PUBLISH_REVIEW_ONLY_FLOOR',issuer:s.issuer,audience:s.audience,
  publicationId:s.publicationId,
  previous:{serial:s.previous.serial,headHash:s.previous.headHash},
  next:{serial:s.next.serial,headHash:s.next.headHash},
  approvalId:s.approvalId,evidenceHash:s.evidenceHash,
  issuedAt:s.issuedAt,expiresAt:s.expiresAt
 }),'utf8');
}
export function createUnsignedRecoveryFloorPublicationStatement({
 issuer,audience,publicationId,previous,next,approvalId,evidenceHash,
 issuedAt,expiresAt
}={}){
 const s={version:1,domain:'verivaro-g1-review-floor-publication-v1',
  operation:'PUBLISH_REVIEW_ONLY_FLOOR',issuer,audience,publicationId,
  previous,next,approvalId,evidenceHash,issuedAt,expiresAt};
 canonicalRecoveryFloorPublicationStatement(s);
 return Object.freeze({...s,previous:Object.freeze({...previous}),
  next:Object.freeze({...next})});
}
// v2 challenges must be authenticated by the signer. Legacy v1 receipts
// are intentionally rejected, rather than transparently downgraded.
export function canonicalRecoveryFloorAuthorityStatement(s){
 if(!keys(s,'version,domain,issuer,audience,serial,headHash,requestNonce,issuedAt,expiresAt')||
  s.version!==2||s.domain!=='verivaro-g1-review-floor-authority-v2'||
  !scopeOk(s.issuer)||!scopeOk(s.audience)||
  !Number.isSafeInteger(s.serial)||s.serial<0||
  s.serial>=Number.MAX_SAFE_INTEGER-2||
  typeof s.headHash!=='string'||!HEX.test(s.headHash)||
  !validNonce(s.requestNonce)||!iso(s.issuedAt)||!iso(s.expiresAt)||
  Date.parse(s.expiresAt)<=Date.parse(s.issuedAt)||
  Date.parse(s.expiresAt)-Date.parse(s.issuedAt)>30000)
  throw invalid();
 return Buffer.from(JSON.stringify({
  version:2,domain:'verivaro-g1-review-floor-authority-v2',
  issuer:s.issuer,audience:s.audience,serial:s.serial,
  headHash:s.headHash,requestNonce:s.requestNonce,
  issuedAt:s.issuedAt,expiresAt:s.expiresAt
 }),'utf8');
}
export function createUnsignedRecoveryFloorAuthorityStatement({
 issuer,audience,serial,headHash,requestNonce,issuedAt,expiresAt
}={}){
 const s={version:2,domain:'verivaro-g1-review-floor-authority-v2',
  issuer,audience,serial,headHash,requestNonce,issuedAt,expiresAt};
 canonicalRecoveryFloorAuthorityStatement(s);
 return Object.freeze(s);
}
export function verifySignedRecoveryFloorAuthority(envelope,{
 issuer,audience,trustedAuthorityKey,trustedAuthorityKeySchedule,
 trustedFloorPolicy,expectedRequestNonce,now,
 maxReceiptAgeMs=10000
}={}){
 if(!keys(envelope,'statement,signature')||!validNonce(expectedRequestNonce)||
  !iso(now)||!Number.isSafeInteger(maxReceiptAgeMs)||
  maxReceiptAgeMs<25||maxReceiptAgeMs>30000)throw invalid();
 const bytes=canonicalRecoveryFloorAuthorityStatement(envelope.statement);
 const s=envelope.statement;
 const age=Date.parse(now)-Date.parse(s.issuedAt);
 if(s.issuer!==issuer||s.audience!==audience||
  s.requestNonce!==expectedRequestNonce||
  age<0||age>maxReceiptAgeMs||
  Date.parse(now)>=Date.parse(s.expiresAt))throw invalid();
 const legacy=trustedAuthorityKey!==undefined&&trustedAuthorityKey!==null;
 const scheduled=trustedAuthorityKeySchedule!==undefined&&
  trustedAuthorityKeySchedule!==null;
 if(legacy===scheduled)throw invalid();
 let authorityKey;
 try{
  authorityKey=scheduled?
   resolveTrustedRecoveryFloorAuthorityPublicKey(
    trustedAuthorityKeySchedule,s.serial):pubkey(trustedAuthorityKey);
 }catch{throw invalid();}
 signature(envelope.signature,bytes,authorityKey);
 if(trustedFloorPolicy!==undefined&&trustedFloorPolicy!==null){
  if(!scheduled)throw invalid();
  try{
   inspectTrustedRecoveryFloorTrustPolicy(trustedFloorPolicy,{
    issuer,audience,trustedAuthorityKeySchedule,now,
    serial:s.serial,headHash:s.headHash
   });
  }catch{throw invalid();}
 }
 return Object.freeze({serial:s.serial,headHash:s.headHash});
}
// Verifies the entire canonical consumed-review ledger, its last entry and
// the previously trusted head immediately preceding the new entry.
// The log is evidence, NOT authenticated remote publication by itself.
export function verifyRecoveryFloorPublication(publication,{
 issuer,audience,expectedPrevious,trustedCustodianKeys,consumptionLog,
 now
}={}){
 if(!keys(publication,'statement,signatures')||!scopeOk(issuer)||
  !scopeOk(audience)||!validHead(expectedPrevious)||
  !keys(trustedCustodianKeys,'primary,secondary')||
  !Buffer.isBuffer(consumptionLog)||!iso(now)||
  !Array.isArray(publication.signatures)||publication.signatures.length!==2)
  throw invalid();
 const s=publication.statement,bytes=canonicalRecoveryFloorPublicationStatement(s);
 if(s.issuer!==issuer||s.audience!==audience||!same(s.previous,expectedPrevious)||
  Date.parse(now)<Date.parse(s.issuedAt)||
  Date.parse(now)>=Date.parse(s.expiresAt))throw invalid();
 const primary=pubkey(trustedCustodianKeys.primary);
 const secondary=pubkey(trustedCustodianKeys.secondary);
 const a=primary.export({type:'spki',format:'der'});
 const b=secondary.export({type:'spki',format:'der'});
 if(a.equals(b))throw invalid();
 for(const [i,role] of ['primary','secondary'].entries()){
  const item=publication.signatures[i];
  if(!keys(item,'role,signature')||item.role!==role)throw invalid();
  signature(item.signature,bytes,i===0?primary:secondary);
 }
 let proof;
 try{
  proof=verifyReferenceRecoveryApprovalLog(consumptionLog,{
   issuer,audience,trustedHead:s.next.headHash
  });
 }catch{throw invalid();}
 if(proof.serial!==s.next.serial)throw invalid();
 const rows=consumptionLog.toString('utf8').trimEnd().split('\n');
 if(rows.length<2)throw invalid();
 let previous,last;
 try{
  previous=JSON.parse(rows.at(-2));
  last=JSON.parse(rows.at(-1));
 }catch{throw invalid();}
 if(previous.serial!==s.previous.serial||previous.hash!==s.previous.headHash||
  last.previousHash!==s.previous.headHash||last.serial!==s.next.serial||
  last.hash!==s.next.headHash||last.kind!=='consume'||
  last.approvalId!==s.approvalId||
  last.evidenceHash!==s.evidenceHash)throw invalid();
 return Object.freeze({decision:'REVIEW_FLOOR_ELIGIBLE_ONLY',
  serial:s.next.serial,headHash:s.next.headHash,
  publicationId:s.publicationId,
  automaticRecoveryPermitted:false});
}
async function withDeadline(task,ms){
 const ctrl=new AbortController();
 let timer;
 try{
  return await Promise.race([
   Promise.resolve().then(()=>task(ctrl.signal)),
   new Promise((_,reject)=>{timer=setTimeout(()=>{
    ctrl.abort();reject(fail());
   },ms);})
  ]);
 }finally{clearTimeout(timer);ctrl.abort();}
}
// Independent authority must authenticate/authorize CAS, persist its own
// monotonic record and fence every competing writer. This gate cannot do that.
export async function openReferenceRecoveryFloorPublicationGate({
 issuer,audience,trustedFloor,trustedAuthorityKey,trustedAuthorityKeySchedule,
 trustedFloorPolicy,readFloorPolicyCheckpoint,trustedCustodianKeys,
 authority,ioTimeoutMs=2000,clock=()=>new Date(),receiptMaxAgeMs=10000
}={}){
 if(!scopeOk(issuer)||!scopeOk(audience)||!validHead(trustedFloor)||
  Boolean(trustedAuthorityKey)===Boolean(trustedAuthorityKeySchedule)||
  Boolean(trustedFloorPolicy)!==(typeof readFloorPolicyCheckpoint==='function')||
  (trustedFloorPolicy&&!trustedAuthorityKeySchedule)||
  !keys(trustedCustodianKeys,'primary,secondary')||
  !authority||typeof authority.read!=='function'||
  typeof authority.compareAndSwap!=='function'||
  !Number.isSafeInteger(ioTimeoutMs)||ioTimeoutMs<25||ioTimeoutMs>30000||
  typeof clock!=='function'||!Number.isSafeInteger(receiptMaxAgeMs)||
  receiptMaxAgeMs<25||receiptMaxAgeMs>30000)throw fail();
 const scope=Object.freeze({issuer,audience});
 const checkPolicy=async()=>{
  if(!trustedFloorPolicy)return;
  const expected=trustedRecoveryFloorTrustPolicyCheckpoint(trustedFloorPolicy);
  const actual=await withDeadline(signal=>readFloorPolicyCheckpoint(scope,{signal}),ioTimeoutMs);
  if(!keys(actual,'revision,digest')||
   actual.revision!==expected.revision||actual.digest!==expected.digest)
   throw fail();
 };
 const inspect=(envelope,expectedRequestNonce)=>{
  const stamp=clock();
  if(!(stamp instanceof Date)||!Number.isFinite(stamp.getTime()))throw fail();
  return verifySignedRecoveryFloorAuthority(envelope,{
   ...scope,trustedAuthorityKey,trustedAuthorityKeySchedule,
   trustedFloorPolicy,expectedRequestNonce,now:stamp.toISOString(),
   maxReceiptAgeMs:receiptMaxAgeMs
  });
 };
 const readHead=async()=>{
  await checkPolicy();
  const requestNonce=freshNonce();
  const envelope=await withDeadline(signal=>authority.read(scope,{
   signal,requestNonce
  }),ioTimeoutMs);
  const result=inspect(envelope,requestNonce);
  await checkPolicy();
  return result;
 };
 let head;
 try{
  const a=await readHead();
  if(!same(a,trustedFloor))throw fail();
  const b=await readHead();
  if(!same(b,trustedFloor))throw fail();
  head=Object.freeze({...b});
 }catch{throw fail();}
 let closed=false,faulted=false,writing=false;
 return Object.freeze({
  async audit(){
   if(closed||faulted||writing)throw fail();
   try{
    const current=await readHead();
    if(!same(current,head)||closed||faulted||writing)throw fail();
    return Object.freeze({...current});
   }catch{faulted=true;throw fail();}
  },
  async publish({publication,consumptionLog}={}){
   if(closed||faulted||writing)throw fail();
   writing=true;
   let remoteAttempt=false;
   try{
    const before=await readHead();
    if(!same(before,head))throw fail();
    const now=clock();
    if(!(now instanceof Date)||!Number.isFinite(now.getTime()))throw fail();
    let verified;
    try{
     verified=verifyRecoveryFloorPublication(publication,{
      ...scope,expectedPrevious:before,trustedCustodianKeys,
      consumptionLog,now:now.toISOString()
     });
    }catch{throw invalid();}
    remoteAttempt=true;
    const requestNonce=freshNonce();
    const receipt=await withDeadline(signal=>authority.compareAndSwap({
     ...scope,previous:before,publication,consumptionLog:Buffer.from(consumptionLog),
     requestNonce
    },{signal}),ioTimeoutMs);
    const ack=inspect(receipt,requestNonce);
    if(ack.serial!==verified.serial||ack.headHash!==verified.headHash)
     throw fail();
    const reread=await readHead();
    if(!same(ack,reread))throw fail();
    await checkPolicy();
    head=Object.freeze({...reread});
    return Object.freeze({status:'REVIEW_FLOOR_PUBLISHED_ONLY',
     serial:head.serial,headHash:head.headHash,
     publicationId:verified.publicationId,
     automaticRecoveryPermitted:false,
     manualReconciliationRequired:true});
   }catch(e){
    if(!remoteAttempt&&e?.message===invalid().message)throw e;
    // Lost ACK, late remote commit, stale remote floor and read-after-write
    // mismatch are uncertain: permanently deny; never auto retry or promote.
    faulted=true;throw fail();
   }finally{writing=false;}
  },
  close(){
   if(writing)throw fail();
   closed=true;
  }
 });
}
