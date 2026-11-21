// G1 protocol contract for a separately governed REVIEW_ONLY floor trust policy.
// Verifies signed revocation/rollback metadata against an independently pinned
// policy checkpoint. No authority, key vault, trusted clock or remote service
// is created by this module. Never grants operational recovery permission.
import {createHash,createPublicKey,sign,verify} from 'node:crypto';
import {
 recoveryFloorAuthorityKeyId
} from './provider-witness-authority-key-schedule.mjs';

const records=new WeakMap();
const HEX=/^[0-9a-f]{64}$/;
const validSerial=n=>Number.isSafeInteger(n)&&n>=0&&n<Number.MAX_SAFE_INTEGER-2;
const validRevision=n=>Number.isSafeInteger(n)&&n>=1&&n<Number.MAX_SAFE_INTEGER-2;
const fail=()=>{throw Error('floor trust policy rejected');};
const exact=(o,names)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 Object.keys(o).sort().join(',')===names.slice().sort().join(',');
const scope=s=>typeof s==='string'&&s.length>0&&s.length<=512&&!/[\x00-\x1f\x7f]/.test(s);
const stamp=s=>typeof s==='string'&&Number.isFinite(Date.parse(s))&&new Date(s).toISOString()===s;
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
function pub(k){
 let v;
 try{
  if(k?.type==='private')fail();
  if(typeof k==='string'&&!k.startsWith('-----BEGIN PUBLIC KEY-----'))fail();
  v=k?.type==='public'?k:createPublicKey(k);
 }catch{fail();}
 if(v?.type!=='public'||v.asymmetricKeyType!=='ed25519')fail();
 return v;
}
function validSchedule(schedule){
 if(schedule?.kind!=='VERIVARO_G1_REFERENCE_AUTHORITY_KEY_EPOCHS'||
  !Array.isArray(schedule.epochs)||schedule.epochs.length<1||
  !Object.isFrozen(schedule)||!Object.isFrozen(schedule.epochs))fail();
 // A copied schedule has no private key resolution. The signature verifier
 // also rejects such copies before accepting any floor receipt.
 for(const e of schedule.epochs){
  if(!exact(e,['firstSerial','lastSerial','keyId'])||
   !validSerial(e.firstSerial)||!HEX.test(e.keyId)||
   !(e.lastSerial===null||validSerial(e.lastSerial)))fail();
 }
 return schedule.epochs;
}
export function recoveryFloorKeyScheduleDigest(schedule){
 return digest(Buffer.from(JSON.stringify({
  version:1,kind:'VERIVARO_G1_REFERENCE_AUTHORITY_KEY_EPOCHS',
  epochs:validSchedule(schedule)
 }),'utf8'));
}
export function canonicalRecoveryFloorTrustPolicyStatement(s){
 if(!exact(s,['version','domain','issuer','audience','revision','scheduleDigest',
  'minimumFloor','revokedKeyIds','issuedAt','expiresAt'])||
  s.version!==1||s.domain!=='verivaro-g1-review-floor-trust-policy-v1'||
  !scope(s.issuer)||!scope(s.audience)||!validRevision(s.revision)||
  typeof s.scheduleDigest!=='string'||!HEX.test(s.scheduleDigest)||
  !exact(s.minimumFloor,['serial','headHash'])||
  !validSerial(s.minimumFloor.serial)||typeof s.minimumFloor.headHash!=='string'||
  !HEX.test(s.minimumFloor.headHash)||
  !Array.isArray(s.revokedKeyIds)||s.revokedKeyIds.length>16||
  !s.revokedKeyIds.every((x,i)=>typeof x==='string'&&HEX.test(x)&&
   (i===0||s.revokedKeyIds[i-1]<x))||
  !stamp(s.issuedAt)||!stamp(s.expiresAt)||
  Date.parse(s.expiresAt)<=Date.parse(s.issuedAt)||
  Date.parse(s.expiresAt)-Date.parse(s.issuedAt)>86400000)fail();
 return Buffer.from(JSON.stringify({
  version:1,domain:'verivaro-g1-review-floor-trust-policy-v1',
  issuer:s.issuer,audience:s.audience,revision:s.revision,
  scheduleDigest:s.scheduleDigest,
  minimumFloor:{serial:s.minimumFloor.serial,headHash:s.minimumFloor.headHash},
  revokedKeyIds:s.revokedKeyIds,
  issuedAt:s.issuedAt,expiresAt:s.expiresAt
 }),'utf8');
}
export function createUnsignedRecoveryFloorTrustPolicyStatement({
 issuer,audience,revision,scheduleDigest,minimumFloor,revokedKeyIds,
 issuedAt,expiresAt
}={}){
 const statement={version:1,domain:'verivaro-g1-review-floor-trust-policy-v1',
  issuer,audience,revision,scheduleDigest,minimumFloor,revokedKeyIds,
  issuedAt,expiresAt};
 canonicalRecoveryFloorTrustPolicyStatement(statement);
 return Object.freeze({...statement,
  minimumFloor:Object.freeze({...minimumFloor}),
  revokedKeyIds:Object.freeze([...revokedKeyIds])
 });
}
function signature(raw,bytes,key){
 if(typeof raw!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(raw))fail();
 const sig=Buffer.from(raw,'base64url');
 if(sig.length!==64||sig.toString('base64url')!==raw||
  !verify(null,bytes,key,sig))fail();
}
export function createTrustedRecoveryFloorTrustPolicy({
 envelope,trustedGovernanceKey,trustedCheckpoint,trustedAuthorityKeySchedule,
 issuer,audience,now
}={}){
 if(!exact(envelope,['statement','signature'])||
  !exact(trustedCheckpoint,['revision','digest'])||
  !validRevision(trustedCheckpoint.revision)||
  typeof trustedCheckpoint.digest!=='string'||!HEX.test(trustedCheckpoint.digest)||
  !scope(issuer)||!scope(audience)||!stamp(now))fail();
 const bytes=canonicalRecoveryFloorTrustPolicyStatement(envelope.statement);
 const statement=envelope.statement,hash=digest(bytes),date=Date.parse(now);
 if(statement.issuer!==issuer||statement.audience!==audience||
  statement.revision!==trustedCheckpoint.revision||
  hash!==trustedCheckpoint.digest||
  statement.scheduleDigest!==recoveryFloorKeyScheduleDigest(trustedAuthorityKeySchedule)||
  date<Date.parse(statement.issuedAt)||date>=Date.parse(statement.expiresAt))fail();
 const governance=pub(trustedGovernanceKey);
 const governanceId=recoveryFloorAuthorityKeyId(governance);
 const ids=trustedAuthorityKeySchedule.epochs.map(e=>e.keyId);
 if(ids.includes(governanceId))fail();
 for(const id of statement.revokedKeyIds)if(!ids.includes(id))fail();
 signature(envelope.signature,bytes,governance);
 const policy=Object.freeze({
  kind:'VERIVARO_G1_VERIFIED_FLOOR_TRUST_POLICY',
  revision:statement.revision,digest:hash
 });
 records.set(policy,Object.freeze({
  issuer,audience,scheduleDigest:statement.scheduleDigest,
  minimumFloor:Object.freeze({...statement.minimumFloor}),
  revoked:Object.freeze([...statement.revokedKeyIds]),
  issuedAtMs:Date.parse(statement.issuedAt),
  expiresAtMs:Date.parse(statement.expiresAt)
 }));
 return policy;
}
export function inspectTrustedRecoveryFloorTrustPolicy(policy,{
 issuer,audience,trustedAuthorityKeySchedule,now,serial,headHash
}={}){
 const p=records.get(policy);
 if(!p||p.issuer!==issuer||p.audience!==audience||
  !stamp(now)||!validSerial(serial)||typeof headHash!=='string'||!HEX.test(headHash)||
  recoveryFloorKeyScheduleDigest(trustedAuthorityKeySchedule)!==p.scheduleDigest||
  Date.parse(now)<p.issuedAtMs||Date.parse(now)>=p.expiresAtMs||
  serial<p.minimumFloor.serial||
  serial===p.minimumFloor.serial&&headHash!==p.minimumFloor.headHash)fail();
 const keyId=trustedAuthorityKeySchedule.epochs.find(e=>
  e.firstSerial<=serial&&(e.lastSerial===null||serial<=e.lastSerial))?.keyId;
 if(!keyId||p.revoked.includes(keyId))fail();
 return Object.freeze({revision:policy.revision,digest:policy.digest,
  serial,headHash,releaseApproved:false,automaticRecoveryPermitted:false});
}
export function trustedRecoveryFloorTrustPolicyCheckpoint(policy){
 if(!records.has(policy))fail();
 return Object.freeze({revision:policy.revision,digest:policy.digest});
}

// A governance-policy revision is an externally authenticated *candidate*.
// These checks are pure: the authority must atomically compare-and-swap its
// pinned checkpoint alongside the floor under an independently fenced lock.
// An app-side call cannot establish linearizability or remote key custody.
export function advanceTrustedRecoveryFloorTrustPolicy({
 previousPolicy,envelope,trustedGovernanceKey,trustedNextCheckpoint,
 trustedAuthorityKeySchedule,issuer,audience,now
}={}){
 const old=records.get(previousPolicy);
 if(!old||old.issuer!==issuer||old.audience!==audience||!stamp(now)||
  previousPolicy.revision>=Number.MAX_SAFE_INTEGER-3||
  Date.parse(now)<old.issuedAtMs||Date.parse(now)>=old.expiresAtMs)fail();
 const next=createTrustedRecoveryFloorTrustPolicy({
  envelope,trustedGovernanceKey,trustedCheckpoint:trustedNextCheckpoint,
  trustedAuthorityKeySchedule,issuer,audience,now
 });
 const newer=records.get(next);
 if(next.revision!==previousPolicy.revision+1||
  newer.scheduleDigest!==old.scheduleDigest||
  newer.minimumFloor.serial<old.minimumFloor.serial||
  newer.minimumFloor.serial===old.minimumFloor.serial&&
   newer.minimumFloor.headHash!==old.minimumFloor.headHash||
  old.revoked.some(id=>!newer.revoked.includes(id)))fail();
 return next;
}

export function trustedRecoveryFloorTrustPolicyMinimumFloor(policy){
 const state=records.get(policy);
 if(!state)fail();
 return Object.freeze({...state.minimumFloor});
}
