// Deterministic, in-memory G1 REVIEW_ONLY transition model.
// This is intentionally NOT a network service, durable database, independent
// signer, production fencing system or a consensus algorithm. Its synchronous
// commit boundary models invariants a real linearizable authority must enforce.
import {
 inspectTrustedRecoveryFloorTrustPolicy,
 trustedRecoveryFloorTrustPolicyCheckpoint,
 trustedRecoveryFloorTrustPolicyMinimumFloor,
 advanceTrustedRecoveryFloorTrustPolicy
} from './provider-witness-authority-trust-policy.mjs';
import {
 verifyRecoveryFloorPublication
} from './provider-witness-recovery-floor-publication.mjs';

const HEX=/^[0-9a-f]{64}$/;
const fail=()=>{throw Error('reference atomic floor model rejected');};
const exact=(v,names)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&
 Object.keys(v).sort().join(',')===names.slice().sort().join(',');
const validHead=h=>exact(h,['serial','headHash'])&&
 Number.isSafeInteger(h.serial)&&h.serial>=0&&
 h.serial<Number.MAX_SAFE_INTEGER-2&&
 typeof h.headHash==='string'&&HEX.test(h.headHash);
const same=(a,b)=>a.serial===b.serial&&a.headHash===b.headHash;
const validCheckpoint=v=>exact(v,['revision','digest'])&&
 Number.isSafeInteger(v.revision)&&v.revision>=1&&
 typeof v.digest==='string'&&HEX.test(v.digest);
const sameCheckpoint=(a,b)=>a.revision===b.revision&&a.digest===b.digest;
const scopeOk=s=>typeof s==='string'&&s.length>0&&s.length<=512&&
 !/[\x00-\x1f\x7f]/.test(s);

export function createReferenceAtomicRecoveryFloorModel({
 issuer,audience,initialFloor,initialPolicy,trustedAuthorityKeySchedule,
 trustedGovernanceKey,trustedCustodianKeys,clock=()=>new Date()
}={}){
 if(!scopeOk(issuer)||!scopeOk(audience)||!validHead(initialFloor)||
  !initialPolicy||!trustedAuthorityKeySchedule||!trustedGovernanceKey||
  !exact(trustedCustodianKeys,['primary','secondary'])||
  typeof clock!=='function')fail();
 const now=()=>{
  const v=clock();
  if(!(v instanceof Date)||!Number.isFinite(v.getTime()))fail();
  return v.toISOString();
 };
 const checked=(p,head)=>inspectTrustedRecoveryFloorTrustPolicy(p,{
  issuer,audience,trustedAuthorityKeySchedule,now:now(),
  serial:head.serial,headHash:head.headHash
 });
 checked(initialPolicy,initialFloor);
 let floor=Object.freeze({...initialFloor}),policy=initialPolicy,
  epoch=0,publications=0,changes=0;
 const partitioned=new Set();
 const checkpoint=()=>trustedRecoveryFloorTrustPolicyCheckpoint(policy);
 // A generated integer is a SIMULATED fence, not an authenticated credential.
 // Real authority-side grants must authenticate the principal and persist the
 // epoch in a remotely linearizable store before any write is enabled.
 return Object.freeze({
  acquireSimulatedWriter(){
   if(epoch>=Number.MAX_SAFE_INTEGER-3)fail();
   epoch++;
   return epoch;
  },
  setSimulatedPartition(writerEpoch,offline){
   if(!Number.isSafeInteger(writerEpoch)||writerEpoch<1||
    writerEpoch>epoch||typeof offline!=='boolean')fail();
   if(offline)partitioned.add(writerEpoch);
   else partitioned.delete(writerEpoch);
  },
  snapshot(){
   return Object.freeze({
    floor:Object.freeze({...floor}),
    policyCheckpoint:checkpoint(),
    fenceEpoch:epoch,publicationCount:publications,
    policyUpdateCount:changes,automaticRecoveryPermitted:false
   });
  },
  // No await between checking the current policy, writer fence, approval
  // ledger and the in-memory floor assignment. This establishes only a
  // single-process *model* of the desired authority-side ordering.
  publish({writerEpoch,expectedPrevious,expectedPolicyCheckpoint,
   publication,consumptionLog,simulateLostAck=false}={}){
   if(!Number.isSafeInteger(writerEpoch)||writerEpoch!==epoch||
    partitioned.has(writerEpoch)||!validHead(expectedPrevious)||
    !same(expectedPrevious,floor)||!validCheckpoint(expectedPolicyCheckpoint)||
    !sameCheckpoint(expectedPolicyCheckpoint,checkpoint())||
    typeof simulateLostAck!=='boolean')fail();
   checked(policy,floor);
   let result;
   try{
    result=verifyRecoveryFloorPublication(publication,{
     issuer,audience,expectedPrevious:floor,trustedCustodianKeys,
     consumptionLog,now:now()
    });
   }catch{fail();}
   const proposed={serial:result.serial,headHash:result.headHash};
   if(!validHead(proposed)||proposed.serial!==floor.serial+1)fail();
   // A policy may revoke the signer for the destination serial as well.
   checked(policy,proposed);
   floor=Object.freeze(proposed);
   publications++;
   // A network partition after commit cannot roll back committed state.
   // Retrying the same previous head must produce a CAS conflict.
   if(simulateLostAck)throw Error('reference atomic floor model acknowledgement lost');
   return Object.freeze({
    status:'REFERENCE_REVIEW_FLOOR_COMMITTED_ONLY',
    ...proposed,publicationId:result.publicationId,
    automaticRecoveryPermitted:false
   });
  },
  // Simulates one authority-side conditional update; validation happens
  // before the policy checkpoint changes. Revocations are irreversible
  // through this endpoint, and policy+floor state share one model boundary.
  replacePolicy({expectedPolicyCheckpoint,envelope,trustedNextCheckpoint}={}){
   if(!validCheckpoint(expectedPolicyCheckpoint)||
    !sameCheckpoint(expectedPolicyCheckpoint,checkpoint())||
    !validCheckpoint(trustedNextCheckpoint))fail();
   let next;
   try{
    next=advanceTrustedRecoveryFloorTrustPolicy({
     previousPolicy:policy,envelope,trustedGovernanceKey,
     trustedNextCheckpoint,trustedAuthorityKeySchedule,
     issuer,audience,now:now()
    });
   }catch{fail();}
   const minimum=envelope.statement.minimumFloor;
   const pinnedMinimum=trustedRecoveryFloorTrustPolicyMinimumFloor(policy);
   // Only preserve the independently pinned minimum or advance precisely
   // to the currently authenticated floor. Unknown intermediate hashes are
   // not attested by this bounded, in-memory model.
   if(!same(minimum,pinnedMinimum)&&!same(minimum,floor))fail();
   policy=next;changes++;
   return Object.freeze({status:'REFERENCE_POLICY_REPLACED_ONLY',
    ...checkpoint(),automaticRecoveryPermitted:false});
  }
 });
}
