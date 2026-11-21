// Candidate coordination guard for a separately governed audit-head publisher.
// Does NOT implement the independent publisher or persistence of trustedFloor.
// In production its public key, freshness floor and network boundary MUST be
// controlled outside the journal/witness host and cannot be self-provisioned.
import {openReferenceWitnessJournal} from './provider-witness-journal.mjs';
import {
 createUnsignedWitnessAuditStatement,
 verifyExternallySignedWitnessAuditReceipt
} from './provider-witness-audit-receipt.mjs';

const HEX=/^[a-f0-9]{64}$/;
const SCOPE=s=>typeof s==='string'&&s.length>0&&s.length<=512&&!/[\x00-\x1f\x7f]/.test(s);
const CP=c=>c&&typeof c==='object'&&!Array.isArray(c)&&
 Object.keys(c).sort().join(',')==='digest,sequence'&&
 Number.isSafeInteger(c.sequence)&&c.sequence>=1&&HEX.test(c.digest);
const SAME=(a,b)=>CP(a)&&CP(b)&&a.sequence===b.sequence&&a.digest===b.digest;
const fail=()=>Error('witness anchor state unavailable');
const matches=(state,receipt)=>state&&receipt&&
 state.count===receipt.count&&state.headHash===receipt.headHash&&
 SAME(state.checkpoint,receipt.checkpoint);

async function withDeadline(task,ms){
 const controller=new AbortController();
 let timer;
 try{
  return await Promise.race([
   Promise.resolve().then(()=>task(controller.signal)),
   new Promise((_,reject)=>{timer=setTimeout(()=>{
    controller.abort();reject(fail());
   },ms);})
  ]);
 }finally{clearTimeout(timer);controller.abort();}
}

// The floor is supplied from a second independently governed source, not from
// the signed receipt or local journal being checked. Only exact matches are
// accepted: promotion of the floor requires a separate authorised operation.
// An old signed receipt plus an old journal is detectable ONLY when the trusted
// floor reflects a more recent head.
export async function openReceiptGuardedReferenceWitness({
 directory,issuer,audience,anchor,trustedPublicKey,trustedFloor,
 ioTimeoutMs=2000,clock=()=>new Date()
}){
 if(!SCOPE(issuer)||!SCOPE(audience)||!anchor||
  typeof anchor.read!=='function'||typeof anchor.compareAndSwap!=='function'||
  typeof trustedPublicKey==='undefined'||!trustedFloor||
  Object.keys(trustedFloor).sort().join(',')!=='count,headHash'||
  !Number.isSafeInteger(trustedFloor.count)||trustedFloor.count<1||
  trustedFloor.count>8192||typeof trustedFloor.headHash!=='string'||
  !HEX.test(trustedFloor.headHash)||!Number.isSafeInteger(ioTimeoutMs)||
  ioTimeoutMs<25||ioTimeoutMs>30000||typeof clock!=='function')throw fail();
 const scope=Object.freeze({issuer,audience});
 const inspect=envelope=>verifyExternallySignedWitnessAuditReceipt(envelope,{
  trustedPublicKey,...scope,minimumCount:trustedFloor.count
 });
 function exact(receipt,state){
  if(!matches(state,receipt))throw fail();
 }
 function floorExact(receipt){
  if(receipt.count!==trustedFloor.count||
   receipt.headHash!==trustedFloor.headHash)throw fail();
 }
 let remoteEnvelope;
 try{
  remoteEnvelope=await withDeadline(signal=>anchor.read(scope,{signal}),ioTimeoutMs);
  floorExact(inspect(remoteEnvelope));
 }catch{throw fail();}
 // Open uses the floor's exact trusted head; no implicit advancement or
 // rewrite of the journal on a remote/local mismatch.
 let journal;
 try{
  journal=await openReferenceWitnessJournal({
   directory,...scope,trustedHead:trustedFloor.headHash
  });
  const state=await journal.audit();
  exact(inspect(remoteEnvelope),state);
  const again=await withDeadline(signal=>anchor.read(scope,{signal}),ioTimeoutMs);
  exact(inspect(again),state);
  remoteEnvelope=again;
 }catch{
  if(journal)await journal.close().catch(()=>{});
  throw fail();
 }
 let expected=Object.freeze({...await journal.audit()}),
  closed=false,faulted=false,writing=false,epoch=0;
 const ready=()=>!closed&&!faulted;
 function checkedEnvelope(envelope,state){
  exact(inspect(envelope),state);
  return envelope;
 }
 return Object.freeze({
  async read(requestScope){
   if(requestScope?.issuer!==issuer||requestScope?.audience!==audience||!ready())throw fail();
   if(writing)throw Error('witness anchor write in progress');
   const currentEpoch=epoch;
   try{
    const [local,remote]=await Promise.all([
     journal.audit(),
     withDeadline(signal=>anchor.read(scope,{signal}),ioTimeoutMs)
    ]);
    if(writing||currentEpoch!==epoch)throw Error('witness anchor changed during read');
    exact(expected,local);
    checkedEnvelope(remote,expected);
    if(!ready())throw fail();
    return Object.freeze({...local.checkpoint});
   }catch(e){
    // A read that raced a successful local rotation is denied without
    // permanently faulting the still-consistent writer. Other failures latch.
    if(writing||currentEpoch!==epoch)throw Error('witness anchor changed during read');
    faulted=true;
    throw fail();
   }
  },
  async compareAndSwap({issuer:iss,audience:aud,previous,next}={}){
   if(iss!==issuer||aud!==audience||!CP(previous)||!CP(next)||
    next.sequence<=previous.sequence||!ready())throw fail();
   if(writing)throw Error('witness anchor write in progress');
   writing=true;epoch++;
   let safeClientConflict=false;
   try{
    const before=await journal.audit();
    exact(expected,before);
    if(!SAME(previous,before.checkpoint)){
     // A stale, rejected client request has not touched disk or the anchor.
     // It must not permanently deny otherwise healthy authentication.
     safeClientConflict=true;
     throw Error('witness compare-and-swap conflict');
    }
    const remote=await withDeadline(signal=>anchor.read(scope,{signal}),ioTimeoutMs);
    checkedEnvelope(remote,before);
    const committed=await journal.compareAndSwap({...scope,previous,next});
    const after=await journal.audit();
    if(!SAME(after.checkpoint,next)||!SAME(committed,next)||
     after.count!==before.count+1)throw fail();
    // Local fsync occurs BEFORE requesting independent publication. If the
    // remote commit or ACK is uncertain, never retry or silently roll back.
    const now=clock();
    if(!(now instanceof Date)||!Number.isFinite(now.getTime()))throw fail();
    const statement=createUnsignedWitnessAuditStatement({
     ...scope,checkpoint:after.checkpoint,count:after.count,
     headHash:after.headHash,issuedAt:now.toISOString()
    });
    const published=await withDeadline(signal=>anchor.compareAndSwap({
     ...scope,previous:remote,statement
    },{signal}),ioTimeoutMs);
    checkedEnvelope(published,after);
    // A signed ACK alone is insufficient: require a fresh consistent read.
    const confirmed=await withDeadline(signal=>anchor.read(scope,{signal}),ioTimeoutMs);
    checkedEnvelope(confirmed,after);
    expected=Object.freeze({...after});
    remoteEnvelope=confirmed;
    return Object.freeze({...after.checkpoint});
   }catch(e){
    if(safeClientConflict)throw e;
    // Every other error can conceal remote advancement or local persistence
    // uncertainty; deny until a supervised reconciliation and restart.
    faulted=true;
    throw fail();
   }finally{writing=false;epoch++;}
  },
  async audit(){
   if(!ready()||writing)throw fail();
   try{
    const state=await journal.audit();
    exact(expected,state);
    return Object.freeze({...state});
   }catch{faulted=true;throw fail();}
  },
  async close(){
   if(closed)return;
   if(writing)throw fail();
   closed=true;
   await journal.close();
  }
 });
}
