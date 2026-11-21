// Single-host REFERENCE signed receipt publisher; NOT an independent service.
// Production needs a separately administered, durable remote trust domain.
// Signing is delegated to a caller-provided capability; no private key stored.
import {open,rename,unlink,realpath,lstat,readdir} from 'node:fs/promises';
import {constants} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {isAbsolute,join,resolve,basename} from 'node:path';
import {
 canonicalWitnessAuditStatement,verifyExternallySignedWitnessAuditReceipt
} from './provider-witness-audit-receipt.mjs';

const HEX=/^[a-f0-9]{64}$/;
const scopeOk=s=>typeof s==='string'&&s.length>0&&s.length<=512&&!/[\x00-\x1f\x7f]/.test(s);
const fail=()=>Error('reference receipt publisher unavailable');
const DIR=constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW;
const READ=constants.O_RDONLY|constants.O_NOFOLLOW;
const EXCLUSIVE=constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW;
const MAX=4096;
// Application deadlines alone do not stop an uncooperative remote signer.
// Late signatures cannot reach this publisher's persistence path after timeout.
const signalOk=s=>s===undefined||(
 s&&typeof s.addEventListener==='function'&&
 typeof s.removeEventListener==='function'&&typeof s.aborted==='boolean'
);
async function signWithDeadline(signStatement,bytes,statement,timeoutMs,externalSignal){
 if(!signalOk(externalSignal)||externalSignal?.aborted)throw fail();
 const controller=new AbortController();
 const signal=externalSignal?AbortSignal.any([controller.signal,externalSignal]):controller.signal;
 let timer,onAbort;
 try{
  const abandoned=new Promise((_,reject)=>{
   onAbort=()=>reject(fail());
   signal.addEventListener('abort',onAbort,{once:true});
   timer=setTimeout(()=>controller.abort(),timeoutMs);
  });
  const signed=await Promise.race([
   Promise.resolve().then(()=>{
    if(signal.aborted)throw fail();
    return signStatement(Buffer.from(bytes),statement,{signal});
   }),
   abandoned
  ]);
  if(signal.aborted)throw fail();
  return signed;
 }finally{
  clearTimeout(timer);
  signal.removeEventListener('abort',onAbort);
  controller.abort();
 }
}
const checkpointSame=(a,b)=>a?.sequence===b?.sequence&&a?.digest===b?.digest;
function same(a,b){return a.count===b.count&&a.headHash===b.headHash&&
 checkpointSame(a.checkpoint,b.checkpoint);}
function exactFloor(state,floor){
 if(state.count!==floor.count||state.headHash!==floor.headHash)throw fail();
}
function canonicalReceipt(e){
 if(!e||typeof e!=='object'||Array.isArray(e)||
  Object.keys(e).sort().join(',')!=='signature,statement')throw fail();
 const s=e.statement;
 // A canonical statement is structurally validated by the signature verifier.
 const body=canonicalWitnessAuditStatement(s);
 if(body.toString('utf8')!==JSON.stringify(s))throw fail();
 if(typeof e.signature!=='string')throw fail();
 const data=Buffer.from(JSON.stringify({statement:s,signature:e.signature})+'\n');
 if(data.length>MAX)throw fail();
 return data;
}
function verifyEnvelope(e,scope,trustedPublicKey,minimumCount){
 const v=verifyExternallySignedWitnessAuditReceipt(e,{
  ...scope,trustedPublicKey,minimumCount
 });
 canonicalReceipt(e);
 return v;
}
function validateStat(s){
 if(!s.isFile()||s.nlink!==1||(s.mode&0o077)!==0||
  s.size<100||s.size>MAX||
  (typeof process.getuid==='function'&&s.uid!==process.getuid()))throw fail();
}
async function strictRead(path,identity){
 const f=await open(path,READ);
 try{
  const first=await f.stat();
  validateStat(first);
  if(identity&&(identity.ino!==first.ino||identity.dev!==first.dev))throw fail();
  const bytes=await f.readFile();
  const second=await f.stat();
  if(bytes.length!==first.size||first.ino!==second.ino||
   first.dev!==second.dev||first.size!==second.size||
   first.mtimeMs!==second.mtimeMs||first.ctimeMs!==second.ctimeMs)throw fail();
  let value;
  try{value=JSON.parse(bytes.toString('utf8'));}catch{throw fail();}
  if(!canonicalReceipt(value).equals(bytes))throw fail();
  // Refuse a path replaced while the original descriptor was being read.
  const linked=await lstat(path);
  if(!linked.isFile()||linked.dev!==second.dev||linked.ino!==second.ino||
   linked.nlink!==1)throw fail();
  return {value,identity:{ino:first.ino,dev:first.dev},bytes};
 }finally{await f.close();}
}
const copy=e=>Object.freeze({
 statement:Object.freeze({...e.statement,
  checkpoint:Object.freeze({...e.statement.checkpoint})}),
 signature:e.signature
});
export async function openReferenceWitnessReceiptPublisher({
 directory,issuer,audience,trustedPublicKey,trustedFloor,signStatement,
 signerTimeoutMs=3000,faultInjection,enableTestFaultInjection=false
}){
 if(!isAbsolute(directory??'')||!scopeOk(issuer)||!scopeOk(audience)||
  !trustedFloor||Object.keys(trustedFloor).sort().join(',')!=='count,headHash'||
  !Number.isSafeInteger(trustedFloor.count)||trustedFloor.count<1||
  trustedFloor.count>8192||!HEX.test(trustedFloor.headHash)||
  !trustedPublicKey||typeof signStatement!=='function'||
  !Number.isSafeInteger(signerTimeoutMs)||signerTimeoutMs<25||signerTimeoutMs>30000||
  (faultInjection!==undefined&&
   (typeof faultInjection!=='function'||enableTestFaultInjection!==true)))
  throw fail();
 const scope=Object.freeze({issuer,audience}),root=resolve(directory);
 const path=join(root,'signed-witness-receipt.json'),lockPath=join(root,'.receipt-publisher.lock');
 const dir=await open(root,DIR);
 let lease,closed=false,busy=false,faulted=false;
 try{
  const stat=await dir.stat();
  if(!stat.isDirectory()||(stat.mode&0o077)!==0||
   (typeof process.getuid==='function'&&stat.uid!==process.getuid())||
   await realpath(root)!==root)throw fail();
  // Any pending publication or writer lock must be investigated manually.
  const startNames=await readdir(root);
  if(startNames.length!==1||startNames[0]!=='signed-witness-receipt.json')throw fail();
  const initial=await strictRead(path);
  const trusted=verifyEnvelope(initial.value,scope,trustedPublicKey,trustedFloor.count);
  exactFloor(trusted,trustedFloor);
  lease=await open(lockPath,EXCLUSIVE,0o600);
  await lease.writeFile('reserved\n');
  await lease.sync();
  await dir.sync();
  const recheck=await strictRead(path,initial.identity);
  const confirmed=verifyEnvelope(recheck.value,scope,trustedPublicKey,trustedFloor.count);
  exactFloor(confirmed,trustedFloor);
  let expected=copy(recheck.value),identity=recheck.identity;
  async function verifyLiveEntries(pending){
   const linkedRoot=await lstat(root),openedRoot=await dir.stat();
   const linkedLease=await lstat(lockPath),openedLease=await lease.stat();
   if(!linkedRoot.isDirectory()||linkedRoot.ino!==openedRoot.ino||
    linkedRoot.dev!==openedRoot.dev||(linkedRoot.mode&0o077)!==0||
    !linkedLease.isFile()||linkedLease.ino!==openedLease.ino||
    linkedLease.dev!==openedLease.dev||linkedLease.nlink!==1||
    (linkedLease.mode&0o077)!==0)throw fail();
   const names=(await readdir(root)).sort();
   const allowed=['signed-witness-receipt.json','.receipt-publisher.lock'];
   if(pending)allowed.push(basename(pending));
   if(JSON.stringify(names)!==JSON.stringify(allowed.sort()))throw fail();
  }
  async function check(){
   if(closed||faulted)throw fail();
   try{
    await verifyLiveEntries();
    const current=await strictRead(path,identity);
    verifyEnvelope(current.value,scope,trustedPublicKey,expected.statement.count);
    if(!canonicalReceipt(current.value).equals(canonicalReceipt(expected)))throw fail();
    return current.value;
   }catch{
    faulted=true;
    throw fail();
   }
  }
  async function injectForTests(phase){
   // Never pass this callback from production configuration. It is deliberately
   // opt-in and exists only to force deterministic local crash/failure stages.
   if(enableTestFaultInjection&&faultInjection)await faultInjection(phase);
  }
  return Object.freeze({
   async read(requestScope){
    if(requestScope?.issuer!==issuer||requestScope?.audience!==audience||
     closed||faulted||busy)throw fail();
    return copy(await check());
   },
   async compareAndSwap({issuer:iss,audience:aud,previous,statement}={}, {signal}={}){
    if(iss!==issuer||aud!==audience||closed||faulted||busy||
     !signalOk(signal)||signal?.aborted)throw fail();
    busy=true;
    let persistenceAttempted=false;
    try{
     const current=await check();
     // Malformed/replayed client input has not altered trusted state. Reject
     // safely without poisoning an otherwise healthy publisher.
     let previousMatches=false;
     try{
      previousMatches=!!previous&&canonicalReceipt(previous).equals(canonicalReceipt(current));
     }catch{}
     if(!previousMatches)throw Error('reference receipt CAS conflict');
     const prior=verifyEnvelope(current,scope,trustedPublicKey,1);
     let nextBytes;
     try{nextBytes=canonicalWitnessAuditStatement(statement);}
     catch{throw Error('reference receipt invalid transition');}
     if(statement.issuer!==issuer||statement.audience!==audience||
      statement.count!==prior.count+1||statement.count>8192||
      statement.checkpoint.sequence<=prior.checkpoint.sequence||
      statement.headHash===prior.headHash)throw Error('reference receipt invalid transition');
     // The signer is an external dependency: it must independently verify the
     // signed journal transition and enforce separate custody in production.
     const signature=await signWithDeadline(
      signStatement,nextBytes,statement,signerTimeoutMs,signal
     );
     const next=copy({statement,signature});
     const observed=verifyEnvelope(next,scope,trustedPublicKey,statement.count);
     if(!same(observed,{count:statement.count,headHash:statement.headHash,
      checkpoint:statement.checkpoint}))throw fail();
     // A cancelled caller cannot cause a local receipt publication. Once
     // persistence begins, ambiguous outcomes fault and require reconciliation.
     if(signal?.aborted)throw fail();
     const bytes=canonicalReceipt(next);
     const pending=join(root,'.receipt-'+randomUUID()+'.pending');
     let pendingCreated=false;
     try{
      const f=await open(pending,EXCLUSIVE,0o600);
      pendingCreated=true;
      persistenceAttempted=true;
      try{await f.writeFile(bytes);await f.sync();}finally{await f.close();}
      await injectForTests('after-temp-fsync');
      await injectForTests('before-final-path-check');
      // Recheck destination inode, lock and directory before replacement.
      await verifyLiveEntries(pending);
      const priorDisk=await strictRead(path,identity);
      if(!priorDisk.bytes.equals(canonicalReceipt(expected)))throw fail();
      if(signal?.aborted)throw fail();
      await rename(pending,path);
      pendingCreated=false;
      await injectForTests('after-rename');
      await dir.sync();
      const verified=await strictRead(path);
      verifyEnvelope(verified.value,scope,trustedPublicKey,statement.count);
      if(!verified.bytes.equals(bytes))throw fail();
      identity=verified.identity;
      expected=next;
      return copy(next);
     }finally{
      if(pendingCreated)await unlink(pending).catch(()=>{});
     }
    }catch(e){
     if(e?.message==='reference receipt CAS conflict'&&!persistenceAttempted)throw e;
     if(e?.message==='reference receipt invalid transition'&&!persistenceAttempted)throw e;
     // No successful operation or retry may follow signer/persistence uncertainty.
     faulted=true;
     throw fail();
    }finally{busy=false;}
   },
   async close(){
    if(closed)return;
    if(busy)throw fail();
    closed=true;
    if(!faulted){try{await verifyLiveEntries();}catch{faulted=true;}}
    await lease.close();
    if(!faulted){
     await unlink(lockPath);
     await dir.sync();
    }
    // Faulted publisher preserves its writer lock: reconciliation must be
    // supervised rather than silently resuming after uncertain writes.
    await dir.close();
   }
  });
 }catch(e){
  if(lease)await lease.close().catch(()=>{});
  await dir.close().catch(()=>{});
  // Caller must not distinguish malformed or rolled-back signed records.
  throw fail();
 }
}


// Read-only triage: never treats a lock as abandoned or authorizes a restart.
export async function inspectReferenceWitnessReceiptRecovery({
 directory,issuer,audience,trustedPublicKey,trustedFloor
}){
 if(typeof directory!=='string'||!isAbsolute(directory)||
  !scopeOk(issuer)||!scopeOk(audience)||!trustedPublicKey||
  !trustedFloor||Object.keys(trustedFloor).sort().join(',')!=='count,headHash'||
  !Number.isSafeInteger(trustedFloor.count)||trustedFloor.count<1||
  trustedFloor.count>8192||!HEX.test(trustedFloor.headHash))throw fail();
 const root=resolve(directory);
 try{
  const dirStat=await lstat(root);
  if(!dirStat.isDirectory()||(dirStat.mode&0o077)!==0||
   (typeof process.getuid==='function'&&dirStat.uid!==process.getuid())||
   await realpath(root)!==root)throw fail();
  const names=(await readdir(root)).sort();
  if(names.some(n=>n!=='signed-witness-receipt.json'&&
   n!=='.receipt-publisher.lock'&&!/^\.receipt-[0-9a-f-]+\.pending$/.test(n)))
   throw fail();
  const {value}=await strictRead(join(root,'signed-witness-receipt.json'));
  const seen=verifyEnvelope(value,{issuer,audience},trustedPublicKey,trustedFloor.count);
  exactFloor(seen,trustedFloor);
  return Object.freeze({
   status:'MANUAL_REVIEW_REQUIRED',
   authenticatedHead:Object.freeze({count:seen.count,headHash:seen.headHash,
    checkpoint:Object.freeze({...seen.checkpoint})}),
   writerLockPresent:names.includes('.receipt-publisher.lock'),
   pendingFiles:Object.freeze(names.filter(n=>n.endsWith('.pending'))),
   automaticRecoveryPermitted:false
  });
 }catch{throw fail();}
}
