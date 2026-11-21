// SINGLE-HOST reference authority for signed G1 REVIEW_ONLY floor publication.
// NOT independently administered, network-addressable or distributed. The
// exact trusted authority state must originate outside this host. Never
// repairs evidence, clears witness locks or authorises operational recovery.
import {createHash} from 'node:crypto';
import {open,lstat,realpath,readdir,unlink} from 'node:fs/promises';
import {constants} from 'node:fs';
import {isAbsolute,join,resolve} from 'node:path';
import {
 canonicalRecoveryFloorPublicationStatement,
 createUnsignedRecoveryFloorAuthorityStatement,
 canonicalRecoveryFloorAuthorityStatement,
 verifySignedRecoveryFloorAuthority,verifyRecoveryFloorPublication
} from './provider-witness-recovery-floor-publication.mjs';

const HEX=/^[0-9a-f]{64}$/,IDENT=/^[0-9a-f]{32}$/,ZERO='0'.repeat(64);
const NONCE=/^[A-Za-z0-9_-]{43}$/;
const validNonce=v=>typeof v==='string'&&NONCE.test(v)&&
 Buffer.from(v,'base64url').length===32&&
 Buffer.from(v,'base64url').toString('base64url')===v;
const fail=()=>Error('reference floor authority unavailable');
const conflict=()=>Error('reference floor authority CAS conflict');
const invalid=()=>Error('reference floor authority invalid publication');
const scopeOk=s=>typeof s==='string'&&s.length>0&&s.length<=512&&
 !/[\x00-\x1f\x7f]/.test(s);
const exact=(obj,fields)=>obj&&typeof obj==='object'&&!Array.isArray(obj)&&
 Object.keys(obj).sort().join(',')===fields.split(',').sort().join(',');
const validSerial=n=>Number.isSafeInteger(n)&&n>=0&&n<Number.MAX_SAFE_INTEGER-2;
const stateValid=s=>exact(s,'serial,headHash,logHash')&&validSerial(s.serial)&&
 typeof s.headHash==='string'&&HEX.test(s.headHash)&&
 typeof s.logHash==='string'&&HEX.test(s.logHash);
const same=(a,b)=>a.serial===b.serial&&a.headHash===b.headHash;
const sameState=(a,b)=>same(a,b)&&a.logHash===b.logHash&&a.count===b.count;
const hash=body=>createHash('sha256').update('verivaro-g1-floor-authority-v1\0')
 .update(Buffer.from(JSON.stringify(body),'utf8')).digest('hex');
const DIR=constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW;
const READ=constants.O_RDONLY|constants.O_NOFOLLOW;
const EXCL=constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW;
const APPEND=constants.O_WRONLY|constants.O_APPEND|constants.O_NOFOLLOW;
const MAX_BYTES=4*1024*1024,MAX_COUNT=8192;
const ENTRY_KEYS='audience,hash,headHash,issuer,kind,previousHash,proposalHash,publicationId,serial,version';
const owned=s=>typeof process.getuid!=='function'||s.uid===process.getuid();
const goodDir=s=>s.isDirectory()&&(s.mode&0o077)===0&&owned(s);
const goodFile=s=>s.isFile()&&s.nlink===1&&(s.mode&0o077)===0&&
 owned(s)&&s.size>=120&&s.size<=MAX_BYTES;
function entry(scope,kind,serial,headHash,publicationId,proposalHash,previousHash){
 const body={version:1,kind,issuer:scope.issuer,audience:scope.audience,
  serial,headHash,publicationId,proposalHash,previousHash};
 return {...body,hash:hash(body)};
}
export function encodeReferenceRecoveryFloorAuthorityGenesis({
 issuer,audience,initialFloor
}={}){
 if(!scopeOk(issuer)||!scopeOk(audience)||
  !exact(initialFloor,'serial,headHash')||
  !validSerial(initialFloor.serial)||!HEX.test(initialFloor.headHash))throw fail();
 const v=entry({issuer,audience},'genesis',initialFloor.serial,
  initialFloor.headHash,null,null,ZERO);
 return Object.freeze({bytes:Buffer.from(JSON.stringify(v)+'\n'),
  trustedAuthorityState:Object.freeze({
   serial:v.serial,headHash:v.headHash,logHash:v.hash
  })});
}
export function verifyReferenceRecoveryFloorAuthorityLog(bytes,{
 issuer,audience,trustedAuthorityState
}={}){
 if(!Buffer.isBuffer(bytes)||bytes.length<120||bytes.length>MAX_BYTES||
  !scopeOk(issuer)||!scopeOk(audience)||!stateValid(trustedAuthorityState))
  throw fail();
 const raw=bytes.toString('utf8');
 if(!Buffer.from(raw,'utf8').equals(bytes)||!raw.endsWith('\n'))throw fail();
 const lines=raw.slice(0,-1).split('\n');
 if(lines.length<1||lines.length>MAX_COUNT)throw fail();
 let prev=ZERO,serial=-1,headHash=null;
 const publications=new Set();
 for(let i=0;i<lines.length;i++){
  if(lines[i].length<120||lines[i].length>2048)throw fail();
  let v;
  try{v=JSON.parse(lines[i]);}catch{throw fail();}
  if(!exact(v,ENTRY_KEYS)||v.version!==1||v.issuer!==issuer||
   v.audience!==audience||v.previousHash!==prev||
   !validSerial(v.serial)||typeof v.headHash!=='string'||
   !HEX.test(v.headHash))throw fail();
  if(i===0){
   if(v.kind!=='genesis'||v.publicationId!==null||
    v.proposalHash!==null)throw fail();
  }else{
   if(v.kind!=='publication'||v.serial!==serial+1||
    v.headHash===headHash||typeof v.publicationId!=='string'||
    !IDENT.test(v.publicationId)||publications.has(v.publicationId)||
    typeof v.proposalHash!=='string'||!HEX.test(v.proposalHash))throw fail();
   publications.add(v.publicationId);
  }
  const canonical=entry({issuer,audience},v.kind,v.serial,v.headHash,
   v.publicationId,v.proposalHash,prev);
  if(canonical.hash!==v.hash||lines[i]!==JSON.stringify(canonical))throw fail();
  serial=v.serial;headHash=v.headHash;prev=v.hash;
 }
 if(serial!==trustedAuthorityState.serial||
  headHash!==trustedAuthorityState.headHash||
  prev!==trustedAuthorityState.logHash)throw fail();
 return Object.freeze({serial,headHash,logHash:prev,count:lines.length});
}
async function checkedRead(path,identity){
 const h=await open(path,READ);
 try{
  const first=await h.stat();
  if(!goodFile(first)||identity&&(first.ino!==identity.ino||
   first.dev!==identity.dev))throw fail();
  const bytes=await h.readFile(),second=await h.stat(),linked=await lstat(path);
  if(!goodFile(second)||!linked.isFile()||linked.nlink!==1||
   bytes.length!==first.size||first.ino!==second.ino||
   first.dev!==second.dev||first.size!==second.size||
   first.mtimeMs!==second.mtimeMs||first.ctimeMs!==second.ctimeMs||
   second.ino!==linked.ino||second.dev!==linked.dev)throw fail();
  return {bytes,identity:{ino:first.ino,dev:first.dev}};
 }finally{await h.close();}
}
const validSignal=s=>s===undefined||s&&typeof s.aborted==='boolean'&&
 typeof s.addEventListener==='function'&&
 typeof s.removeEventListener==='function';
async function signBounded(signReceipt,statement,timeoutMs,externalSignal){
 if(!validSignal(externalSignal)||externalSignal?.aborted)throw fail();
 const controller=new AbortController();
 const signal=externalSignal?AbortSignal.any([controller.signal,externalSignal]):
  controller.signal;
 let timer,onAbort;
 try{
  const aborted=new Promise((_,reject)=>{
   onAbort=()=>reject(fail());
   signal.addEventListener('abort',onAbort,{once:true});
   timer=setTimeout(()=>controller.abort(),timeoutMs);
  });
  const bytes=canonicalRecoveryFloorAuthorityStatement(statement);
  const signature=await Promise.race([
   Promise.resolve().then(()=>{
    if(signal.aborted)throw fail();
    return signReceipt(Buffer.from(bytes),statement,{signal});
   }),aborted
  ]);
  if(signal.aborted)throw fail();
  return {statement,signature};
 }finally{
  clearTimeout(timer);
  signal.removeEventListener('abort',onAbort);
  controller.abort();
 }
}
export async function openReferenceRecoveryFloorAuthority({
 directory,issuer,audience,trustedAuthorityState,
 trustedAuthorityKey,trustedAuthorityKeySchedule,
 trustedCustodianKeys,signReceipt,
 clock=()=>new Date(),signTimeoutMs=2000,receiptValidityMs=10000,
 enableTestFaultInjection=false,faultInjection
}={}){
 if(typeof directory!=='string'||!isAbsolute(directory)||
  !scopeOk(issuer)||!scopeOk(audience)||!stateValid(trustedAuthorityState)||
  Boolean(trustedAuthorityKey)===Boolean(trustedAuthorityKeySchedule)||
  !exact(trustedCustodianKeys,'primary,secondary')||
  typeof signReceipt!=='function'||typeof clock!=='function'||
  !Number.isSafeInteger(signTimeoutMs)||signTimeoutMs<25||
  signTimeoutMs>30000||!Number.isSafeInteger(receiptValidityMs)||
  receiptValidityMs<25||receiptValidityMs>30000||
  (faultInjection!==undefined&&
   (enableTestFaultInjection!==true||typeof faultInjection!=='function')))
  throw fail();
 const root=resolve(directory),scope=Object.freeze({issuer,audience});
 const path=join(root,'recovery-floor-authority.jsonl'),
  lockPath=join(root,'.recovery-floor-authority.lock');
 const dir=await open(root,DIR);
 let lease,closed=false,busy=false,faulted=false;
 try{
  const opened=await dir.stat(),linked=await lstat(root);
  if(!goodDir(opened)||!goodDir(linked)||opened.ino!==linked.ino||
   opened.dev!==linked.dev||await realpath(root)!==root)throw fail();
  const names=await readdir(root);
  if(names.length!==1||names[0]!=='recovery-floor-authority.jsonl')throw fail();
  const initial=await checkedRead(path);
  const pinned=verifyReferenceRecoveryFloorAuthorityLog(initial.bytes,{
   ...scope,trustedAuthorityState
  });
  lease=await open(lockPath,EXCL,0o600);
  await lease.writeFile('reserved\n');await lease.sync();await dir.sync();
  const confirmed=await checkedRead(path,initial.identity);
  const again=verifyReferenceRecoveryFloorAuthorityLog(confirmed.bytes,{
   ...scope,trustedAuthorityState
  });
  if(!sameState(pinned,again))throw fail();
  const identity=initial.identity;
  let expected={...again};
  const usedIds=new Set(confirmed.bytes.toString('utf8').trimEnd()
   .split('\n').slice(1).map(line=>JSON.parse(line).publicationId));
  async function checkEntries(){
   const d=await dir.stat(),linked=await lstat(root),
    l=await lease.stat(),linkedLock=await lstat(lockPath);
   if(!goodDir(d)||!goodDir(linked)||d.ino!==linked.ino||
    d.dev!==linked.dev||!linkedLock.isFile()||linkedLock.nlink!==1||
    (linkedLock.mode&0o077)!==0||!owned(linkedLock)||
    l.ino!==linkedLock.ino||l.dev!==linkedLock.dev)throw fail();
   const entries=(await readdir(root)).sort();
   if(JSON.stringify(entries)!==JSON.stringify([
    '.recovery-floor-authority.lock','recovery-floor-authority.jsonl'
   ]))throw fail();
  }
  async function checked(){
   if(closed||faulted)throw fail();
   try{
    await checkEntries();
    const {bytes}=await checkedRead(path,identity);
    const current=verifyReferenceRecoveryFloorAuthorityLog(bytes,{
     ...scope,trustedAuthorityState:{
      serial:expected.serial,headHash:expected.headHash,
      logHash:expected.logHash
     }
    });
    if(!sameState(current,expected))throw fail();
    return current;
   }catch{faulted=true;throw fail();}
  }
  function timestamp(){
   const time=clock();
   if(!(time instanceof Date)||!Number.isFinite(time.getTime()))throw fail();
   return time.toISOString();
  }
  async function receipt(state,signal,requestNonce){
   if(!validNonce(requestNonce))throw fail();
   const issuedAt=timestamp();
   const expiresAt=new Date(Date.parse(issuedAt)+receiptValidityMs).toISOString();
   const statement=createUnsignedRecoveryFloorAuthorityStatement({
    ...scope,serial:state.serial,headHash:state.headHash,
    requestNonce,issuedAt,expiresAt
   });
   const response=await signBounded(signReceipt,statement,signTimeoutMs,signal);
   verifySignedRecoveryFloorAuthority(response,{
    ...scope,trustedAuthorityKey,trustedAuthorityKeySchedule,
    expectedRequestNonce:requestNonce,
    now:timestamp(),maxReceiptAgeMs:receiptValidityMs
   });
   return response;
  }
  return Object.freeze({
   async read(requestScope,{signal,requestNonce}={}){
    if(closed||faulted||busy||requestScope?.issuer!==issuer||
     requestScope?.audience!==audience||!validSignal(signal)||
     signal?.aborted||!validNonce(requestNonce))throw fail();
    busy=true;
    try{
     const state=await checked();
     const signed=await receipt(state,signal,requestNonce);
     const second=await checked();
     if(!sameState(state,second)||signal?.aborted)throw fail();
     return signed;
    }catch{faulted=true;throw fail();}
    finally{busy=false;}
   },
   async compareAndSwap({issuer:iss,audience:aud,previous,publication,
    consumptionLog,requestNonce}={}, {signal}={}){
    if(closed||faulted||busy||iss!==issuer||aud!==audience||
     !validSignal(signal)||signal?.aborted||!validNonce(requestNonce))throw fail();
    busy=true;
    let started=false;
    try{
     const before=await checked();
     if(!previous||!same(previous,before))throw conflict();
     let proposal;
     try{
      proposal=verifyRecoveryFloorPublication(publication,{
       ...scope,expectedPrevious:{serial:before.serial,headHash:before.headHash},
       trustedCustodianKeys,consumptionLog,now:timestamp()
      });
     }catch{throw invalid();}
     if(usedIds.has(proposal.publicationId))throw conflict();
     if(before.count>=MAX_COUNT||signal?.aborted)throw fail();
     const proposalBytes=canonicalRecoveryFloorPublicationStatement(
      publication.statement);
     const proposalHash=createHash('sha256')
      .update('verivaro-g1-floor-proposal-v1\0')
      .update(proposalBytes).digest('hex');
     const next=entry(scope,'publication',proposal.serial,proposal.headHash,
      proposal.publicationId,proposalHash,before.logHash);
     const line=Buffer.from(JSON.stringify(next)+'\n');
     if(line.length>2048)throw fail();
     const writer=await open(path,APPEND);
     try{
      const st=await writer.stat();
      if(!goodFile(st)||st.ino!==identity.ino||
       st.dev!==identity.dev)throw fail();
      if(signal?.aborted)throw fail();
      started=true;
      await writer.writeFile(line);await writer.sync();await dir.sync();
     }finally{await writer.close();}
     if(enableTestFaultInjection&&faultInjection)
      await faultInjection('after-fsync');
     expected={serial:next.serial,headHash:next.headHash,
      logHash:next.hash,count:before.count+1};
     await checked();
     usedIds.add(proposal.publicationId);
     const signed=await receipt(expected,signal,requestNonce);
     if(signal?.aborted)throw fail();
     return signed;
    }catch(e){
     if(!started&&e?.message===conflict().message)throw e;
     if(!started&&e?.message===invalid().message)throw e;
     faulted=true;throw fail();
    }finally{busy=false;}
   },
   async audit(){
    if(closed||faulted||busy)throw fail();
    return Object.freeze({...await checked()});
   },
   async close(){
    if(closed)return;
    if(busy)throw fail();
    if(!faulted){try{await checked();}catch{faulted=true;}}
    closed=true;
    await lease.close();
    if(!faulted){await unlink(lockPath);await dir.sync();}
    await dir.close();
   }
  });
 }catch{
  if(lease)await lease.close().catch(()=>{});
  await dir.close().catch(()=>{});
  throw fail();
 }
}
