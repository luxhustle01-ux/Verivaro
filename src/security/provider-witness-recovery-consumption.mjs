// Single-host reference consumption register for signed REVIEW_ONLY evidence.
// NOT an independently administered or distributed replay-protection service.
// The pinned head and serial must come from a separate trusted domain.
// This module never repairs the journal, removes recovery locks or restarts.
import {createHash} from 'node:crypto';
import {open,lstat,readdir,realpath,unlink} from 'node:fs/promises';
import {constants} from 'node:fs';
import {isAbsolute,resolve,join} from 'node:path';
import {verifyRecoveryReviewApproval} from './provider-witness-recovery-approval.mjs';

const HEX=/^[0-9a-f]{64}$/;
const IDENT=/^[0-9a-f]{32}$/;
const ZERO='0'.repeat(64);
const fail=()=>Error('recovery review consumption unavailable');
const validScope=s=>typeof s==='string'&&s.length>0&&s.length<=512&&
 !/[\x00-\x1f\x7f]/.test(s);
const validSerial=s=>Number.isSafeInteger(s)&&s>=0&&s<Number.MAX_SAFE_INTEGER-2;
const DIR=constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW;
const READ=constants.O_RDONLY|constants.O_NOFOLLOW;
const EXCLUSIVE=constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW;
const APPEND=constants.O_WRONLY|constants.O_APPEND|constants.O_NOFOLLOW;
const MAX_RECORDS=8192,MAX_BYTES=4*1024*1024;
const RECORD_KEYS='approvalId,audience,evidenceHash,hash,issuer,kind,previousHash,serial,version';
const hash=bytes=>createHash('sha256').update('verivaro-g1-consumed-review-v1\0')
 .update(bytes).digest('hex');
function makeRecord(scope,kind,serial,approvalId,evidenceHash,previousHash){
 const body={version:1,kind,issuer:scope.issuer,audience:scope.audience,
  serial,approvalId,evidenceHash,previousHash};
 return {...body,hash:hash(Buffer.from(JSON.stringify(body),'utf8'))};
}
const same=(a,b)=>a.serial===b.serial&&a.count===b.count&&a.headHash===b.headHash;
const goodDirectory=s=>s.isDirectory()&&(s.mode&0o077)===0&&
 (typeof process.getuid!=='function'||s.uid===process.getuid());
const goodFile=s=>s.isFile()&&s.nlink===1&&(s.mode&0o077)===0&&
 s.size>=100&&s.size<=MAX_BYTES&&
 (typeof process.getuid!=='function'||s.uid===process.getuid());

export function encodeReferenceRecoveryApprovalGenesis({issuer,audience,serial=0}={}){
 if(!validScope(issuer)||!validScope(audience)||!validSerial(serial))throw fail();
 const genesis=makeRecord({issuer,audience},'genesis',serial,null,null,ZERO);
 return Object.freeze({bytes:Buffer.from(JSON.stringify(genesis)+'\n'),
  headHash:genesis.hash});
}
export function verifyReferenceRecoveryApprovalLog(bytes,{issuer,audience,trustedHead}={}){
 if(!Buffer.isBuffer(bytes)||bytes.length<100||bytes.length>MAX_BYTES||
  !validScope(issuer)||!validScope(audience)||typeof trustedHead!=='string'||
  !HEX.test(trustedHead))throw fail();
 const raw=bytes.toString('utf8');
 if(!Buffer.from(raw,'utf8').equals(bytes)||!raw.endsWith('\n'))throw fail();
 const lines=raw.slice(0,-1).split('\n');
 if(lines.length<1||lines.length>MAX_RECORDS)throw fail();
 let serial=-1,previousHash=ZERO;
 const usedIds=new Set();
 for(let i=0;i<lines.length;i++){
  if(!lines[i]||lines[i].length>2048)throw fail();
  let e;
  try{e=JSON.parse(lines[i]);}catch{throw fail();}
  if(!e||typeof e!=='object'||Array.isArray(e)||
   Object.keys(e).sort().join(',')!==RECORD_KEYS||
   e.version!==1||e.issuer!==issuer||e.audience!==audience||
   e.previousHash!==previousHash||!validSerial(e.serial))throw fail();
  if(i===0){
   if(e.kind!=='genesis'||e.approvalId!==null||e.evidenceHash!==null)
    throw fail();
  }else{
   if(e.kind!=='consume'||e.serial!==serial+1||
    typeof e.approvalId!=='string'||!IDENT.test(e.approvalId)||
    typeof e.evidenceHash!=='string'||!HEX.test(e.evidenceHash)||
    usedIds.has(e.approvalId))throw fail();
   usedIds.add(e.approvalId);
  }
  const expected=makeRecord({issuer,audience},e.kind,e.serial,e.approvalId,
   e.evidenceHash,previousHash);
  if(e.hash!==expected.hash||JSON.stringify(expected)!==lines[i])throw fail();
  serial=e.serial;previousHash=e.hash;
 }
 if(previousHash!==trustedHead)throw fail();
 return Object.freeze({serial,count:lines.length,headHash:previousHash});
}
async function verifiedFileRead(path,identity){
 const f=await open(path,READ);
 try{
  const before=await f.stat();
  if(!goodFile(before)||identity&&(before.ino!==identity.ino||
   before.dev!==identity.dev))throw fail();
  const bytes=await f.readFile(),after=await f.stat(),linked=await lstat(path);
  if(!goodFile(after)||!linked.isFile()||linked.nlink!==1||
   bytes.length!==before.size||before.size!==after.size||
   before.dev!==after.dev||before.ino!==after.ino||
   before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs||
   linked.ino!==after.ino||linked.dev!==after.dev)throw fail();
  return {bytes,identity:{ino:before.ino,dev:before.dev}};
 }finally{await f.close();}
}
export async function openReferenceRecoveryApprovalConsumption({
 directory,issuer,audience,trustedRegisterFloor,trustedReviewerKeys,
 trustedFloor,clock=()=>new Date(),
 enableTestFaultInjection=false,faultInjection
}={}){
 if(typeof directory!=='string'||!isAbsolute(directory)||
  !validScope(issuer)||!validScope(audience)||
  !trustedRegisterFloor||typeof trustedRegisterFloor!=='object'||
  Array.isArray(trustedRegisterFloor)||
  Object.keys(trustedRegisterFloor).sort().join(',')!=='headHash,serial'||
  !validSerial(trustedRegisterFloor.serial)||
  typeof trustedRegisterFloor.headHash!=='string'||
  !HEX.test(trustedRegisterFloor.headHash)||!trustedReviewerKeys||
  !trustedFloor||typeof clock!=='function'||
  (faultInjection!==undefined&&
   (enableTestFaultInjection!==true||typeof faultInjection!=='function')))
  throw fail();
 const root=resolve(directory),scope=Object.freeze({issuer,audience});
 const path=join(root,'recovery-review-consumption.jsonl');
 const lockPath=join(root,'.recovery-review-consumption.lock');
 const dir=await open(root,DIR);
 let lease,closed=false,faulted=false,writing=false;
 try{
  const ds=await dir.stat(),linked=await lstat(root);
  if(!goodDirectory(ds)||!goodDirectory(linked)||
   ds.ino!==linked.ino||ds.dev!==linked.dev||
   await realpath(root)!==root)throw fail();
  const initialNames=await readdir(root);
  if(initialNames.length!==1||
   initialNames[0]!=='recovery-review-consumption.jsonl')throw fail();
  const initial=await verifiedFileRead(path);
  const pinned=verifyReferenceRecoveryApprovalLog(initial.bytes,{
   ...scope,trustedHead:trustedRegisterFloor.headHash
  });
  if(pinned.serial!==trustedRegisterFloor.serial)throw fail();
  lease=await open(lockPath,EXCLUSIVE,0o600);
  await lease.writeFile('reserved\n');await lease.sync();await dir.sync();
  const second=await verifiedFileRead(path,initial.identity);
  const verified=verifyReferenceRecoveryApprovalLog(second.bytes,{
   ...scope,trustedHead:trustedRegisterFloor.headHash
  });
  if(!same(pinned,verified))throw fail();
  const identity=initial.identity;
  let expected=Object.freeze({...verified});
  const usedIds=new Set(second.bytes.toString('utf8').trimEnd().split('\n')
   .slice(1).map(line=>JSON.parse(line).approvalId));
  async function validateLease(){
   const ds=await dir.stat(),link=await lstat(root);
   const ld=await lease.stat(),lock=await lstat(lockPath);
   if(!goodDirectory(ds)||!goodDirectory(link)||
    ds.ino!==link.ino||ds.dev!==link.dev||
    !lock.isFile()||lock.nlink!==1||(lock.mode&0o077)!==0||
    lock.ino!==ld.ino||lock.dev!==ld.dev||
    (typeof process.getuid==='function'&&lock.uid!==process.getuid()))throw fail();
   const names=(await readdir(root)).sort();
   if(JSON.stringify(names)!==JSON.stringify([
    '.recovery-review-consumption.lock','recovery-review-consumption.jsonl'
   ]))throw fail();
  }
  async function checked(){
   if(closed||faulted)throw fail();
   try{
    await validateLease();
    const {bytes}=await verifiedFileRead(path,identity);
    const value=verifyReferenceRecoveryApprovalLog(bytes,{
     ...scope,trustedHead:expected.headHash
    });
    if(!same(value,expected))throw fail();
    return value;
   }catch{faulted=true;throw fail();}
  }
  return Object.freeze({
   async audit(){
    if(writing||closed||faulted)throw fail();
    return Object.freeze({...await checked()});
   },
   async consume({envelope,assessment,expectedApprovalId}={}){
    if(writing||closed||faulted)throw fail();
    writing=true;
    let writeStarted=false;
    try{
     const before=await checked(),now=clock();
     if(!(now instanceof Date)||!Number.isFinite(now.getTime()))throw fail();
     let approval;
     try{
      approval=verifyRecoveryReviewApproval(envelope,{
       assessment,...scope,trustedFloor,trustedReviewerKeys,
       externalConsumedSerial:before.serial,expectedApprovalId,
       now:now.toISOString()
      });
     }catch{
      // A rejected request did not touch disk or external authority.
      throw Error('recovery approval consumption conflict');
     }
     // Serial progression alone is insufficient: one incident approval ID
     // must not become reusable under a fresh signed serial.
     if(usedIds.has(approval.approvalId))
      throw Error('recovery approval consumption conflict');
     if(before.count>=MAX_RECORDS)throw fail();
     const entry=makeRecord(scope,'consume',approval.serial,approval.approvalId,
      approval.evidenceHash,before.headHash);
     const line=Buffer.from(JSON.stringify(entry)+'\n');
     if(line.length>2048)throw fail();
     const w=await open(path,APPEND);
     try{
      const st=await w.stat();
      if(!goodFile(st)||st.dev!==identity.dev||
       st.ino!==identity.ino)throw fail();
      writeStarted=true;
      await w.writeFile(line);await w.sync();
     }finally{await w.close();}
     if(enableTestFaultInjection&&faultInjection){
      await faultInjection('after-log-fsync');
     }
     expected=Object.freeze({serial:approval.serial,headHash:entry.hash,
      count:before.count+1});
     await checked();
     usedIds.add(approval.approvalId);
     return Object.freeze({
      decision:'REVIEW_APPROVAL_CONSUMED_ONLY',serial:approval.serial,
      registerHeadHash:entry.hash,approvalId:approval.approvalId,
      evidenceHash:approval.evidenceHash,automaticRecoveryPermitted:false,
      manualReconciliationRequired:true
     });
    }catch(e){
     if(!writeStarted&&e?.message==='recovery approval consumption conflict')throw e;
     faulted=true;
     throw fail();
    }finally{writing=false;}
   },
   async close(){
    if(closed)return;
    if(writing)throw fail();
    if(!faulted){try{await checked();}catch{faulted=true;}}
    closed=true;
    await lease.close();
    if(!faulted){await unlink(lockPath);await dir.sync();}
    // A faulted or crashed writer leaves its lock for explicit forensic review.
    await dir.close();
   }
  });
 }catch{
  if(lease)await lease.close().catch(()=>{});
  await dir.close().catch(()=>{});
  throw fail();
 }
}
