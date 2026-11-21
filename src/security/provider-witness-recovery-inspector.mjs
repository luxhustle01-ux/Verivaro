// Read-only reference reconciliation: journal x signed receipt x independent floor.
// Never grants restart or performs remediation; the trusted floor and public
// key must be obtained outside the witness/publisher administrative domain.
import {open,realpath,lstat,readdir} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,resolve,isAbsolute} from 'node:path';
import {verifyWitnessJournal} from './provider-witness-journal.mjs';
import {inspectReferenceWitnessReceiptRecovery} from './provider-witness-publisher-reference.mjs';

const HEX=/^[0-9a-f]{64}$/;
const scopeOk=s=>typeof s==='string'&&s.length>0&&s.length<=512&&!/[\x00-\x1f\x7f]/.test(s);
const fail=()=>Error('witness recovery evidence inconsistent');
const DIR=constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW;
const READ=constants.O_RDONLY|constants.O_NOFOLLOW;
const MAX=4*1024*1024;
const cpSame=(a,b)=>a?.sequence===b?.sequence&&a?.digest===b?.digest;
const same=(a,b)=>a.count===b.count&&a.headHash===b.headHash&&
 cpSame(a.checkpoint,b.checkpoint);

async function inspectJournal(directory,scope,trustedHead){
 const path=join(directory,'witness-journal.jsonl');
 const dir=await open(directory,DIR);
 try{
  const st=await dir.stat(),linked=await lstat(directory);
  if(!st.isDirectory()||st.dev!==linked.dev||st.ino!==linked.ino||
   (st.mode&0o077)!==0||
   (typeof process.getuid==='function'&&st.uid!==process.getuid())||
   await realpath(directory)!==directory)throw fail();
  const names=(await readdir(directory)).sort();
  if(!names.includes('witness-journal.jsonl')||
   names.some(x=>x!=='witness-journal.jsonl'&&x!=='.witness-writer.lock'))
   throw fail();
  const locked=names.includes('.witness-writer.lock');
  if(locked){
   const lock=await lstat(join(directory,'.witness-writer.lock'));
   if(!lock.isFile()||lock.nlink!==1||(lock.mode&0o077)!==0||
    (typeof process.getuid==='function'&&lock.uid!==process.getuid()))
    throw fail();
  }
  const file=await open(path,READ);
  try{
   const before=await file.stat();
   if(!before.isFile()||before.nlink!==1||before.size<100||
    before.size>MAX||(before.mode&0o077)!==0||
    (typeof process.getuid==='function'&&before.uid!==process.getuid()))
    throw fail();
   const bytes=await file.readFile();
   const after=await file.stat(),linkedFile=await lstat(path);
   if(!linkedFile.isFile()||linkedFile.nlink!==1||
    before.dev!==after.dev||before.ino!==after.ino||
    before.size!==after.size||before.mtimeMs!==after.mtimeMs||
    before.ctimeMs!==after.ctimeMs||
    after.dev!==linkedFile.dev||after.ino!==linkedFile.ino||
    bytes.length!==after.size)throw fail();
   const state=verifyWitnessJournal(bytes,{...scope,trustedHead});
   return {state,bytes,locked};
  }finally{await file.close();}
 }finally{await dir.close();}
}
function publisherSame(a,b){
 const x=a.authenticatedHead,y=b.authenticatedHead;
 return x?.count===y?.count&&x?.headHash===y?.headHash&&
 cpSame(x?.checkpoint,y?.checkpoint)&&
 a.writerLockPresent===b.writerLockPresent&&
 JSON.stringify(a.pendingFiles)===JSON.stringify(b.pendingFiles);
}
export async function inspectReferenceWitnessRecoveryConsistency({
 journalDirectory,publisherDirectory,issuer,audience,trustedPublicKey,trustedFloor
}={}){
 if(typeof journalDirectory!=='string'||!isAbsolute(journalDirectory)||
  typeof publisherDirectory!=='string'||!isAbsolute(publisherDirectory)||
  resolve(journalDirectory)===resolve(publisherDirectory)||
  !scopeOk(issuer)||!scopeOk(audience)||!trustedPublicKey||
  !trustedFloor||typeof trustedFloor!=='object'||Array.isArray(trustedFloor)||
  Object.keys(trustedFloor).sort().join(',')!=='count,headHash'||
  !Number.isSafeInteger(trustedFloor.count)||trustedFloor.count<1||
  trustedFloor.count>8192||typeof trustedFloor.headHash!=='string'||
  !HEX.test(trustedFloor.headHash))throw fail();
 try{
  const scope={issuer,audience},pubArgs={
   directory:publisherDirectory,...scope,trustedPublicKey,trustedFloor
  };
  // Repeated reads detect many interleavings, but are NOT a distributed
  // atomic snapshot or a claim of hostile-administrator resistance.
  const pub1=await inspectReferenceWitnessReceiptRecovery(pubArgs);
  const local1=await inspectJournal(journalDirectory,scope,trustedFloor.headHash);
  const pub2=await inspectReferenceWitnessReceiptRecovery(pubArgs);
  const local2=await inspectJournal(journalDirectory,scope,trustedFloor.headHash);
  if(!publisherSame(pub1,pub2)||!same(local1.state,local2.state)||
   !local1.bytes.equals(local2.bytes)||
   local1.locked!==local2.locked||
   !same(local2.state,pub2.authenticatedHead)||
   local2.state.count!==trustedFloor.count||
   local2.state.headHash!==trustedFloor.headHash)throw fail();
  return Object.freeze({
   status:'MANUAL_REVIEW_REQUIRED',
   evidenceConsistentAtInspection:true,
   authenticatedHead:Object.freeze({
    count:local2.state.count,headHash:local2.state.headHash,
    checkpoint:Object.freeze({...local2.state.checkpoint})
   }),
   writerLocks:Object.freeze({
    journal:local2.locked,publisher:pub2.writerLockPresent
   }),
   pendingPublisherFiles:Object.freeze([...pub2.pendingFiles]),
   automaticRecoveryPermitted:false
  });
 }catch{throw fail();}
}
