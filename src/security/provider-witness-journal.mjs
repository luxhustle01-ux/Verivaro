// Isolated reference implementation of a witnessed, hash-chained checkpoint log.
// This is NOT a production independent witness. The audit head MUST be retained
// and authenticated outside this host, file system and administrative domain.
import {createHash} from 'node:crypto';
import {open,realpath} from 'node:fs/promises';
import {constants} from 'node:fs';
import {isAbsolute,join,resolve} from 'node:path';

const ZERO='0'.repeat(64);
const HEX=/^[a-f0-9]{64}$/;
const SCOPE=s=>typeof s==='string'&&s.length>0&&s.length<=512&&!/[\x00-\x1f\x7f]/.test(s);
const CP=c=>c&&typeof c==='object'&&!Array.isArray(c)&&
 Object.keys(c).sort().join(',')==='digest,sequence'&&
 Number.isSafeInteger(c.sequence)&&c.sequence>=1&&HEX.test(c.digest);
const SAME=(a,b)=>CP(a)&&CP(b)&&a.sequence===b.sequence&&a.digest===b.digest;
const fail=()=>Error('witness audit integrity unavailable');
const H=raw=>createHash('sha256').update('verivaro-witness-journal-v1\0').update(raw).digest('hex');
function record(index,scope,previous,next,previousHash){
 const body={version:1,index,issuer:scope.issuer,audience:scope.audience,
  previous,next,previousHash};
 return {...body,hash:H(Buffer.from(JSON.stringify(body),'utf8'))};
}
const snapshot=cp=>Object.freeze({sequence:cp.sequence,digest:cp.digest});
const MAX_BYTES=4*1024*1024;
export function encodeWitnessGenesis({issuer,audience,checkpoint}){
 if(!SCOPE(issuer)||!SCOPE(audience)||!CP(checkpoint))throw fail();
 const entry=record(0,{issuer,audience},null,snapshot(checkpoint),ZERO);
 return Object.freeze({bytes:Buffer.from(JSON.stringify(entry)+'\n'),headHash:entry.hash});
}
export function verifyWitnessJournal(bytes,{issuer,audience,trustedHead}){
 if(!Buffer.isBuffer(bytes)||bytes.length<100||bytes.length>MAX_BYTES||
  !SCOPE(issuer)||!SCOPE(audience)||typeof trustedHead!=='string'||!HEX.test(trustedHead))
  throw fail();
 const raw=bytes.toString('utf8');
 if(!Buffer.from(raw,'utf8').equals(bytes)||!raw.endsWith('\n'))throw fail();
 const lines=raw.slice(0,-1).split('\n');
 if(lines.length<1||lines.length>8192||lines.some(s=>!s||s.length>2048))throw fail();
 const scope={issuer,audience};
 let previous=null,previousHash=ZERO;
 for(let i=0;i<lines.length;i++){
  let e;
  try{e=JSON.parse(lines[i]);}catch{throw fail();}
  if(!e||typeof e!=='object'||Array.isArray(e)||
   Object.keys(e).sort().join(',')!=='audience,hash,index,issuer,next,previous,previousHash,version'||
   e.index!==i||e.version!==1||e.issuer!==issuer||e.audience!==audience||
   e.previousHash!==previousHash||!CP(e.next)||
   (i===0?e.previous!==null:
    !SAME(e.previous,previous)||e.next.sequence<=previous.sequence))throw fail();
  const expected=record(i,scope,previous,snapshot(e.next),previousHash);
  if(e.hash!==expected.hash||lines[i]!==JSON.stringify(expected))throw fail();
  previous=snapshot(e.next);previousHash=e.hash;
 }
 if(previousHash!==trustedHead)throw fail();
 return Object.freeze({checkpoint:previous,headHash:previousHash,count:lines.length});
}
const DIR=constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW;
const FILE=constants.O_RDONLY|constants.O_NOFOLLOW;
const LOCK=constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW;
const APPEND=constants.O_WRONLY|constants.O_APPEND|constants.O_NOFOLLOW;
function goodFile(s,min=1){
 return s.isFile()&&s.nlink===1&&(s.mode&0o077)===0&&s.size>=min&&s.size<=MAX_BYTES&&
  (typeof process.getuid!=='function'||s.uid===process.getuid());
}
async function journalRead(path,identity){
 const h=await open(path,FILE);
 try{
  const first=await h.stat();
  if(!goodFile(first)||identity&&(first.ino!==identity.ino||first.dev!==identity.dev))throw fail();
  const bytes=await h.readFile();
  const second=await h.stat();
  if(bytes.length!==first.size||first.size!==second.size||first.mtimeMs!==second.mtimeMs||
   first.ino!==second.ino||first.dev!==second.dev)throw fail();
  return {bytes,identity:{ino:first.ino,dev:first.dev}};
 }finally{await h.close();}
}
export async function openReferenceWitnessJournal({directory,issuer,audience,trustedHead}){
 if(typeof directory!=='string'||!isAbsolute(directory)||
  !SCOPE(issuer)||!SCOPE(audience)||typeof trustedHead!=='string'||!HEX.test(trustedHead))
  throw fail();
 const absolute=resolve(directory),path=join(absolute,'witness-journal.jsonl'),
  lockPath=join(absolute,'.witness-writer.lock'),scope=Object.freeze({issuer,audience});
 const dir=await open(absolute,DIR);
 let lock,closed=false,busy=false,faulted=false;
 try{
  const stat=await dir.stat();
  if(!stat.isDirectory()||(stat.mode&0o077)!==0||
   (typeof process.getuid==='function'&&stat.uid!==process.getuid())||
   await realpath(absolute)!==absolute)throw fail();
  // Verify the externally retained head before taking an exclusive writer lock.
  const initial=await journalRead(path);
  verifyWitnessJournal(initial.bytes,{...scope,trustedHead});
  lock=await open(lockPath,LOCK,0o600);
  await lock.writeFile('reserved\n');await lock.sync();await dir.sync();
  const again=await journalRead(path,initial.identity);
  verifyWitnessJournal(again.bytes,{...scope,trustedHead});
  const identity=initial.identity;
  let expectedHead=trustedHead;
  async function checked(){
   if(closed||faulted)throw fail();
   try{
    const {bytes}=await journalRead(path,identity);
    return verifyWitnessJournal(bytes,{...scope,trustedHead:expectedHead});
   }catch{faulted=true;throw fail();}
  }
  return Object.freeze({
   async read(requestScope){
    if(requestScope?.issuer!==issuer||requestScope?.audience!==audience||busy)throw fail();
    return (await checked()).checkpoint;
   },
   async compareAndSwap({issuer:iss,audience:aud,previous,next}){
    if(iss!==issuer||aud!==audience||!CP(previous)||!CP(next)||
     next.sequence<=previous.sequence||closed||faulted||busy)throw fail();
    busy=true;
    try{
     const state=await checked();
     if(!SAME(state.checkpoint,previous))throw Error('witness compare-and-swap conflict');
     const entry=record(state.count,scope,snapshot(previous),snapshot(next),state.headHash);
     const contents=Buffer.from(JSON.stringify(entry)+'\n');
     if(state.count>=8192||contents.length>2048)throw fail();
     // A single writer holds the process-exclusion lock. Never acknowledge
     // prior to write + fsync; partial/uncertain append permanently faults.
     let began=false;
     try{
      const handle=await open(path,APPEND);
      try{
       const fs=await handle.stat();
       if(!goodFile(fs)||fs.ino!==identity.ino||fs.dev!==identity.dev)throw fail();
       began=true;
       await handle.writeFile(contents);
       await handle.sync();
      }finally{await handle.close();}
      expectedHead=entry.hash;
      const verified=await checked();
      if(!SAME(verified.checkpoint,next))throw fail();
      return verified.checkpoint;
     }catch{
      faulted=true;
      throw fail();
     }
    }finally{busy=false;}
   },
   async audit(){
    if(busy)throw fail();
    const state=await checked();
    return Object.freeze({...state});
   },
   async close(){
    if(closed)return;
    if(busy)throw fail();
    closed=true;
    await lock.close();
    await (await import('node:fs/promises')).unlink(lockPath);
    await dir.sync();await dir.close();
   }
  });
 }catch(e){
  // On a post-lock uncertainty, preserve the abandoned lock for investigation.
  // Safe cleanup is a separate operator-approved procedure, not auto-repair.
  if(lock)await lock.close().catch(()=>{});
  await dir.close().catch(()=>{});
  throw e;
 }
}
