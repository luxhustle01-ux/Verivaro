// Single-host, single-active-verifier durable checkpoint store.
// A separately trusted, operator-provisioned starting checkpoint is mandatory.
// Disk persistence does NOT protect against privileged rollback of the volume.
import {open,realpath,rename,unlink} from 'node:fs/promises';
import {constants} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {isAbsolute,resolve,join} from 'node:path';
import {createRotatingProviderVerifier} from './provider-key-rotation.mjs';

const NOFOLLOW=constants.O_NOFOLLOW;
const directoryFlags=constants.O_RDONLY|constants.O_DIRECTORY|NOFOLLOW;
const fileFlags=constants.O_RDONLY|NOFOLLOW;
const openExclusive=constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|NOFOLLOW;
const canonical=(v)=>JSON.stringify(v)+'\n';
const checkpointOk=c=>c&&Number.isSafeInteger(c.sequence)&&c.sequence>=1&&typeof c.digest==='string'&&/^[0-9a-f]{64}$/.test(c.digest);
const scopeOk=s=>typeof s==='string'&&s.length>0&&s.length<=512&&!/[\x00-\x1f\x7f]/.test(s);
const same=(a,b)=>a.sequence===b.sequence&&a.digest===b.digest;
function validateDirectory(stat){
 if(!stat.isDirectory()||(stat.mode&0o077)!==0||
    (typeof process.getuid==='function'&&stat.uid!==process.getuid()))
  throw Error('untrusted checkpoint directory');
}
function validateFile(stat){
 if(!stat.isFile()||(stat.mode&0o077)!==0||stat.nlink!==1||
    stat.size<1||stat.size>2048||
    (typeof process.getuid==='function'&&stat.uid!==process.getuid()))
  throw Error('untrusted checkpoint file');
}
async function readStrict(path,issuer,audience){
 const file=await open(path,fileFlags);
 try{
  const before=await file.stat();validateFile(before);
  const bytes=await file.readFile();
  const after=await file.stat();
  if(bytes.length!==before.size||after.size!==before.size||after.mtimeMs!==before.mtimeMs)
   throw Error('checkpoint changed during read');
  const raw=bytes.toString('utf8'),record=JSON.parse(raw);
  if(!record||typeof record!=='object'||Array.isArray(record)||
   Object.keys(record).sort().join(',')!=='audience,digest,issuer,sequence,version'||
   record.version!==1||record.issuer!==issuer||record.audience!==audience||
   !checkpointOk(record)||raw!==canonical(record))
   throw Error('invalid checkpoint record');
  return Object.freeze({sequence:record.sequence,digest:record.digest});
 }finally{await file.close();}
}
async function writeExclusive(path,contents){
 const fh=await open(path,openExclusive,0o600);
 try{await fh.writeFile(contents);await fh.sync();}finally{await fh.close();}
}

export async function openFileProviderCheckpointStore({directory,issuer,audience}){
 if(typeof directory!=='string'||!isAbsolute(directory)||!scopeOk(issuer)||!scopeOk(audience))
  throw Error('invalid checkpoint store configuration');
 const absolute=resolve(directory),dir=await open(absolute,directoryFlags);
 let session,closed=false,busy=false,bound=false;
 const verifierCapability=Symbol('bound provider checkpoint verifier');
 const dataPath=join(absolute,'provider-keyset-checkpoint.json');
 const lockPath=join(absolute,'.provider-keyset-instance.lock');
 try{
  validateDirectory(await dir.stat());
  if(await realpath(absolute)!==absolute)throw Error('checkpoint directory symlink denied');
  // Refuse abandoned locks: a crash requires explicit operator reconciliation.
  session=await open(lockPath,openExclusive,0o600);
  await session.writeFile('locked\n');await session.sync();await dir.sync();
  const store={
   async read(){
    if(closed)throw Error('checkpoint store closed');
    return readStrict(dataPath,issuer,audience);
   },
   async compareAndSwap(previous,next,capability){
    if(closed)throw Error('checkpoint store closed');
    // Once a verifier is bound, only its private persistence closure can
    // change the checkpoint. Otherwise a second caller could advance disk
    // while the active verifier keeps trusting a stale in-memory keyset.
    if(bound&&capability!==verifierCapability)throw Error('checkpoint store reserved for bound verifier');
    if(busy)throw Error('checkpoint store busy');
    if(!checkpointOk(previous)||!checkpointOk(next)||next.sequence<=previous.sequence)
     throw Error('invalid checkpoint advance');
    busy=true;
    try{
    const actual=await readStrict(dataPath,issuer,audience);
    if(!same(actual,previous))throw Error('checkpoint conflict or rollback');
    const pending=join(absolute,'.provider-keyset-'+randomUUID()+'.pending');
    const record={version:1,issuer,audience,sequence:next.sequence,digest:next.digest};
    let tmp=false;
    try{
     await writeExclusive(pending,canonical(record));tmp=true;
     await rename(pending,dataPath);tmp=false;
     await dir.sync(); // Persist rename and new directory entry.
     const committed=await readStrict(dataPath,issuer,audience);
     if(!same(committed,next))throw Error('checkpoint persistence mismatch');
     return committed;
    }finally{if(tmp)await unlink(pending).catch(()=>{});}
    }finally{busy=false;}
   },
   bindVerifier(){
    if(closed||busy||bound)throw Error('checkpoint verifier already bound or store unavailable');
    bound=true;
    return (previous,next)=>store.compareAndSwap(previous,next,verifierCapability);
   },
   isOpen(){return !closed;},
   async close(){
    if(closed)return;
    if(busy)throw Error('checkpoint rotation pending');
    closed=true;
    // Keep lock on any unsafe cleanup error. Operators must verify state.
    await session.close();session=undefined;
    await unlink(lockPath);await dir.sync();await dir.close();
   }
  };
  // Refuse an absent, malformed, mismatched or unsafe initial trust anchor.
  await store.read();
  return Object.freeze(store);
 }catch(e){
  // If initialization fails, never silently clear an existing or uncertain
  // lock: fail closed and require operator examination of the directory.
  if(session)await session.close().catch(()=>{});
  await dir.close().catch(()=>{});
  throw e;
 }
}

// A new process MUST read its operator-provisioned trusted checkpoint from disk.
// A stale catalogue or unverified checkpoint cannot be passed as an API argument.
export async function openFileBackedProviderVerifier({store,...config}){
 if(!store||typeof store.read!=='function'||typeof store.bindVerifier!=='function'||
    typeof store.isOpen!=='function'||!store.isOpen())
  throw Error('active checkpoint store required');
 const checkpoint=await store.read();
 // Validate the signed catalogue BEFORE claiming the one allowed verifier.
 // A rejected stale catalogue may then be retried safely against the same
 // checkpoint; a successfully bound verifier cannot be duplicated.
 let persist;
 const inner=createRotatingProviderVerifier({...config,checkpoint,
  persistCheckpoint:(previous,next)=>{
   if(typeof persist!=='function')throw Error('checkpoint verifier not bound');
   return persist(previous,next);
  }});
 persist=store.bindVerifier();
 return Object.freeze({
  issuer:inner.issuer,audience:inner.audience,
  verify(token,now){
   if(!store.isOpen())throw Error('checkpoint store closed');
   return inner.verify(token,now);
  },
  rotate(bytes,signature,anchor){
   if(!store.isOpen())throw Error('checkpoint store closed');
   return inner.rotate(bytes,signature,anchor);
  }
 });
}
