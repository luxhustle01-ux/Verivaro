// Offline, independently pinned Ed25519 release attestation. No embedded trusted keys.
import {createHash,createPublicKey,verify as verifySignature,timingSafeEqual} from 'node:crypto';
import {TextDecoder} from 'node:util';
const fail=(msg)=>{throw Error('release attestation rejected: '+msg);};
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const oid=x=>typeof x==='string'&&/^[a-f0-9]{40}$/.test(x);
const exact=(obj,keys)=>obj&&typeof obj==='object'&&!Array.isArray(obj)&&
 Object.keys(obj).sort().join(',')===keys.slice().sort().join(',');
const canonical=x=>Buffer.from(JSON.stringify(x)+'\n','utf8');
function parse(bytes,limit){
 if(!Buffer.isBuffer(bytes)||bytes.length<3||bytes.length>limit)fail('invalid JSON length');
 let obj,text;
 try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);obj=JSON.parse(text);}
 catch{fail('invalid UTF-8 or JSON');}
 if(!canonical(obj).equals(bytes))fail('non-canonical or ambiguous JSON');
 return obj;
}
const pathOK=x=>typeof x==='string'&&
 /^(?:db\/migrations\/[0-9]{4}_[a-z0-9_]+\.sql|(?:src|scripts|db|\.github|docs)\/[a-zA-Z0-9_./-]+)$/.test(x)&&
 !x.split('/').some(p=>p==='.'||p==='..'||!p);
export function ledgerHeadFor(files){
 let previous='0'.repeat(64);
 let n=0;
 for(const f of files){
  if(!f.path.startsWith('db/migrations/'))continue;
  n++;
  if(f.path.slice(14,18)!==String(n).padStart(4,'0'))fail('migration order');
  previous=hash(Buffer.from(['VV_LEDGER_V1',n,f.path,f.sha256,previous].join('\n')));
 }
 if(!n)fail('missing migrations');
 return previous;
}
export function makeMigrationReleaseManifest({sequence,sourceCommit,files}){
 if(!Number.isSafeInteger(sequence)||sequence<1||!oid(sourceCommit)||
  !Array.isArray(files)||files.length<1||files.length>600)fail('invalid release manifest inputs');
 const seen=new Set();
 const entries=files.map(f=>{
  if(!exact(f,['path','bytes'])||!pathOK(f.path)||!Buffer.isBuffer(f.bytes)||
   f.bytes.length<1||f.bytes.length>2*1024*1024||seen.has(f.path))
   fail('invalid or duplicate file');
  seen.add(f.path);
  return {path:f.path,byteLength:f.bytes.length,sha256:hash(f.bytes)};
 });
 return canonical({schemaVersion:1,type:'VERIVARO_MIGRATION_RELEASE_V1',
  repository:'SCSoftwareVentures/Verivaro',sequence,sourceCommit,
  ledgerHead:ledgerHeadFor(entries),productionApproved:false,files:entries});
}
function validateManifest(m,expectedPaths){
 if(!exact(m,['schemaVersion','type','repository','sequence','sourceCommit','ledgerHead',
  'productionApproved','files'])||
  m.schemaVersion!==1||m.type!=='VERIVARO_MIGRATION_RELEASE_V1'||
  m.repository!=='SCSoftwareVentures/Verivaro'||
  !Number.isSafeInteger(m.sequence)||m.sequence<1||!oid(m.sourceCommit)||
  !hex(m.ledgerHead)||m.productionApproved!==false||
  !Array.isArray(expectedPaths)||expectedPaths.length<1||
  !Array.isArray(m.files)||m.files.length!==expectedPaths.length)fail('manifest contract');
 for(let i=0;i<m.files.length;i++){
  const f=m.files[i];
  if(!exact(f,['path','byteLength','sha256'])||
   f.path!==expectedPaths[i]||!pathOK(f.path)||!hex(f.sha256)||
   !Number.isSafeInteger(f.byteLength)||f.byteLength<1||f.byteLength>2*1024*1024)
   fail('manifest path, size or hash');
 }
 if(ledgerHeadFor(m.files)!==m.ledgerHead)fail('migration ledger head');
}
function decodeBase64(x){
 if(typeof x!=='string'||!/^[A-Za-z0-9+/]{86}==$/.test(x))fail('invalid Ed25519 signature encoding');
 const data=Buffer.from(x,'base64');
 if(data.length!==64||data.toString('base64')!==x)fail('invalid Ed25519 signature bytes');
 return data;
}
export function releaseSigningPayload(manifestBytes){
 if(!Buffer.isBuffer(manifestBytes))fail('missing manifest bytes');
 return Buffer.concat([Buffer.from('VERIVARO_MIGRATION_RELEASE_ED25519_V1\0'),manifestBytes]);
}
export function verifyMigrationReleaseAttestation({
 manifestBytes,policyBytes,pinnedPolicySha256,signatures,expectedPaths,filesByPath
}){
 if(!hex(pinnedPolicySha256)||!Buffer.isBuffer(policyBytes)||
  !timingSafeEqual(Buffer.from(hash(policyBytes),'hex'),Buffer.from(pinnedPolicySha256,'hex')))
  fail('externally pinned trust policy mismatch');
 const policy=parse(policyBytes,65536);
 if(!exact(policy,['schemaVersion','type','minimumSequence','threshold','keys'])||
  policy.schemaVersion!==1||policy.type!=='VERIVARO_EXTERNAL_RELEASE_TRUST_V1'||
  !Number.isSafeInteger(policy.minimumSequence)||policy.minimumSequence<1||
  policy.threshold!==2||!Array.isArray(policy.keys)||
  policy.keys.length<2||policy.keys.length>12)fail('invalid trust policy');
 const byId=new Map(),roles=new Set();
 for(const key of policy.keys){
  if(!exact(key,['id','role','publicKeyPem','revoked'])||
   !/^[a-z0-9_-]{4,64}$/.test(key.id)||
   !['owner','independent-reviewer'].includes(key.role)||
   typeof key.publicKeyPem!=='string'||key.publicKeyPem.length>2048||
   typeof key.revoked!=='boolean'||byId.has(key.id))
   fail('invalid trust policy key');
  let pub;
  try{pub=createPublicKey(key.publicKeyPem);}catch{fail('unparseable trust key');}
  if(pub.asymmetricKeyType!=='ed25519')fail('trust key is not Ed25519');
  byId.set(key.id,{...key,pub});roles.add(key.role);
 }
 if(!roles.has('owner')||!roles.has('independent-reviewer'))fail('missing independent signer role');
 const manifest=parse(manifestBytes,1024*1024);
 validateManifest(manifest,expectedPaths);
 if(manifest.sequence<policy.minimumSequence)fail('release sequence below independently pinned floor');
 if(!(filesByPath instanceof Map)||filesByPath.size!==expectedPaths.length)
  fail('unbound source file set');
 for(const f of manifest.files){
  const bytes=filesByPath.get(f.path);
  if(!Buffer.isBuffer(bytes)||bytes.length!==f.byteLength||hash(bytes)!==f.sha256)
   fail('source bytes differ from signed manifest');
 }
 if(!Array.isArray(signatures)||signatures.length!==2)fail('two independent signatures required');
 const used=new Set(),approvedRoles=new Set(),releaseDigest=hash(manifestBytes);
 for(const entryBytes of signatures){
  const sig=parse(entryBytes,8192);
  if(!exact(sig,['schemaVersion','type','keyId','manifestSha256','signature'])||
   sig.schemaVersion!==1||sig.type!=='VERIVARO_ED25519_RELEASE_SIGNATURE_V1'||
   !hex(sig.manifestSha256)||sig.manifestSha256!==releaseDigest||
   used.has(sig.keyId))fail('signature envelope');
  const trusted=byId.get(sig.keyId);
  if(!trusted||trusted.revoked||approvedRoles.has(trusted.role))fail('untrusted or duplicate signer role');
  const raw=decodeBase64(sig.signature);
  if(!verifySignature(null,releaseSigningPayload(manifestBytes),trusted.pub,raw))
   fail('invalid Ed25519 signature');
  used.add(sig.keyId);approvedRoles.add(trusted.role);
 }
 if(!approvedRoles.has('owner')||!approvedRoles.has('independent-reviewer'))
  fail('independent signer separation not satisfied');
 return Object.freeze({cryptographicallyVerified:true,releaseSequence:manifest.sequence,
  manifestSha256:releaseDigest,ledgerHead:manifest.ledgerHead,fileCount:manifest.files.length,
  signerRoles:['owner','independent-reviewer'],
  independentlyCustodied:false,productionApproved:false});
}
export {canonical as canonicalReleaseJson,hash as releaseSha256};
