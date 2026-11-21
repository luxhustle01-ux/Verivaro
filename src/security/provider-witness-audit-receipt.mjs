// Offline receipt contract. Signing MUST take place in a separately governed
// independent anchoring system. No signing private keys live in this module.
import {createPublicKey,createHash,verify} from 'node:crypto';

const HEX=/^[a-f0-9]{64}$/;
const fail=()=>{throw Error('witness audit receipt verification failed');};
const validScope=s=>typeof s==='string'&&s.length>0&&s.length<=512&&!/[\x00-\x1f\x7f]/.test(s);
const validCp=c=>c&&typeof c==='object'&&!Array.isArray(c)&&
 Object.keys(c).sort().join(',')==='digest,sequence'&&
 Number.isSafeInteger(c.sequence)&&c.sequence>=1&&
 typeof c.digest==='string'&&HEX.test(c.digest);
const date=v=>typeof v==='string'&&Number.isFinite(Date.parse(v))&&
 new Date(v).toISOString()===v;
function validate(s){
 if(!s||typeof s!=='object'||Array.isArray(s)||
  Object.keys(s).sort().join(',')!=='algorithm,audience,checkpoint,count,headHash,issuedAt,issuer,version'||
  s.version!==1||s.algorithm!=='Ed25519'||
  !validScope(s.issuer)||!validScope(s.audience)||!validCp(s.checkpoint)||
  !Number.isSafeInteger(s.count)||s.count<1||s.count>8192||
  !HEX.test(s.headHash)||!date(s.issuedAt))fail();
}
export function canonicalWitnessAuditStatement(statement){
 validate(statement);
 return Buffer.from(JSON.stringify({
  version:1,algorithm:'Ed25519',issuer:statement.issuer,audience:statement.audience,
  count:statement.count,checkpoint:{
   sequence:statement.checkpoint.sequence,digest:statement.checkpoint.digest
  },headHash:statement.headHash,issuedAt:statement.issuedAt
 }),'utf8');
}
export function createUnsignedWitnessAuditStatement({
 issuer,audience,checkpoint,count,headHash,issuedAt
}){
 const statement={
  version:1,algorithm:'Ed25519',issuer,audience,count,
  checkpoint,headHash,issuedAt
 };
 canonicalWitnessAuditStatement(statement);
 return Object.freeze({...statement,checkpoint:Object.freeze({...checkpoint})});
}
export function verifyExternallySignedWitnessAuditReceipt(envelope,{
 trustedPublicKey,issuer,audience,minimumCount,expectedHeadHash
}){
 if(!validScope(issuer)||!validScope(audience)||
  !Number.isSafeInteger(minimumCount)||minimumCount<1||minimumCount>8192||
  (expectedHeadHash!==undefined&&(!HEX.test(expectedHeadHash))))fail();
 let publicKey;
 try{publicKey=trustedPublicKey?.type==='public'?trustedPublicKey:createPublicKey(trustedPublicKey);}
 catch{fail();}
 if(publicKey.asymmetricKeyType!=='ed25519')fail();
 const statement=envelope?.statement,signature=envelope?.signature;
 const bytes=canonicalWitnessAuditStatement(statement);
 if(statement.issuer!==issuer||statement.audience!==audience||
  statement.count<minimumCount||
  (expectedHeadHash!==undefined&&statement.headHash!==expectedHeadHash)||
  typeof signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(signature))fail();
 const raw=Buffer.from(signature,'base64url');
 if(raw.length!==64||raw.toString('base64url')!==signature||
  !verify(null,bytes,publicKey,raw))fail();
 return Object.freeze({
  checkpoint:Object.freeze({...statement.checkpoint}),
  count:statement.count,headHash:statement.headHash,
  signerFingerprint:createHash('sha256').update(publicKey.export({type:'spki',format:'der'})).digest('hex')
 });
}
