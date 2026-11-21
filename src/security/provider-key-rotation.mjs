import {createHash,createPublicKey,verify} from 'node:crypto';
import {createProviderVerifier} from './provider-identity.mjs';
// Signed operator-approved keyset snapshots, never fetched from JWT headers.
// A separately trusted checkpoint is required at startup AND must be durably
// advanced before a newly rotated provider keyset becomes active.
export function createRotatingProviderVerifier({issuer,audience,requiredAcr,requiredAmr,authorityKey,checkpoint,catalogue,signature,persistCheckpoint,now=()=>Math.floor(Date.now()/1000)}){
 const authority=authorityKey?.type==='public'?authorityKey:createPublicKey(authorityKey);
 if(authority.asymmetricKeyType!=='ed25519'||!Number.isSafeInteger(checkpoint?.sequence)||checkpoint.sequence<1||! /^[a-f0-9]{64}$/.test(checkpoint.digest))throw Error('invalid keyset trust anchor');
 let current,state='ready';
 function accept(bytes,sig,anchor){
  if(!Buffer.isBuffer(bytes)||bytes.length>65536||!Buffer.isBuffer(sig)||sig.length!==64||!verify(null,bytes,authority,sig))throw Error('keyset signature denied');
  // Signed bytes are authenticated, but JSON.parse silently discards duplicate
  // names and normalises escapes. Refuse multiple possible interpretations.
  const raw=bytes.toString('utf8');
  if(!Buffer.from(raw,'utf8').equals(bytes))throw Error('noncanonical provider keyset');
  const m=JSON.parse(raw);
  if(!m||typeof m!=='object'||Array.isArray(m)||
     !Buffer.from(JSON.stringify(m),'utf8').equals(bytes))
   throw Error('noncanonical provider keyset');
  const digest=createHash('sha256').update(bytes).digest('hex'),n=now();
  if(!Number.isSafeInteger(n)||n<1)throw Error('invalid keyset clock');
  if(!m||m.version!==1||m.issuer!==issuer||m.audience!==audience||!Number.isSafeInteger(m.sequence)||m.sequence!==anchor?.sequence||digest!==anchor?.digest||
   !Number.isSafeInteger(m.issuedAt)||!Number.isSafeInteger(m.expiresAt)||m.issuedAt>n||m.expiresAt<=n||m.expiresAt-m.issuedAt>86400||m.expiresAt<=m.issuedAt||
   !Array.isArray(m.keys)||m.keys.length<1||m.keys.length>8)throw Error('keyset scope or freshness denied');
  const verifier=createProviderVerifier({issuer,audience,requiredAcr,requiredAmr,keys:m.keys.map(k=>({kid:k.kid,publicKey:k.pem}))});
  return {sequence:m.sequence,digest,expiresAt:m.expiresAt,verifier};
 }
 current=accept(catalogue,signature,checkpoint);
 return Object.freeze({issuer,audience,
  verify(token,n=now()){
   if(state!=='ready')throw Error('provider keyset unavailable pending trusted checkpoint');
   if(now()>=current.expiresAt)throw Error('keyset expired');
   return current.verifier.verify(token,n);
  },
  async rotate(bytes,sig,anchor){
   if(state!=='ready')throw Error('provider keyset unavailable pending trusted checkpoint');
   // Do not change live state for malformed, stale, or unsigned candidates.
   const replacement=accept(bytes,sig,anchor);
   if(replacement.sequence<=current.sequence)throw Error('keyset rollback denied');
   if(typeof persistCheckpoint!=='function')throw Error('durable checkpoint writer required');
   const previous=Object.freeze({sequence:current.sequence,digest:current.digest});
   const next=Object.freeze({sequence:replacement.sequence,digest:replacement.digest});
   // The callback must compare-and-swap the independently trusted checkpoint
   // atomically and return the durable result. Verification is denied while
   // persistence is outstanding; on ambiguity remain failed closed until restart.
   state='rotating';
   try{
    const saved=await persistCheckpoint(previous,next);
    if(saved?.sequence!==next.sequence||saved?.digest!==next.digest)throw Error('checkpoint result mismatch');
    current=replacement;
    state='ready';
    return next;
   }catch{
    state='faulted';
    throw Error('provider keyset checkpoint update unconfirmed; restart required');
   }
  }
 });
}
