import {createPrivateKey,createPublicKey,randomBytes,randomUUID,sign} from 'node:crypto';
import {digestOpaque} from './provider-identity.mjs';
import {verifyIdentityToken} from './verify-identity.mjs';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const b64=o=>Buffer.from(JSON.stringify(o)).toString('base64url');
// Backend-for-frontend boundary. Provider token must originate from the
// server-side authorization-code exchange; never expose binding to the client.
export function createAuthenticationGateway({db,provider,localIssuer,localAudience,privateKey,now=()=>Math.floor(Date.now()/1000),maxConcurrentExchanges=8}){
 if(!db||!['begin','redeem','revoke'].every(k=>typeof db[k]==='function')||typeof provider?.verify!=='function'||typeof localIssuer!=='string'||!localIssuer||
 localIssuer===provider.issuer||typeof localAudience!=='string'||!localAudience||localAudience===provider.audience||!Number.isInteger(maxConcurrentExchanges)||maxConcurrentExchanges<1||maxConcurrentExchanges>32)throw Error('invalid authentication gateway');
 const key=privateKey?.type==='private'?privateKey:createPrivateKey(privateKey);
 if(key.asymmetricKeyType!=='rsa'||(key.asymmetricKeyDetails?.modulusLength??0)<2048)throw Error('invalid local signing key');
 const publicKey=createPublicKey(key);
 let activeExchanges=0;
 return Object.freeze({
  async begin(){
   const nonce=randomBytes(32).toString('base64url'),binding=randomBytes(32).toString('base64url');
   if(!await db.begin(digestOpaque(nonce),digestOpaque(binding),provider.issuer,provider.audience))throw Error('login temporarily unavailable');
   return Object.freeze({nonce,binding});
  },
  async exchange({idToken,binding}){
   // The async provider may query an independent remote witness. Cap pending
   // calls before any await so the direct API cannot exhaust its DB or witness.
   if(activeExchanges>=maxConcurrentExchanges)throw Error('authentication denied');
   activeExchanges++;
   try{
    const n=now(),p=await provider.verify(idToken,n),sessionId=randomUUID(),expiresAt=Math.min(n+900,p.expiresAt);
    const actorId=await db.redeem({nonce:digestOpaque(p.nonce),binding:digestOpaque(binding),issuer:p.issuer,audience:p.audience,subjectDigest:p.subjectDigest,sessionId,authenticatedAt:p.authenticatedAt,expiresAt});
    if(!UUID.test(actorId)||now()>=expiresAt)throw Error('invalid registered session');
    const body=b64({alg:'RS256',typ:'JWT'})+'.'+b64({iss:localIssuer,aud:localAudience,sub:actorId,sid:sessionId,iat:n,nbf:n,exp:expiresAt});
    const token=body+'.'+sign('RSA-SHA256',Buffer.from(body),key).toString('base64url');
    return Object.freeze({token,expiresAt});
   }catch{throw Error('authentication denied');}
   finally{activeExchanges--;}
  },
  async logout(token){
   try{const p=verifyIdentityToken(token,{publicKey,issuer:localIssuer,audience:localAudience,now:now()});return await db.revoke(p.actorId,p.sessionId);}
   catch{throw Error('logout denied');}
  }
 });
}
