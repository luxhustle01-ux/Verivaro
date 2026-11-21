import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { verifyIdentityToken } from '../../src/security/verify-identity.mjs';

const { privateKey, publicKey } = generateKeyPairSync('rsa',{modulusLength:2048});
const now=1900000000;
const actor='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const base={iss:'https://identity.example.test',aud:'verivaro',sub:actor,sid:'12345678-1234-4234-8234-123456789abc',iat:now-10,nbf:now-10,exp:now+300};
function token(claims=base,header={alg:'RS256',typ:'JWT'},key=privateKey) {
 const h=Buffer.from(JSON.stringify(header)).toString('base64url');
 const p=Buffer.from(JSON.stringify(claims)).toString('base64url');
 return h+'.'+p+'.'+sign('RSA-SHA256',Buffer.from(h+'.'+p),key).toString('base64url');
}
const options={publicKey,issuer:base.iss,audience:base.aud,now};
test('accepts a correctly signed short-lived identity',()=>{
 assert.equal(verifyIdentityToken(token(),options).actorId,actor);
});
test('rejects impersonation, wrong issuer/audience and expired claims',()=>{
 for(const claims of [
  {...base,sub:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'},
  {...base,iss:'https://attacker.test'},
  {...base,aud:'other'},
  {...base,exp:now},
  {...base,nbf:now+1},
  {...base,iat:now+1},
  {...base,exp:now+7200}
 ]) {
  // Altered subject with valid issuer signature is legitimate identity, not an attack.
  if(claims.sub!==base.sub) continue;
  assert.throws(()=>verifyIdentityToken(token(claims),options));
 }
 const parts=token().split('.');
 const forged={...base,sub:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'};
 parts[1]=Buffer.from(JSON.stringify(forged)).toString('base64url');
 assert.throws(()=>verifyIdentityToken(parts.join('.'),options));
});
test('rejects alg confusion, missing signature and unknown signing key',()=>{
 assert.throws(()=>verifyIdentityToken(token(base,{alg:'none',typ:'JWT'}),options));
 assert.throws(()=>verifyIdentityToken(token().split('.').slice(0,2).join('.')+'.',options));
 const other=generateKeyPairSync('rsa',{modulusLength:2048});
 assert.throws(()=>verifyIdentityToken(token(base,undefined,other.privateKey),options));
});

test('rejects unrecognized signed header and identity claim fields',()=>{
 assert.throws(()=>verifyIdentityToken(token(base,{alg:'RS256',typ:'JWT',jku:'https://attacker.test/keys'}),options));
 assert.throws(()=>verifyIdentityToken(token({...base,tenant_id:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'}),options));
 assert.throws(()=>verifyIdentityToken(token({...base,role:'owner'}),options));
});

test('rejects correctly signed JWT using a weak 1024-bit RSA key',()=>{
 const weak=generateKeyPairSync('rsa',{modulusLength:1024});
 assert.throws(()=>verifyIdentityToken(token(base,undefined,weak.privateKey),{...options,publicKey:weak.publicKey}),/invalid token signature/);
});

test('session claim is mandatory and signature-bound',()=>{
 assert.equal(verifyIdentityToken(token(),options).sessionId,'12345678-1234-4234-8234-123456789abc');
 for(const sid of [undefined,null,'invalid',42])assert.throws(()=>verifyIdentityToken(token({...base,sid}),options),/session/);
 const parts=token().split('.');
 parts[1]=Buffer.from(JSON.stringify({...base,sid:'87654321-4321-4321-8321-cba987654321'})).toString('base64url');
 assert.throws(()=>verifyIdentityToken(parts.join('.'),options),/signature/);
});

function rawSignedToken(headerJson,claimsJson) {
 const h=Buffer.from(headerJson).toString('base64url');
 const p=Buffer.from(claimsJson).toString('base64url');
 return h+'.'+p+'.'+sign('RSA-SHA256',Buffer.from(h+'.'+p),privateKey).toString('base64url');
}
test('rejects signed duplicate local JWT member names and escaped aliases',()=>{
 const header=JSON.stringify({alg:'RS256',typ:'JWT'});
 const claims=JSON.stringify(base);
 const duplicateIssuer=claims.replace('"iss":',String.raw`"\u0069ss":"https://ambiguous.example.test","iss":`);
 const duplicateExp=claims.replace('"exp":',String.raw`"exp":1,"exp":`);
 const duplicateAlgorithm=header.replace('"alg":',String.raw`"alg":"none","alg":`);
 const escapedType=header.replace('"typ":',String.raw`"\u0074yp":"non-jwt","typ":`);
 for(const t of [
  rawSignedToken(header,duplicateIssuer),
  rawSignedToken(header,duplicateExp),
  rawSignedToken(duplicateAlgorithm,claims),
  rawSignedToken(escapedType,claims)
 ]) assert.throws(()=>verifyIdentityToken(t,options),/duplicate claim/);
});
