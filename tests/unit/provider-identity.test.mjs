import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,generateKeyPairSync} from 'node:crypto';
import {provider,issuer,audience,local,nonce,subject,token} from '../fixtures/provider-fixture.mjs';
import {createAuthenticationGateway} from '../../src/security/authentication-gateway.mjs';
import {verifyIdentityToken} from '../../src/security/verify-identity.mjs';
test('provider verifier rejects spoofed issuer, audience, MFA, stale proof, key and ambiguous claims',()=>{
 const n=nonce(),now=Math.floor(Date.now()/1000),good=token(n);
 assert.equal(provider.verify(good).nonce,n);
 for(const bad of [
  token(n,{iss:'https://wrong.invalid'}),token(n,{aud:'wrong'}),token(n,{aud:[audience,'other']}),token(n,{azp:'wrong'}),
  token(n,{amr:['pwd']}),token(n,{acr:'none'}),token(n,{auth_time:now-241}),token(n,{iat:now+5}),token(n,{exp:now-1}),
  token(n,{nonce:'invalid'}),token(n,{sub:''}),token(n,{}, {kid:'unknown'}),token(n,{}, {jku:'https://wrong.invalid/key'}),
  token(n,{}, {},generateKeyPairSync('rsa',{modulusLength:2048}).privateKey),
  token(n,{}, {},undefined,'{"sub":"first","\\u0073ub":"second"}')
 ])assert.throws(()=>provider.verify(bad));
});
test('local session minted only after database redemption, mapped actor never upstream subject',async()=>{
 const actor=randomUUID(),calls=[];
 const db={begin:async()=>true,redeem:async x=>{calls.push(x);return actor;},revoke:async(a,s)=>{calls.push({a,s});return true;}};
 const gateway=createAuthenticationGateway({db,provider,localIssuer:'urn:verivaro:local',localAudience:'api',privateKey:local.privateKey});
 const c=await gateway.begin(),result=await gateway.exchange({idToken:token(c.nonce),binding:c.binding});
 const p=verifyIdentityToken(result.token,{publicKey:local.publicKey,issuer:'urn:verivaro:local',audience:'api'});
 assert.equal(p.actorId,actor);assert.notEqual(p.actorId,subject);assert.equal(p.sessionId,calls[0].sessionId);
 assert.equal(await gateway.logout(result.token),true);
 assert.deepEqual(calls[1],{a:actor,s:p.sessionId});
 await assert.rejects(gateway.exchange({idToken:token(c.nonce,{amr:['pwd']}),binding:c.binding}),/authentication denied/);
 assert.equal(calls.length,2);
});

test('asynchronous provider rejection never redeems a challenge and async verification is awaited',async()=>{
 const actor=randomUUID(),calls=[],now=Math.floor(Date.now()/1000);
 let release,verifyCalls=0;
 const asyncProvider=Object.freeze({...provider,verify:async(jwt,t)=>{
  verifyCalls++;
  await new Promise(resolve=>{release=resolve;});
  return provider.verify(jwt,t);
 }});
 const db={begin:async()=>true,redeem:async x=>{calls.push(x);return actor;},revoke:async()=>true};
 const gw=createAuthenticationGateway({db,provider:asyncProvider,localIssuer:'urn:verivaro:local',localAudience:'api',privateKey:local.privateKey,maxConcurrentExchanges:1});
 const c=await gw.begin();
 const pending=gw.exchange({idToken:token(c.nonce),binding:c.binding});
 assert.equal(verifyCalls,1);
 assert.equal(calls.length,0);
 // Pending remote verification consumes one permit; no extra database work.
 await assert.rejects(gw.exchange({idToken:token(c.nonce),binding:c.binding}),/authentication denied/);
 assert.equal(verifyCalls,1);
 release();
 const result=await pending;
 assert.equal(verifyIdentityToken(result.token,{publicKey:local.publicKey,issuer:'urn:verivaro:local',audience:'api'}).actorId,actor);
 assert.equal(calls.length,1);
 const rejector=Object.freeze({...provider,verify:async()=>{throw Error('witness unavailable');}});
 const denied=createAuthenticationGateway({db,provider:rejector,localIssuer:'urn:verivaro:local',localAudience:'api',privateKey:local.privateKey,maxConcurrentExchanges:1});
 await assert.rejects(denied.exchange({idToken:token(c.nonce),binding:c.binding}),/authentication denied/);
 assert.equal(calls.length,1);
 const wrong=Object.freeze({...provider,verify:async()=>{throw Error('keyset rollback');}});
 const failing=createAuthenticationGateway({db,provider:wrong,localIssuer:'urn:verivaro:local',localAudience:'api',privateKey:local.privateKey});
 await assert.rejects(failing.exchange({idToken:token(c.nonce),binding:c.binding}),/authentication denied/);
 assert.equal(calls.length,1);
 for(const maxConcurrentExchanges of [0,33,1.5,NaN])assert.throws(()=>createAuthenticationGateway({db,provider:asyncProvider,localIssuer:'urn:verivaro:local',localAudience:'api',privateKey:local.privateKey,maxConcurrentExchanges}),/invalid authentication gateway/);
});
