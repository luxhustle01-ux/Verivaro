import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:https';
import {execFileSync} from 'node:child_process';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHttpsProviderCheckpointWitness} from '../../src/security/provider-checkpoint-https-witness.mjs';

const scope={issuer:'https://identity.example.test',audience:'verivaro-fixture'};
const first={sequence:1,digest:'1'.repeat(64)};
const second={sequence:2,digest:'2'.repeat(64)};
const responseFor=(c)=>JSON.stringify({
 version:1,...scope,checkpoint:c,consistency:'linearizable',durability:'committed'
});
async function fixture(t,handler){
 const dir=await mkdtemp(join(tmpdir(),'vv-https-witness-'));
 const keyPath=join(dir,'test-private-key.pem'),certPath=join(dir,'test-certificate.pem');
 // Ephemeral self-signed localhost certificate. No committed real credentials.
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes',
  '-keyout',keyPath,'-out',certPath,'-subj','/CN=localhost',
  '-addext','subjectAltName=DNS:localhost','-days','1'],{stdio:'ignore'});
 const [key,cert]=await Promise.all([readFile(keyPath),readFile(certPath)]);
 const server=createServer({key,cert,ca:cert,requestCert:true,rejectUnauthorized:true},handler);
 await new Promise((resolve,reject)=>{
  server.once('error',reject);
  server.listen(0,'localhost',resolve);
 });
 t.after(async()=>{
  server.closeAllConnections();
  await new Promise(resolve=>server.close(resolve));
  await rm(dir,{recursive:true,force:true});
 });
 const endpoint='https://localhost:'+server.address().port+'/v1/provider-checkpoint';
 const configuration={
  endpoint,...scope,caPem:cert,clientCertPem:cert,clientKeyPem:key,
  requestTimeoutMs:350,maxInFlight:1,allowLoopbackForTests:true
 };
 return {configuration,server};
}
async function jsonRequest(req){
 let size=0,raw='';
 for await(const part of req){size+=part.length;if(size>4096)throw Error('test request too large');raw+=part.toString('utf8');}
 return JSON.parse(raw);
}
function reply(res,value,status=200,extra={}){
 res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store',...extra});
 res.end(value);
}
test('real TLS + client certificate witness read, CAS, conflict and bounded requests',async t=>{
 let stored=first,calls=0,mutual=false,requestHeaders;
 const f=await fixture(t,async(req,res)=>{
  try{
   mutual=req.socket.authorized===true;requestHeaders=req.headers;
   const input=await jsonRequest(req);calls++;
   if(req.method!=='POST'||req.url!=='/v1/provider-checkpoint'||!mutual)throw Error('invalid TLS request');
   if(input.version!==1||input.issuer!==scope.issuer||input.audience!==scope.audience)throw Error('scope mismatch');
   if(input.operation==='read')return reply(res,responseFor(stored));
   if(input.operation!=='compare-and-swap')throw Error('invalid op');
   if(input.previous.sequence!==stored.sequence||input.previous.digest!==stored.digest)
    return reply(res,'{"error":"conflict"}',409);
   stored={...input.next};
   return reply(res,responseFor(stored));
  }catch{reply(res,'{"error":"denied"}',400);}
 });
 const witness=createHttpsProviderCheckpointWitness(f.configuration);
 t.after(()=>witness.close());
 assert.deepEqual(await witness.read(scope),first);
 assert.deepEqual(await witness.compareAndSwap({...scope,previous:first,next:second}),second);
 assert.deepEqual(await witness.read(scope),second);
 await assert.rejects(witness.compareAndSwap({...scope,previous:first,next:second}),/unavailable/);
 await assert.rejects(witness.read({issuer:scope.issuer,audience:'other'}),/unavailable/);
 await assert.rejects(witness.compareAndSwap({...scope,previous:second,next:first}),/unavailable/);
 assert.equal(calls,4);
 assert.equal(mutual,true);
 assert.equal(requestHeaders['cache-control'],'no-store');
 assert.equal(requestHeaders['accept-encoding'],'identity');
});
test('rejects unsafe endpoints, missing mutual TLS credentials and invalid limits',async t=>{
 const f=await fixture(t,(req,res)=>reply(res,responseFor(first)));
 const good=f.configuration;
 for(const override of [
  {endpoint:'http://localhost/v1/provider-checkpoint'},
  {endpoint:'https://evil.example.invalid/v1/provider-checkpoint?x=1'},
  {endpoint:'https://user:pass@localhost/v1/provider-checkpoint'},
  {endpoint:'https://127.0.0.1/v1/provider-checkpoint',allowLoopbackForTests:false},
  {endpoint:'https://10.0.0.1/v1/provider-checkpoint'},
  {allowLoopbackForTests:false},
  {caPem:undefined},{clientCertPem:undefined},{clientKeyPem:undefined},
  {requestTimeoutMs:0},{maxInFlight:33},{maxResponseBytes:999999}
 ])assert.throws(()=>createHttpsProviderCheckpointWitness({...good,...override}),/invalid/);
 // A different trust root does not validate the fixture server's cert.
 const invalidCa=Buffer.from('-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----');
 const witness=createHttpsProviderCheckpointWitness({...good,caPem:invalidCa,requestTimeoutMs:120});
 t.after(()=>witness.close());
 await assert.rejects(witness.read(scope),/unavailable/);
});
test('redirect, oversized and ambiguous witness replies fail closed',async t=>{
 let mode='redirect';
 const f=await fixture(t,async(req,res)=>{
  await jsonRequest(req);
  if(mode==='redirect')return reply(res,'',307,{Location:'https://example.invalid/steal'});
  if(mode==='oversized')return reply(res,'x'.repeat(3000));
  if(mode==='duplicate'){
   const good=responseFor(first);
   return reply(res,good.replace('"version":1','"version":1,"version":1'));
  }
  if(mode==='wrong-scope')return reply(res,JSON.stringify({
   version:1,issuer:scope.issuer,audience:'wrong',checkpoint:first,
   consistency:'linearizable',durability:'committed'
  }));
  if(mode==='stale-contract')return reply(res,JSON.stringify({
   version:1,...scope,checkpoint:first,consistency:'eventual',durability:'pending'
  }));
  reply(res,responseFor(first));
 });
 const witness=createHttpsProviderCheckpointWitness(f.configuration);
 t.after(()=>witness.close());
 for(const next of ['redirect','oversized','duplicate','wrong-scope','stale-contract']){
  mode=next;
  await assert.rejects(witness.read(scope),/unavailable/);
 }
 mode='valid';
 assert.deepEqual(await witness.read(scope),first);
});
test('request timeout aborts network response, and max-in-flight denies saturation',async t=>{
 let mode='stall',entered,closed;
 const enteredP=()=>new Promise(resolve=>{entered=resolve;});
 let seen=enteredP();
 const closedP=new Promise(resolve=>{closed=resolve;});
 const f=await fixture(t,async(req,res)=>{
  await jsonRequest(req);
  if(mode==='stall'){
   res.once('close',()=>closed());
   entered();
   return;
  }
  reply(res,responseFor(first));
 });
 const witness=createHttpsProviderCheckpointWitness({...f.configuration,requestTimeoutMs:120});
 t.after(()=>witness.close());
 const pending=witness.read(scope);
 await seen;
 await assert.rejects(witness.read(scope),/capacity exceeded/);
 await assert.rejects(pending,/unavailable/);
 // The local HTTPS transport must be torn down, not just Promise.race'd.
 await Promise.race([
  closedP,
  new Promise((_,reject)=>setTimeout(()=>reject(Error('socket was not closed')),1500))
 ]);
 mode='ok';
 assert.deepEqual(await witness.read(scope),first);
});
test('caller cancellation and close both tear down pending transport',async t=>{
 let entered,mode='stall';
 let seen=new Promise(resolve=>{entered=resolve;});
 const f=await fixture(t,async(req,res)=>{
  await jsonRequest(req);
  if(mode==='stall'){entered();return;}
  reply(res,responseFor(first));
 });
 const witness=createHttpsProviderCheckpointWitness({...f.configuration,requestTimeoutMs:1000});
 t.after(()=>witness.close());
 const controller=new AbortController(),pending=witness.read(scope,{signal:controller.signal});
 await seen;
 controller.abort();
 await assert.rejects(pending,/unavailable/);
 seen=new Promise(resolve=>{entered=resolve;});
 const pending2=witness.read(scope);
 await seen;
 witness.close();
 await assert.rejects(pending2,/unavailable/);
 mode='ok';
 await assert.rejects(witness.read(scope),/unavailable/);
});
