// Explicit opt-in HTTPS adapter for an independently administered G1 witness.
// Not a witness server: remote linearizability, durability, and custody require
// independent operational verification. No insecure HTTP or redirects.
import {Agent,request as httpsRequest} from 'node:https';
import {isIP} from 'node:net';

const checkpointOk=c=>c&&Number.isSafeInteger(c.sequence)&&c.sequence>=1&&
 typeof c.digest==='string'&&/^[a-f0-9]{64}$/.test(c.digest);
const same=(a,b)=>checkpointOk(a)&&checkpointOk(b)&&a.sequence===b.sequence&&a.digest===b.digest;
const scopeOk=s=>typeof s==='string'&&s.length>0&&s.length<=512&&
 !/[\x00-\x1f\x7f]/.test(s);
const pem=(value,marker)=>(
 (typeof value==='string'||Buffer.isBuffer(value))&&value.length>32&&
 value.length<=65536&&String(value).includes(marker)
);
const fail=()=>Error('independent checkpoint witness transport unavailable');

export function createHttpsProviderCheckpointWitness({
 endpoint,issuer,audience,caPem,clientCertPem,clientKeyPem,
 requestTimeoutMs=3000,maxInFlight=8,maxResponseBytes=2048,
 allowLoopbackForTests=false
}){
 let url;
 try{url=new URL(endpoint);}catch{throw Error('invalid witness endpoint');}
 const host=url.hostname.replace(/^\[|\]$/g,''),ip=isIP(host);
 const loopback=host==='localhost'||host.endsWith('.localhost')||
  host==='127.0.0.1'||host==='::1';
 if(url.protocol!=='https:'||url.username||url.password||url.hash||url.search||
  url.pathname!=='/v1/provider-checkpoint'||!host||
  (ip&&!loopback)||(loopback&&allowLoopbackForTests!==true)||
  !scopeOk(issuer)||!scopeOk(audience)||
  !pem(caPem,'-----BEGIN CERTIFICATE-----')||
  !pem(clientCertPem,'-----BEGIN CERTIFICATE-----')||
  !pem(clientKeyPem,'PRIVATE KEY-----')||
  !Number.isSafeInteger(requestTimeoutMs)||requestTimeoutMs<25||requestTimeoutMs>30000||
  !Number.isSafeInteger(maxInFlight)||maxInFlight<1||maxInFlight>32||
  !Number.isSafeInteger(maxResponseBytes)||maxResponseBytes<256||maxResponseBytes>8192)
  throw Error('invalid HTTPS witness configuration');
 // Explicit CA and client certificate; rejectUnauthorized is never disabled.
 // No shared ambient proxy, browser cookies, bearer token or system CA fallback.
 const agent=new Agent({
  ca:caPem,cert:clientCertPem,key:clientKeyPem,
  rejectUnauthorized:true,keepAlive:false,
  maxSockets:maxInFlight,maxTotalSockets:maxInFlight
 });
 let closed=false;
 const active=new Set();
 const scope=Object.freeze({issuer,audience});

 async function send(operation,details={},externalSignal){
  if(closed||externalSignal?.aborted)throw fail();
  if(active.size>=maxInFlight)throw Error('independent checkpoint witness capacity exceeded');
  const controller=new AbortController();
  active.add(controller);
  try{
   const body=Buffer.from(JSON.stringify({version:1,operation,...scope,...details}));
   if(body.length>4096)throw fail();
   const signals=[controller.signal,AbortSignal.timeout(requestTimeoutMs)];
   if(externalSignal){
    if(typeof externalSignal.addEventListener!=='function'||typeof externalSignal.aborted!=='boolean')
     throw fail();
    signals.push(externalSignal);
   }
   const signal=AbortSignal.any(signals);
   const result=await new Promise((resolve,reject)=>{
    let request;
    try{
     request=httpsRequest(url,{
      method:'POST',agent,signal,rejectUnauthorized:true,
      headers:{
       'Content-Type':'application/json',
       'Accept':'application/json',
       'Accept-Encoding':'identity',
       'Cache-Control':'no-store',
       'Pragma':'no-cache',
       'Content-Length':String(body.length)
      }
     },response=>{
      const ct=response.headers['content-type'];
      const cc=response.headers['cache-control'];
      const encoding=response.headers['content-encoding'];
      const length=response.headers['content-length'];
      if(response.statusCode!==200||
       typeof ct!=='string'||!/^application\/json(?:;\s*charset=utf-8)?$/i.test(ct)||
       typeof cc!=='string'||!/(?:^|,)\s*no-store(?:,|$)/i.test(cc)||
       (encoding!==undefined&&encoding!=='identity')||
       (length!==undefined&&(!/^\d+$/.test(length)||Number(length)>maxResponseBytes))){
       response.destroy();reject(fail());return;
      }
      let size=0,finished=false;
      const chunks=[];
      response.on('data',chunk=>{
       size+=chunk.length;
       if(size>maxResponseBytes){response.destroy();reject(fail());return;}
       chunks.push(chunk);
      });
      response.once('end',()=>{
       finished=true;
       try{
        const raw=Buffer.concat(chunks).toString('utf8');
        const obj=JSON.parse(raw);
        // Canonical JSON refuses ambiguous duplicate/escaped member names.
        if(JSON.stringify(obj)!==raw||!obj||Array.isArray(obj)||
         Object.keys(obj).sort().join(',')!=='audience,checkpoint,consistency,durability,issuer,version'||
         obj.version!==1||obj.issuer!==issuer||obj.audience!==audience||
         obj.consistency!=='linearizable'||obj.durability!=='committed'||
         !obj.checkpoint||Array.isArray(obj.checkpoint)||
         Object.keys(obj.checkpoint).sort().join(',')!=='digest,sequence'||
         !checkpointOk(obj.checkpoint))throw fail();
        resolve(Object.freeze({...obj.checkpoint}));
       }catch{reject(fail());}
      });
      response.once('aborted',()=>reject(fail()));
      response.once('error',()=>reject(fail()));
      response.once('close',()=>{if(!finished)reject(fail());});
     });
     request.once('error',()=>reject(fail()));
     request.end(body);
    }catch{request?.destroy();reject(fail());}
   });
   return result;
  }catch{throw fail();}
  finally{active.delete(controller);}
 }
 return Object.freeze({
  async read(requestScope,{signal}={}){
   if(requestScope?.issuer!==issuer||requestScope?.audience!==audience)throw fail();
   return send('read',{},signal);
  },
  async compareAndSwap({issuer:iss,audience:aud,previous,next},{signal}={}){
   if(iss!==issuer||aud!==audience||!checkpointOk(previous)||
    !checkpointOk(next)||next.sequence<=previous.sequence||same(previous,next))throw fail();
   const saved=await send('compare-and-swap',{previous,next},signal);
   if(!same(saved,next))throw fail();
   return saved;
  },
  close(){
   if(closed)return;
   closed=true;
   for(const controller of active)controller.abort();
   agent.destroy();
  }
 });
}
