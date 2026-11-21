// TEST FIXTURE ONLY. Single-process loopback HTTPS front end to the local
// witness journal; never expose this listener to an external network.
import {createServer} from 'node:https';

const fail=()=>Error('fixture witness request denied');
const validScope=s=>typeof s==='string'&&s.length>0&&s.length<=512&&!/[\x00-\x1f\x7f]/.test(s);
const validCp=c=>c&&typeof c==='object'&&!Array.isArray(c)&&
 Object.keys(c).sort().join(',')==='digest,sequence'&&
 Number.isSafeInteger(c.sequence)&&c.sequence>=1&&
 typeof c.digest==='string'&&/^[a-f0-9]{64}$/.test(c.digest);
function checkPayload(raw,scope){
 if(!raw||Buffer.byteLength(raw,'utf8')>4096)throw fail();
 let body;
 try{body=JSON.parse(raw);}catch{throw fail();}
 if(!body||typeof body!=='object'||Array.isArray(body)||
  JSON.stringify(body)!==raw||body.version!==1||
  body.issuer!==scope.issuer||body.audience!==scope.audience)throw fail();
 const fields=Object.keys(body).sort().join(',');
 if(body.operation==='read'){
  if(fields!=='audience,issuer,operation,version')throw fail();
 }else if(body.operation==='compare-and-swap'){
  if(fields!=='audience,issuer,next,operation,previous,version'||
   !validCp(body.previous)||!validCp(body.next)||
   body.next.sequence<=body.previous.sequence)throw fail();
 }else throw fail();
 return body;
}
function respond(res,status,body){
 if(res.destroyed||res.writableEnded)return;
 const bytes=Buffer.from(body);
 res.writeHead(status,{
  'Content-Type':'application/json',
  'Cache-Control':'no-store',
  'Content-Length':String(bytes.length)
 });
 res.end(bytes);
}
export async function openLoopbackWitnessHttpsFixture({
 journal,issuer,audience,key,cert,ca,maxConcurrentRequests=32
}){
 if(!journal||typeof journal.read!=='function'||typeof journal.compareAndSwap!=='function'||
  !validScope(issuer)||!validScope(audience)||!key||!cert||!ca||
  !Number.isSafeInteger(maxConcurrentRequests)||maxConcurrentRequests<1||
  maxConcurrentRequests>128)throw fail();
 const scope=Object.freeze({issuer,audience});
 let active=0,closed=false;
 const server=createServer({
  key,cert,ca,requestCert:true,rejectUnauthorized:true,
  minVersion:'TLSv1.2'
 },async(req,res)=>{
  if(closed||active>=maxConcurrentRequests){
   req.resume();respond(res,503,'{"error":"unavailable"}');return;
  }
  active++;
  try{
   if(req.socket.authorized!==true||req.method!=='POST'||
    req.url!=='/v1/provider-checkpoint'||
    req.headers['content-type']!=='application/json'||
    req.headers['accept']!=='application/json'||
    req.headers['accept-encoding']!=='identity'||
    req.headers['transfer-encoding']!==undefined||
    !/^[1-9]\d*$/.test(req.headers['content-length']??'')||
    Number(req.headers['content-length'])>4096)throw fail();
   const chunks=[];let n=0;
   for await(const b of req){
    n+=b.length;
    if(n>4096)throw fail();
    chunks.push(b);
   }
   if(n!==Number(req.headers['content-length']))throw fail();
   const buf=Buffer.concat(chunks),raw=buf.toString('utf8');
   if(!Buffer.from(raw,'utf8').equals(buf))throw fail();
   const body=checkPayload(raw,scope);
   let checkpoint;
   if(body.operation==='read')checkpoint=await journal.read(scope);
   else checkpoint=await journal.compareAndSwap({...scope,previous:body.previous,next:body.next});
   respond(res,200,JSON.stringify({
    version:1,...scope,checkpoint,consistency:'linearizable',durability:'committed'
   }));
  }catch(e){
   const status=e?.message==='witness compare-and-swap conflict'?409:400;
   respond(res,status,'{"error":"unavailable"}');
  }finally{active--;}
 });
 server.headersTimeout=3000;
 server.requestTimeout=3000;
 server.keepAliveTimeout=1000;
 server.maxHeadersCount=32;
 try{
  await new Promise((resolve,reject)=>{
   server.once('error',reject);
   server.listen(0,'localhost',resolve);
  });
 }catch(e){server.close();throw e;}
 const address=server.address();
 if(!address||typeof address==='string')throw fail();
 return Object.freeze({
  endpoint:'https://localhost:'+address.port+'/v1/provider-checkpoint',
  async close(){
   if(closed)return;
   closed=true;
   server.closeAllConnections();
   await new Promise((resolve,reject)=>server.close(err=>err?reject(err):resolve()));
  }
 });
}
