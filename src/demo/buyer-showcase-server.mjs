// Loopback-only synthetic buyer showcase. No production API or access control.
// Never expose over public network: fixture information is not authenticated.
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {buildBuyerShowcasePayload} from './buyer-showcase.mjs';

const resources=[
 ['/',{name:'buyer-showcase.html',type:'text/html; charset=utf-8'}],
 ['/buyer-showcase.css',{name:'buyer-showcase.css',type:'text/css; charset=utf-8'}],
 ['/buyer-showcase.js',{name:'buyer-showcase.js',type:'text/javascript; charset=utf-8'}]
];
const csp="default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const publicHeaders={
 'Content-Security-Policy':csp,
 'X-Content-Type-Options':'nosniff',
 'X-Frame-Options':'DENY',
 'Referrer-Policy':'no-referrer',
 'Cache-Control':'no-store',
 'Permissions-Policy':'camera=(), microphone=(), geolocation=(), payment=()'
};
const respond=(res,status,body,type,method='GET')=>{
 const data=Buffer.isBuffer(body)?body:Buffer.from(String(body),'utf8');
 res.writeHead(status,{...publicHeaders,'Content-Type':type,
  'Content-Length':data.length});
 res.end(method==='HEAD'?undefined:data);
};
export async function createBuyerShowcaseServer(){
 const payload=await buildBuyerShowcasePayload();
 const staticFiles=new Map();
 for(const [route,file] of resources){
  const content=await readFile(fileURLToPath(new URL(file.name,import.meta.url)));
  staticFiles.set(route,{...file,content});
 }
 const json=Buffer.from(JSON.stringify(payload),'utf8');
 return createServer((req,res)=>{
  const local=req.socket.localAddress;
  const host=req.headers.host||'';
  if(local!=='127.0.0.1'||!/^((127\.0\.0\.1)|(localhost))(:[0-9]{1,5})?$/.test(host)){
   respond(res,403,'Forbidden\n','text/plain; charset=utf-8',req.method);return;
  }
  if(!['GET','HEAD'].includes(req.method)){
   respond(res,405,'Method not allowed\n','text/plain; charset=utf-8',req.method);return;
  }
  if(req.url==='/buyer-demo.json'){
   respond(res,200,json,'application/json; charset=utf-8',req.method);return;
  }
  const file=staticFiles.get(req.url);
  if(!file){
   respond(res,404,'Not found\n','text/plain; charset=utf-8',req.method);return;
  }
  respond(res,200,file.content,file.type,req.method);
 });
}
