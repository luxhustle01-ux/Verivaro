import {randomBytes,createHash,createCipheriv,createDecipheriv,hkdfSync} from 'node:crypto';
import {digestOpaque} from './provider-identity.mjs';
import {verifyIdentityToken} from './verify-identity.mjs';
const random=()=>randomBytes(32).toString('base64url');
const flow='__Host-vv_flow',session='__Host-vv_session';
const secure=(name,value,maxAge)=>name+'='+value+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age='+maxAge;
const noStore={'Cache-Control':'no-store, private','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",'Content-Type':'text/plain; charset=utf-8'};
function endpoint(s){const u=new URL(s);if(u.protocol!=='https:'||u.username||u.password||u.hash||u.search)throw Error('invalid HTTPS endpoint');return u;}
function cookie(req,name){
 const raw=req.headers.cookie;if(typeof raw!=='string'||raw.length>8192)return null;
 const hits=raw.split(';').map(x=>x.trim()).filter(x=>x.startsWith(name+'='));
 if(hits.length!==1)return null;
 const value=hits[0].slice(name.length+1);try{digestOpaque(value);return value;}catch{return null;}
}
function send(res,status,body='',extra={}){
 if(res.destroyed||res.writableEnded)return;
 res.writeHead(status,{...noStore,'Content-Length':Buffer.byteLength(body),...extra});res.end(body);
}
async function boundedJson(response){
 if(response.status!==200||!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type')??'')||!response.body){await response.body?.cancel();throw Error('token exchange denied');}
 const reader=response.body.getReader(),chunks=[];let size=0;
 try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>65536)throw Error('token response too large');chunks.push(Buffer.from(value));}
 const parsed=JSON.parse(Buffer.concat(chunks).toString('utf8'));
 if(!parsed||typeof parsed.id_token!=='string'||parsed.id_token.length>32768)throw Error('invalid token response');
 return parsed.id_token;
 }finally{try{await reader.cancel();}catch{}reader.releaseLock();}
}
export function createBrowserAuthentication({db,gateway,provider,localVerifier,origin,authorizationEndpoint,tokenEndpoint,clientSecret,key,requiredAcr,fetcher=fetch,now=()=>Math.floor(Date.now()/1000),maxConcurrent=8}){
 const app=endpoint(origin),auth=endpoint(authorizationEndpoint),token=endpoint(tokenEndpoint),iss=endpoint(provider.issuer);
 if(app.href!==app.origin+'/'||auth.origin!==iss.origin||token.origin!==iss.origin||typeof provider.audience!=='string'||typeof requiredAcr!=='string'||!requiredAcr||
 typeof clientSecret!=='string'||clientSecret.length<32||clientSecret.length>256||!/^[A-Za-z0-9_-]+$/.test(clientSecret)||
 !Buffer.isBuffer(key)||key.length!==32||!Number.isInteger(maxConcurrent)||maxConcurrent<1||maxConcurrent>32||
 !['storeFlow','takeFlow','storeBrowserSession','readBrowserSession','logoutBrowser','logoutAllBrowser','recordAuth'].every(k=>typeof db?.[k]==='function'))throw Error('invalid browser authentication configuration');
 const redirect=app.origin+'/auth/callback',secret=Buffer.from(hkdfSync('sha256',key,Buffer.from(app.origin),'verivaro-browser-v1',32));
 let active=0;
 function seal(value,purpose,handle){
  const nonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',secret,nonce);cipher.setAAD(Buffer.from(purpose+':'+handle));
  return Buffer.concat([nonce,cipher.update(JSON.stringify(value),'utf8'),cipher.final(),cipher.getAuthTag()]);
 }
 function unseal(value,purpose,handle){
  if(!Buffer.isBuffer(value)||value.length<32||value.length>8192)throw Error('invalid sealed data');
  const d=createDecipheriv('aes-256-gcm',secret,value.subarray(0,12));d.setAAD(Buffer.from(purpose+':'+handle));d.setAuthTag(value.subarray(-16));
  return JSON.parse(Buffer.concat([d.update(value.subarray(12,-16)),d.final()]).toString('utf8'));
 }
 async function resolveSession(req){
  const h=cookie(req,session);if(!h)return null;
  const enc=await db.readBrowserSession(digestOpaque(h));if(!enc)return null;
  const data=unseal(enc,'session',h);
  verifyIdentityToken(data.token,{...localVerifier,now:now()});
  return data.token;
 }
 async function handler(req,res){
  // Only fixed routes; never use Host or forwarded headers to generate URLs.
  if(typeof req.url!=='string'||req.url.length>8192||!req.url.startsWith('/auth/'))return send(res,404);
  const url=new URL(req.url,app.origin);
  if(req.url.split('?')[0]!==url.pathname)return send(res,404);
  if(url.origin!==app.origin||!['/auth/login','/auth/callback','/auth/logout','/auth/logout-all','/auth/session'].includes(url.pathname))return send(res,404);
  if(req.headers['transfer-encoding']!==undefined||(req.headers['content-length']!==undefined&&req.headers['content-length']!=='0'))return send(res,400,'Request denied',{'Connection':'close'});
  if(active>=maxConcurrent)return send(res,429,'Temporarily unavailable',{'Retry-After':'5'});
  active++;
  try{
   if(url.pathname==='/auth/login'){
    if(req.method!=='POST'||url.search||req.headers.origin!==app.origin)return send(res,403,'Request denied');
    // Explicit logout is required before switching accounts; never silently replace a session.
    if(await resolveSession(req))return send(res,409,'Already signed in');
    const c=await gateway.begin(),state=random(),browser=random(),verifier=random();
    if(!await db.storeFlow(digestOpaque(state),digestOpaque(browser),seal({...c,verifier},'flow',state)))return send(res,503,'Temporarily unavailable');
    const authUrl=new URL(auth.href);
    for(const [k,v] of Object.entries({response_type:'code',response_mode:'query',scope:'openid',client_id:provider.audience,redirect_uri:redirect,state,nonce:c.nonce,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256',max_age:'0',prompt:'login',acr_values:requiredAcr}))authUrl.searchParams.set(k,v);
    return send(res,303,'',{Location:authUrl.href,'Set-Cookie':secure(flow,browser,300)});
   }
   if(url.pathname==='/auth/callback'){
    if(req.method!=='GET')return send(res,405);
    if(await resolveSession(req))return send(res,409,'Already signed in');
    // Require issuer response parameter (RFC 9207) and exactly one of each field.
    if([...url.searchParams.keys()].length!==3||!['state','code','iss'].every(k=>url.searchParams.getAll(k).length===1)||url.searchParams.get('iss')!==provider.issuer)throw Error('callback denied');
    const state=url.searchParams.get('state'),code=url.searchParams.get('code'),browser=cookie(req,flow);
    if(!browser||typeof code!=='string'||!/^[\x21-\x7e]{1,2048}$/.test(code))throw Error('callback denied');
    const sealed=await db.takeFlow(digestOpaque(state),digestOpaque(browser));if(!sealed)throw Error('callback denied');
    const c=unseal(sealed,'flow',state);
    const body=new URLSearchParams({grant_type:'authorization_code',code,redirect_uri:redirect,code_verifier:c.verifier,client_id:provider.audience});
    const credential=Buffer.from(provider.audience+':'+clientSecret).toString('base64');
    const upstream=await fetcher(token.href,{method:'POST',redirect:'error',signal:AbortSignal.timeout(5000),headers:{'Content-Type':'application/x-www-form-urlencoded',Authorization:'Basic '+credential,Accept:'application/json'},body});
    const idToken=await boundedJson(upstream);
    // Check exact nonce before redeeming any challenge.
    if((await provider.verify(idToken,now())).nonce!==c.nonce)throw Error('callback denied');
    const result=await gateway.exchange({idToken,binding:c.binding});
    const p=verifyIdentityToken(result.token,{...localVerifier,now:now()}),h=random();
    try{if(!await db.storeBrowserSession(digestOpaque(h),p.sessionId,seal({token:result.token},'session',h)))throw Error('session unavailable');}
    catch(e){try{await gateway.logout(result.token);}catch{}throw e;}
    try{await db.recordAuth('completed');}catch{}
    return send(res,303,'',{Location:'/','Set-Cookie':[secure(flow,'',0),secure(session,h,Math.max(0,p.expiresAt-now()))]});
   }
   if(url.pathname==='/auth/logout'||url.pathname==='/auth/logout-all'){
    if(req.method!=='POST'||url.search||req.headers.origin!==app.origin)return send(res,403,'Request denied');
    const h=cookie(req,session);
    if(url.pathname==='/auth/logout-all'){
     if(!h||!await db.logoutAllBrowser(digestOpaque(h)))return send(res,401,'Authentication required');
    }else if(h)await db.logoutBrowser(digestOpaque(h));
    return send(res,204,'',{'Set-Cookie':[secure(session,'',0),secure(flow,'',0)]});
   }
   if(req.method!=='GET'||url.search)return send(res,405);
   return send(res,(await resolveSession(req))?204:401);
  }catch{if(url.pathname==='/auth/callback')try{await db.recordAuth('denied');}catch{}return send(res,url.pathname==='/auth/callback'?401:503,'Authentication unavailable');}
  finally{active--;}
 }
 return Object.freeze({handler,resolveSession});
}
