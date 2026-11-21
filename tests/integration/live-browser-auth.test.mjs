import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {randomUUID,randomBytes,createHash} from 'node:crypto';
import {createServer} from 'node:http';
import {issuer,audience,provider,local,subject,token} from '../fixtures/provider-fixture.mjs';
import {digestSubject,digestOpaque} from '../../src/security/provider-identity.mjs';
import {createIdentityDatabase} from '../../src/security/identity-database.mjs';
import {createAuthenticationGateway} from '../../src/security/authentication-gateway.mjs';
import {createBrowserAuthentication} from '../../src/security/browser-authentication.mjs';
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_IDENTITY_PASSWORD)throw Error('disposable CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const cfg={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:4,connectionTimeoutMillis:3000};
test('real HTTP and PostgreSQL browser login, PKCE, CSRF, issuer, replay, opaque sessions and logout',{timeout:45000},async()=>{
 const admin=new Pool({...cfg,user:process.env.PGUSER,password:process.env.PGPASSWORD}),ip=new Pool({...cfg,user:'vv_ci_identity',password:process.env.VV_IDENTITY_PASSWORD});
 const db=createIdentityDatabase(ip,{expectedLogin:'vv_ci_identity'}),localVerifier={publicKey:local.publicKey,issuer:'urn:verivaro:local',audience:'api'};
 const asyncProvider=Object.freeze({...provider,verify:async (...args)=>provider.verify(...args)});
 const gateway=createAuthenticationGateway({db,provider:asyncProvider,localIssuer:localVerifier.issuer,localAudience:localVerifier.audience,privateKey:local.privateKey});
 const origin='https://verivaro.example.invalid',actor=randomUUID(),tenant='11111111-1111-4111-8111-111111111111',externalSubject='browser-subject';
 const secret=randomBytes(32).toString('base64url'),key=randomBytes(32),codes=new Map();let calls=0,server;
 const browser=createBrowserAuthentication({db,gateway,provider:asyncProvider,localVerifier,origin,authorizationEndpoint:issuer+'/authorize',tokenEndpoint:issuer+'/token',clientSecret:secret,key,requiredAcr:'fixture:mfa',fetcher:async(url,options)=>{
  calls++;assert.equal(url,issuer+'/token');assert.equal(options.redirect,'error');assert.equal(options.headers.Authorization,'Basic '+Buffer.from(audience+':'+secret).toString('base64'));
  const p=options.body,c=codes.get(p.get('code'));assert.ok(c);codes.delete(p.get('code'));
  assert.equal(p.get('grant_type'),'authorization_code');assert.equal(p.get('redirect_uri'),origin+'/auth/callback');
  assert.equal(createHash('sha256').update(p.get('code_verifier')).digest('base64url'),c.challenge);
  return new Response(JSON.stringify({id_token:token(c.nonce,{sub:externalSubject,...c.override}),access_token:'synthetic-unused'}),{headers:{'content-type':'application/json'}});
 }});
 try{
  await admin.query("INSERT INTO verivaro.memberships(tenant_id,actor_id,role) VALUES($1,$2,'viewer')",[tenant,actor]);
  await admin.query('SELECT verivaro_identity.provision_binding($1,$2,$3,$4)',[issuer,digestSubject(externalSubject),actor,randomUUID()]);
  server=createServer((req,res)=>{
   if(req.url==='/fixture-protected'){
    browser.resolveSession(req).then(t=>{res.writeHead(t?204:401);res.end();},()=>{res.writeHead(503);res.end();});
   }else browser.handler(req,res);
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const base='http://127.0.0.1:'+server.address().port;
  const request=(path,opts={})=>fetch(base+path,{redirect:'manual',...opts});
  async function begin(){
   const r=await request('/auth/login',{method:'POST',headers:{origin}});assert.equal(r.status,303);
   const cookie=r.headers.getSetCookie()[0];assert.match(cookie,/^__Host-vv_flow=/);assert.match(cookie,/Secure; HttpOnly; SameSite=Lax/);assert.doesNotMatch(cookie,/Domain=/);
   const u=new URL(r.headers.get('location')),state=u.searchParams.get('state'),nonce=u.searchParams.get('nonce'),code=randomUUID();
   assert.equal(u.origin,issuer);assert.equal(u.searchParams.get('code_challenge_method'),'S256');assert.equal(u.searchParams.get('redirect_uri'),origin+'/auth/callback');
   codes.set(code,{nonce,challenge:u.searchParams.get('code_challenge')});
   return {state,code,cookie:cookie.split(';')[0],path:'/auth/callback?'+new URLSearchParams({state,code,iss:issuer})};
  }
  assert.equal((await request('/auth/login',{method:'POST',headers:{origin:'https://evil.invalid'}})).status,403);
  assert.equal((await request('/auth/login')).status,403);
  const a=await begin(),b=await begin();
  assert.equal((await request(a.path,{headers:{cookie:b.cookie}})).status,401);
  assert.equal((await request(a.path+'&state='+a.state,{headers:{cookie:a.cookie}})).status,401);
  assert.equal((await request(a.path.replace(encodeURIComponent(issuer),encodeURIComponent('https://evil.invalid')),{headers:{cookie:a.cookie}})).status,401);
  assert.equal(calls,0);
  const results=await Promise.all(Array.from({length:4},()=>request(a.path,{headers:{cookie:a.cookie}})));
  assert.equal(results.filter(r=>r.status===303).length,1);assert.equal(calls,1);
  const success=results.find(r=>r.status===303),cookies=success.headers.getSetCookie();
  assert.equal(success.headers.get('location'),'/');assert.equal(await success.text(),'');
  const full=cookies.find(c=>c.startsWith('__Host-vv_session='));assert.match(full,/Secure; HttpOnly; SameSite=Lax/);assert.doesNotMatch(full,/Domain=/);
  const sess=full.split(';')[0],handle=sess.split('=')[1];assert.equal(handle.length,43);
  const row=(await admin.query('SELECT envelope FROM verivaro_private.browser_sessions WHERE handle_hash=$1',[digestOpaque(handle)])).rows[0];
  assert.ok(row.envelope.length>43);assert.equal(row.envelope.includes(Buffer.from('eyJ')),false);
  assert.equal((await request('/auth/session',{headers:{cookie:sess}})).status,204);
  assert.equal((await request('/fixture-protected',{headers:{cookie:sess}})).status,204);
  assert.equal((await request('/auth/session',{headers:{cookie:sess+'; '+sess}})).status,401);
  assert.equal((await request('/auth/login',{method:'POST',headers:{origin,cookie:sess}})).status,409);
  assert.equal((await request('/auth/logout',{method:'POST',headers:{origin:'https://evil.invalid',cookie:sess}})).status,403);
  assert.equal((await request('/auth/session',{headers:{cookie:sess}})).status,204);
  const logout=await request('/auth/logout',{method:'POST',headers:{origin,cookie:sess}});assert.equal(logout.status,204);assert.match(logout.headers.getSetCookie()[0],/Max-Age=0/);
  assert.equal((await request('/auth/session',{headers:{cookie:sess}})).status,401);
  assert.equal((await request(a.path,{headers:{cookie:a.cookie}})).status,401);
  const bad=await begin();codes.get(bad.code).override={nonce:randomBytes(32).toString('base64url')};
  assert.equal((await request(bad.path,{headers:{cookie:bad.cookie}})).status,401);
  assert.equal((await request(bad.path,{headers:{cookie:bad.cookie}})).status,401);
  const next=await begin();const newSession=await request(next.path,{headers:{cookie:next.cookie}});
  assert.equal(newSession.status,303);const ns=newSession.headers.getSetCookie().find(c=>c.startsWith('__Host-vv_session=')).split(';')[0];
  await admin.query('SELECT verivaro_identity.disable_binding($1,$2,$3)',[issuer,digestSubject(externalSubject),randomUUID()]);
  assert.equal((await request('/auth/session',{headers:{cookie:ns}})).status,401);
  await assert.rejects(ip.query('SELECT * FROM verivaro_private.browser_sessions'),e=>e.code==='42501');
 }finally{if(server)await new Promise(r=>{server.closeAllConnections();server.close(r);});await admin.end();await ip.end();}
});
