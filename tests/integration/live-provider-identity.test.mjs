import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import {issuer,audience,provider,local,subject,token} from '../fixtures/provider-fixture.mjs';
import {digestSubject} from '../../src/security/provider-identity.mjs';
import {createIdentityDatabase} from '../../src/security/identity-database.mjs';
import {createAuthenticationGateway} from '../../src/security/authentication-gateway.mjs';
import {verifyIdentityToken} from '../../src/security/verify-identity.mjs';
import {createScopedDatabase} from '../../src/security/scoped-database.mjs';
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_IDENTITY_PASSWORD)throw Error('disposable CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const cfg={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:4,connectionTimeoutMillis:3000};
test('real MFA gateway, atomic nonce consumption, local RLS access, logout and binding disable',{timeout:30000},async()=>{
 const admin=new Pool({...cfg,user:process.env.PGUSER,password:process.env.PGPASSWORD}),ip=new Pool({...cfg,user:'vv_ci_identity',password:process.env.VV_IDENTITY_PASSWORD}),rp=new Pool({...cfg,user:'vv_ci_runtime',password:process.env.VV_RUNTIME_PASSWORD});
 const db=createIdentityDatabase(ip,{expectedLogin:'vv_ci_identity'});
 const asyncProvider=Object.freeze({...provider,verify:async (...args)=>provider.verify(...args)});
 const gw=createAuthenticationGateway({db,provider:asyncProvider,localIssuer:'urn:verivaro:local',localAudience:'api',privateKey:local.privateKey});
 const tenant='11111111-1111-4111-8111-111111111111',project='33333333-3333-4333-8333-333333333333',actor=randomUUID();
 const localVerifier={publicKey:local.publicKey,issuer:'urn:verivaro:local',audience:'api'};
 try{
  await admin.query("INSERT INTO verivaro.memberships(tenant_id,actor_id,role) VALUES($1,$2,'viewer')",[tenant,actor]);
  await admin.query("INSERT INTO verivaro.project_members(tenant_id,project_id,actor_id,role) VALUES($1,$2,$3,'viewer')",[tenant,project,actor]);
  await admin.query('SELECT verivaro_identity.provision_binding($1,$2,$3,$4)',[issuer,digestSubject(subject),actor,randomUUID()]);
  const key=(await admin.query('SELECT key_bytes FROM verivaro_private.context_key WHERE singleton')).rows[0].key_bytes;
  const scoped=createScopedDatabase(rp,{key,verifier:localVerifier,expectedLogin:'vv_ci_runtime'});
  const c=await gw.begin(),idToken=token(c.nonce),wrong=await gw.begin();
  await assert.rejects(gw.exchange({idToken,binding:wrong.binding}));
  await assert.rejects(gw.exchange({idToken:token(c.nonce,{sub:'unknown'}),binding:c.binding}));
  await assert.rejects(gw.exchange({idToken:token(c.nonce,{amr:['pwd']}),binding:c.binding}));
  const results=await Promise.allSettled(Array.from({length:4},()=>gw.exchange({idToken,binding:c.binding})));
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
  const result=results.find(r=>r.status==='fulfilled').value,p=verifyIdentityToken(result.token,localVerifier);
  assert.equal(p.actorId,actor);
  assert.deepEqual((await scoped.execute({token:result.token,tenantId:tenant,operation:'listProjects'})).map(x=>x.id),[project]);
  assert.equal(await gw.logout(result.token),true);
  await assert.rejects(scoped.execute({token:result.token,tenantId:tenant,operation:'listProjects'}));
  await assert.rejects(gw.exchange({idToken,binding:c.binding}));
  const fresh=await gw.begin(),newToken=await gw.exchange({idToken:token(fresh.nonce),binding:fresh.binding});
  assert.equal(await admin.query('SELECT verivaro_identity.disable_binding($1,$2,$3) AS ok',[issuer,digestSubject(subject),randomUUID()]).then(r=>r.rows[0].ok),true);
  await assert.rejects(scoped.execute({token:newToken.token,tenantId:tenant,operation:'listProjects'}));
  const later=await gw.begin();await assert.rejects(gw.exchange({idToken:token(later.nonce),binding:later.binding}));
  const cc=await ip.connect();
  try{
   await cc.query('SET ROLE verivaro_identity_service');
   await assert.rejects(cc.query('SELECT verivaro_identity.register_session($1,$2,now(),now()+interval \'5 minutes\')',[actor,randomUUID()]),e=>e.code==='42501');
   await assert.rejects(cc.query('SELECT verivaro_identity.provision_binding($1,$2,$3,$4)',[issuer,digestSubject('other'),actor,randomUUID()]),e=>e.code==='42501');
   await assert.rejects(cc.query('SELECT * FROM verivaro_private.provider_bindings'),e=>e.code==='42501');
  }finally{cc.release(true);}
 }finally{await admin.end();await ip.end();await rp.end();}
});
