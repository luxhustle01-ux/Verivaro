import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {randomBytes} from 'node:crypto';
import {
 retireServiceCredential,
 CredentialRetirementStateUncertainError,
 CredentialRetirementSessionsUnverifiedError
} from '../../src/security/service-credential-retirement.mjs';

// Disposable CI PostgreSQL only. Never run this fault injector against Neon
// or an operator-provided database. No privileged staging credentials used.
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||
   !process.env.VV_TLS_FIXTURE||!process.env.VV_TEST_DRIVER_DIR||
   !process.env.VV_CI_PG_CONTAINER)
 throw Error('disposable PostgreSQL CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const cfg={
 host:process.env.PGHOST,port:Number(process.env.PGPORT),
 database:'verivaro_test',user:process.env.PGUSER,password:process.env.PGPASSWORD,
 connectionTimeoutMillis:3000,max:3
};
const group='verivaro_monitor_reader';

function interception(pool,{sqlPrefix,executeThenThrow=false,alsoFailRollback=false}){
 const releases=[];
 return {
  releases,
  proxy:{
   get totalCount(){return pool.totalCount;},
   async connect(){
    const client=await pool.connect();
    return {
     async query(sql,...args){
      if(typeof sql==='string'&&sql.startsWith(sqlPrefix)){
       if(executeThenThrow)await client.query(sql,...args);
       throw Error('synthetic client transport fault');
      }
      if(alsoFailRollback&&sql==='ROLLBACK')
       throw Error('synthetic rollback transport fault');
      return client.query(sql,...args);
     },
     release(err){releases.push(err);client.release(err);}
    };
   }
  }
 };
}
async function state(admin,oldLogin,newLogin){
 const r=await admin.query(`SELECT rolname,rolcanlogin
  FROM pg_catalog.pg_roles WHERE rolname = ANY($1::text[]) ORDER BY rolname`,
  [[oldLogin,newLogin]]);
 const m=await admin.query(`SELECT r.rolname
  FROM pg_catalog.pg_auth_members mem
  JOIN pg_catalog.pg_roles r ON r.oid=mem.member
  JOIN pg_catalog.pg_roles grp ON grp.oid=mem.roleid
  WHERE r.rolname=ANY($1::text[]) AND grp.rolname=$2`,
  [[oldLogin,newLogin],group]);
 return {roles:r.rows,members:new Set(m.rows.map(x=>x.rolname))};
}
async function withSyntheticPair(admin,suffix,task,{createOldSession=false}={}){
 const oldLogin='vv_ci_flt_'+suffix+'_old',newLogin='vv_ci_flt_'+suffix+'_new';
 const password=randomBytes(32).toString('hex');
 // Only fixed test-controlled ASCII identifiers reach DDL.
 for(const name of [oldLogin,newLogin]){
  assert.match(name,/^vv_ci_flt_[a-z]+_(?:old|new)$/);
  await admin.query(`CREATE ROLE "${name}" LOGIN NOINHERIT PASSWORD '${password}'`);
 }
 await admin.query(`GRANT ${group} TO "${oldLogin}","${newLogin}"
  WITH INHERIT FALSE, SET TRUE, ADMIN FALSE`);
 let held,oldPool;
 try{
  if(createOldSession){
   oldPool=new Pool({...cfg,user:oldLogin,password,max:1});
   held=await oldPool.connect();
   const authenticated=await held.query('SELECT session_user AS login');
   assert.equal(authenticated.rows[0].login,oldLogin);
  }
  await task({oldLogin,newLogin,held});
 }finally{
  if(held)held.release(true);
  if(oldPool)await oldPool.end();
  // The fixture is disposable, but cleanup is explicit and ordered.
  for(const name of [oldLogin,newLogin]){
   await admin.query(`DROP ROLE IF EXISTS "${name}"`);
  }
 }
}

test('real PostgreSQL state survives distinct rollback, uncertain commit and postcommit faults',
 {timeout:60000},async()=>{
 const admin=new Pool(cfg);
 try{
  await withSyntheticPair(admin,'rollback',async({oldLogin,newLogin})=>{
   const f=interception(admin,{sqlPrefix:'REVOKE "'+group+'"'});
   await assert.rejects(
    retireServiceCredential(f.proxy,{role:group,oldLogin,newLogin,confirm:oldLogin}),
    /credential retirement failed/);
   assert.equal(f.releases.length,1);
   assert.ok(f.releases[0] instanceof Error);
   const s=await state(admin,oldLogin,newLogin);
   assert.equal(s.roles.find(r=>r.rolname===oldLogin).rolcanlogin,true);
   assert.ok(s.members.has(oldLogin),'rollback must preserve old group membership');
  });
  await withSyntheticPair(admin,'rbuncert',async({oldLogin,newLogin})=>{
   const f=interception(admin,{
    sqlPrefix:'REVOKE "'+group+'"',
    alsoFailRollback:true
   });
   await assert.rejects(
    retireServiceCredential(f.proxy,{role:group,oldLogin,newLogin,confirm:oldLogin}),
    CredentialRetirementStateUncertainError);
   assert.equal(f.releases.length,1);
   assert.ok(f.releases[0] instanceof Error);
   // No COMMIT was issued. Destroying the PG socket rolls back the
   // uncommitted ALTER ROLE, unlike treating a missing ACK as proof.
   const s=await state(admin,oldLogin,newLogin);
   assert.equal(s.roles.find(r=>r.rolname===oldLogin).rolcanlogin,true);
   assert.ok(s.members.has(oldLogin));
  });
  await withSyntheticPair(admin,'commit',async({oldLogin,newLogin})=>{
   // PostgreSQL commits the real transaction, then the proxy loses ACK.
   const f=interception(admin,{sqlPrefix:'COMMIT',executeThenThrow:true});
   await assert.rejects(
    retireServiceCredential(f.proxy,{role:group,oldLogin,newLogin,confirm:oldLogin}),
    CredentialRetirementStateUncertainError);
   assert.equal(f.releases.length,1);
   assert.ok(f.releases[0] instanceof Error);
   const s=await state(admin,oldLogin,newLogin);
   assert.equal(s.roles.find(r=>r.rolname===oldLogin).rolcanlogin,false);
   assert.ok(!s.members.has(oldLogin),'committed membership removal must persist');
   assert.equal(s.roles.find(r=>r.rolname===newLogin).rolcanlogin,true);
   assert.ok(s.members.has(newLogin));
  });
  await withSyntheticPair(admin,'sessions',async({oldLogin,newLogin,held})=>{
   const pid=held.processID;
   const f=interception(admin,{sqlPrefix:'SELECT pg_catalog.pg_terminate_backend'});
   await assert.rejects(
    retireServiceCredential(f.proxy,{role:group,oldLogin,newLogin,confirm:oldLogin}),
    CredentialRetirementSessionsUnverifiedError);
   assert.equal(f.releases.length,1);
   assert.ok(f.releases[0] instanceof Error);
   const s=await state(admin,oldLogin,newLogin);
   assert.equal(s.roles.find(r=>r.rolname===oldLogin).rolcanlogin,false);
   assert.ok(!s.members.has(oldLogin));
   assert.equal((await admin.query(
    'SELECT count(*)::int AS count FROM pg_catalog.pg_stat_activity WHERE pid=$1',
    [pid])).rows[0].count,1,'old authenticated session must remain until authorised reconciliation');
   assert.equal((await held.query('SELECT 1 AS ok')).rows[0].ok,1);
  },{createOldSession:true});
 }finally{await admin.end();}
});
