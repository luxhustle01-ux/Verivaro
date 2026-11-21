import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve,join} from 'node:path';
import {loadServicePoolConfig} from '../../src/security/service-pool-config.mjs';
import {createMonitorDatabase} from '../../src/security/monitor-database.mjs';
import {retireServiceCredential} from '../../src/security/service-credential-retirement.mjs';
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||!process.env.VV_TLS_FIXTURE||!process.env.VV_TEST_DRIVER_DIR)throw Error('disposable TLS CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const dir=process.env.VV_TLS_FIXTURE,role='verivaro_monitor_reader';
const config={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:2,connectionTimeoutMillis:3000};
const env=(login,which,extra={})=>({PGHOST:'localhost',PGPORT:process.env.PGPORT,PGUSER:login,PGDATABASE:'verivaro_test',VV_DB_PASSWORD_FILE:join(dir,which+'-password'),VV_DB_CA_FILE:join(dir,'ca.pem'),...extra});
test('live PostgreSQL TLS rejects wrong CA, hostname and plaintext; credential retirement terminates old sessions',{timeout:90000},async()=>{
 const admin=new Pool({...config,user:process.env.PGUSER,password:process.env.PGPASSWORD});
 const oldLogin='vv_ci_tls_old',newLogin='vv_ci_tls_new';
 const oldCfg=await loadServicePoolConfig({env:env(oldLogin,'old'),role}),newCfg=await loadServicePoolConfig({env:env(newLogin,'new'),role});
 const oldPool=new Pool(oldCfg),newPool=new Pool(newCfg);let held;
 oldPool.on('error',()=>{});newPool.on('error',()=>{});
 async function rejected(settings,pattern){const pool=new Pool(settings);try{await assert.rejects(pool.connect(),pattern);}finally{await pool.end();}}
 try{
  const valid=createMonitorDatabase(oldPool,{mode:'reader',expectedLogin:oldLogin});assert.ok((await valid.snapshot()).health);
  const tls=await oldPool.query('SELECT ssl,version,cipher FROM pg_stat_ssl WHERE pid=pg_backend_pid()');
  assert.equal(tls.rows[0].ssl,true);assert.match(tls.rows[0].version,/^TLSv1\.[23]$/);console.log('verified_postgresql_tls='+tls.rows[0].version);
  await rejected(await loadServicePoolConfig({env:env(oldLogin,'old',{VV_DB_CA_FILE:join(dir,'wrong.pem')}),role}),/certificate|self.signed|issuer/i);
  await rejected(await loadServicePoolConfig({env:env(oldLogin,'old',{PGHOST:'vv-wrong.test'}),role}),/hostname|altnames|certificate/i);
  await rejected({...oldCfg,ssl:false},/pg_hba|reject|encryption/i);
  const replacement=createMonitorDatabase(newPool,{mode:'reader',expectedLogin:newLogin});assert.ok((await replacement.snapshot()).health);
  // Incident regression: the existing credential MUST remain usable while an
  // unexpected elevated replacement is rejected without any retirement DDL.
  await admin.query('GRANT pg_read_all_data TO vv_ci_tls_new');
  try{
   await assert.rejects(retireServiceCredential(admin,{role,oldLogin,newLogin,confirm:oldLogin}),/credential retirement failed/);
   assert.equal((await oldPool.query('SELECT 1 AS ok')).rows[0].ok,1);
  }finally{await admin.query('REVOKE pg_read_all_data FROM vv_ci_tls_new');}
  await admin.query('GRANT verivaro_monitor_reader TO vv_ci_tls_new WITH ADMIN OPTION');
  try{
   await assert.rejects(retireServiceCredential(admin,{role,oldLogin,newLogin,confirm:oldLogin}),/credential retirement failed/);
   assert.equal((await oldPool.query('SELECT 1 AS ok')).rows[0].ok,1);
  }finally{await admin.query('REVOKE ADMIN OPTION FOR verivaro_monitor_reader FROM vv_ci_tls_new');}
  // A replacement with unexpected *direct* ACLs must never trigger
  // old-login retirement. Membership checks alone are insufficient.
  async function rejectDirectGrant(grant,revoke){
   await admin.query(grant);
   try{
    await assert.rejects(
     retireServiceCredential(admin,{role,oldLogin,newLogin,confirm:oldLogin}),
     /credential retirement failed/);
    // Old login remains authenticated, including during denied retirement.
    assert.equal((await oldPool.query('SELECT 1 AS ok')).rows[0].ok,1);
   }finally{await admin.query(revoke);}
   assert.ok((await replacement.snapshot()).health);
  }
  await rejectDirectGrant(
   'GRANT USAGE ON SCHEMA verivaro_private TO vv_ci_tls_new',
   'REVOKE USAGE ON SCHEMA verivaro_private FROM vv_ci_tls_new');
  await rejectDirectGrant(
   'GRANT SELECT ON TABLE verivaro_private.context_key TO vv_ci_tls_new',
   'REVOKE SELECT ON TABLE verivaro_private.context_key FROM vv_ci_tls_new');
  await rejectDirectGrant(
   'GRANT EXECUTE ON FUNCTION verivaro.bound_context() TO vv_ci_tls_new',
   'REVOKE EXECUTE ON FUNCTION verivaro.bound_context() FROM vv_ci_tls_new');
  await rejectDirectGrant(
   'ALTER DEFAULT PRIVILEGES IN SCHEMA verivaro_private GRANT SELECT ON TABLES TO vv_ci_tls_new',
   'ALTER DEFAULT PRIVILEGES IN SCHEMA verivaro_private REVOKE SELECT ON TABLES FROM vv_ci_tls_new');
  // Both the replacement and its group must be free of persistent startup
  // overrides before the old authenticated identity can be retired.
  await rejectDirectGrant(
   'ALTER ROLE vv_ci_tls_new SET search_path TO public',
   'ALTER ROLE vv_ci_tls_new RESET search_path');
  await rejectDirectGrant(
   "ALTER ROLE verivaro_monitor_reader SET statement_timeout = '10s'",
   'ALTER ROLE verivaro_monitor_reader RESET statement_timeout');
  await rejectDirectGrant(
   "ALTER DATABASE verivaro_test SET work_mem = '16MB'",
   'ALTER DATABASE verivaro_test RESET work_mem');
  // A credential replacement must satisfy the full admission catalogue
  // policy, not a shorter retirement-only subset.
  await rejectDirectGrant(
   'GRANT SET ON PARAMETER session_replication_role TO vv_ci_tls_new',
   'REVOKE SET ON PARAMETER session_replication_role FROM vv_ci_tls_new');
  await rejectDirectGrant(
   'GRANT EXECUTE ON FUNCTION pg_catalog.pg_backend_pid() TO vv_ci_tls_new',
   'REVOKE EXECUTE ON FUNCTION pg_catalog.pg_backend_pid() FROM vv_ci_tls_new');
  await rejectDirectGrant(
   'GRANT CREATE ON DATABASE verivaro_test TO verivaro_monitor_reader',
   'REVOKE CREATE ON DATABASE verivaro_test FROM verivaro_monitor_reader');
  await rejectDirectGrant(
   'GRANT SET ON PARAMETER session_replication_role TO verivaro_monitor_reader',
   'REVOKE SET ON PARAMETER session_replication_role FROM verivaro_monitor_reader');
  // Ownership outside the connected database is also disqualifying.
  await admin.query('CREATE DATABASE vv_ci_tls_owned_db OWNER vv_ci_tls_new');
  try{
   await assert.rejects(
    retireServiceCredential(admin,{role,oldLogin,newLogin,confirm:oldLogin}),
    /credential retirement failed/);
   assert.equal((await oldPool.query('SELECT 1 AS ok')).rows[0].ok,1);
  }finally{await admin.query('DROP DATABASE vv_ci_tls_owned_db');}
  assert.ok((await replacement.snapshot()).health);

  held=await oldPool.connect();held.on('error',()=>{});
  await held.query('SET ROLE verivaro_monitor_reader');
  const pid=held.processID;
  await assert.rejects(retireServiceCredential(admin,{role,oldLogin,newLogin,confirm:'wrong'}));
  const retired=await retireServiceCredential(admin,{role,oldLogin,newLogin,confirm:oldLogin});assert.deepEqual(retired,{retired:true,remainingSessions:0});
  assert.equal((await admin.query('SELECT count(*)::int AS n FROM pg_stat_activity WHERE pid=$1',[pid])).rows[0].n,0);
  await assert.rejects(held.query('SELECT 1'));
  await rejected(oldCfg,/not permitted|authentication|password|login/i);
  assert.ok((await replacement.snapshot()).health);
 }finally{held?.release(true);await oldPool.end();await newPool.end();await admin.end();}
});
