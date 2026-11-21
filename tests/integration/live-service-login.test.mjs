import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {randomBytes} from 'node:crypto';
import {assertServiceLogin} from '../../src/security/service-login.mjs';
import {createDistributedAdmission} from '../../src/security/distributed-admission.mjs';
if(process.env.VV_LIVE_TEST!=='1'||process.env.PGDATABASE!=='verivaro_test'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_ADMISSION_PASSWORD)throw Error('disposable CI only');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const cfg={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:1,connectionTimeoutMillis:3000};
test('live dedicated service identity rejects indirect, direct and administrative privilege drift',{timeout:30000},async()=>{
 const admin=new Pool({...cfg,user:process.env.PGUSER,password:process.env.PGPASSWORD}),pool=new Pool({...cfg,user:'vv_ci_admission_a',password:process.env.VV_ADMISSION_PASSWORD});
 const role='verivaro_admission_service',login='vv_ci_admission_a',signal=new AbortController().signal;
 const adapter=createDistributedAdmission(pool,{peerKey:randomBytes(32),expectedLogin:login});
 async function check(expected=login,target=role){const c=await pool.connect();try{await c.query('DISCARD ALL');await assertServiceLogin(c,target,expected);}finally{c.release(true);}}
 async function rejectAfter(grant,revoke){
  await admin.query(grant);
  try{await assert.rejects(check());await assert.rejects(adapter.acquire('192.0.2.1',1024,signal),/admission operation failed/);}
  finally{await admin.query(revoke);}
  await check();
 }
 try{
  await check();
  await assert.rejects(check('vv_ci_admission_b'));await assert.rejects(check(login,'verivaro_alert_sender'));
  // Persistent startup settings are invisible to ordinary membership/ACL
  // checks. Refuse role-specific and database-scoped overrides regardless
  // of whether the GUC is innocuous: no hidden per-login defaults.
  await rejectAfter('ALTER ROLE vv_ci_admission_a SET search_path TO public',
    'ALTER ROLE vv_ci_admission_a RESET search_path');
  await rejectAfter("ALTER ROLE vv_ci_admission_a IN DATABASE verivaro_test SET work_mem = '16MB'",
    'ALTER ROLE vv_ci_admission_a IN DATABASE verivaro_test RESET work_mem');
  await rejectAfter("ALTER ROLE verivaro_admission_service SET statement_timeout = '10s'",
    'ALTER ROLE verivaro_admission_service RESET statement_timeout');
  // Database defaults apply to every service login even when neither login
  // nor NOLOGIN group has an ALTER ROLE override.
  await rejectAfter('ALTER DATABASE verivaro_test SET search_path TO public',
    'ALTER DATABASE verivaro_test RESET search_path');
  await rejectAfter("ALTER DATABASE verivaro_test SET work_mem = '16MB'",
    'ALTER DATABASE verivaro_test RESET work_mem');
  // An already-switched session must not pass as the authenticated login,
  // even if the target role is the otherwise approved service group.
  const switched=await pool.connect();
  try{
   await switched.query('DISCARD ALL');
   await switched.query('SET ROLE verivaro_admission_service');
   await assert.rejects(assertServiceLogin(switched,role,login),/unsafe service login/);
   await switched.query('RESET ROLE');
   await assertServiceLogin(switched,role,login);
  }finally{switched.release(true);}
  await rejectAfter('GRANT pg_read_all_data TO vv_ci_admission_a','REVOKE pg_read_all_data FROM vv_ci_admission_a');
  await rejectAfter('GRANT verivaro_monitor_reader TO vv_ci_admission_a','REVOKE verivaro_monitor_reader FROM vv_ci_admission_a');
  await rejectAfter('GRANT USAGE ON SCHEMA verivaro_private TO vv_ci_admission_a','REVOKE USAGE ON SCHEMA verivaro_private FROM vv_ci_admission_a');
  await rejectAfter('GRANT SELECT (key_bytes) ON verivaro_private.context_key TO vv_ci_admission_a','REVOKE SELECT (key_bytes) ON verivaro_private.context_key FROM vv_ci_admission_a');
  await rejectAfter('GRANT CREATE ON SCHEMA public TO vv_ci_admission_a','REVOKE CREATE ON SCHEMA public FROM vv_ci_admission_a');
  await rejectAfter('GRANT verivaro_admission_service TO vv_ci_admission_a WITH ADMIN OPTION','REVOKE ADMIN OPTION FOR verivaro_admission_service FROM vv_ci_admission_a');

  // These privileges are independent of the authorized NOLOGIN service
  // membership. They must all be rejected on *direct service checkout*
  // before an application can issue an operation.
  await rejectAfter('GRANT USAGE ON SCHEMA public TO vv_ci_admission_a',
    'REVOKE USAGE ON SCHEMA public FROM vv_ci_admission_a');
  await rejectAfter('GRANT CONNECT ON DATABASE verivaro_test TO vv_ci_admission_a',
    'REVOKE CONNECT ON DATABASE verivaro_test FROM vv_ci_admission_a');
  // Direct privileges on pg_catalog are also independent grants, even
  // when PostgreSQL already gives PUBLIC access to the same object.
  await rejectAfter('GRANT EXECUTE ON FUNCTION pg_catalog.pg_backend_pid() TO vv_ci_admission_a',
    'REVOKE EXECUTE ON FUNCTION pg_catalog.pg_backend_pid() FROM vv_ci_admission_a');
  await rejectAfter('GRANT SELECT ON TABLE pg_catalog.pg_type TO vv_ci_admission_a',
    'REVOKE SELECT ON TABLE pg_catalog.pg_type FROM vv_ci_admission_a');
  // A login can own another database without CREATEDB on the currently
  // connected database; ownership is a cluster-level authority drift.
  await admin.query('CREATE DATABASE vv_ci_service_login_owned_db OWNER vv_ci_admission_a');
  try{
   await assert.rejects(check(),/unsafe service login/);
   await assert.rejects(adapter.acquire('192.0.2.1',1024,signal),/admission operation failed/);
  }finally{
   await admin.query('DROP DATABASE vv_ci_service_login_owned_db');
  }
  await check();
  // These grants live in distinct PostgreSQL privilege catalogues and must
  // not bypass an admission audit that otherwise checks schema/table ACLs.
  await rejectAfter('GRANT SET ON PARAMETER session_replication_role TO vv_ci_admission_a',
    'REVOKE SET ON PARAMETER session_replication_role FROM vv_ci_admission_a');
  await rejectAfter('GRANT USAGE ON LANGUAGE plpgsql TO vv_ci_admission_a',
    'REVOKE USAGE ON LANGUAGE plpgsql FROM vv_ci_admission_a');
  await rejectAfter('GRANT CREATE ON TABLESPACE pg_default TO vv_ci_admission_a',
    'REVOKE CREATE ON TABLESPACE pg_default FROM vv_ci_admission_a');
  // The approved group must not accumulate privileges usable after
  // SET ROLE, even when the dedicated login remains NOINHERIT.
  await rejectAfter('GRANT CREATE ON DATABASE verivaro_test TO verivaro_admission_service',
    'REVOKE CREATE ON DATABASE verivaro_test FROM verivaro_admission_service');
  await rejectAfter('GRANT CREATE ON SCHEMA public TO verivaro_admission_service',
    'REVOKE CREATE ON SCHEMA public FROM verivaro_admission_service');
  await rejectAfter('GRANT SET ON PARAMETER session_replication_role TO verivaro_admission_service',
    'REVOKE SET ON PARAMETER session_replication_role FROM verivaro_admission_service');
  await admin.query('CREATE DATABASE vv_ci_service_group_owned_db OWNER verivaro_admission_service');
  try{
   await assert.rejects(check(),/unsafe service login/);
   await assert.rejects(adapter.acquire('192.0.2.1',1024,signal),/admission operation failed/);
  }finally{
   await admin.query('DROP DATABASE vv_ci_service_group_owned_db');
  }
  await check();
  await admin.query('CREATE SEQUENCE verivaro_private.vv_ci_direct_grant_seq');
  try{
   await rejectAfter('GRANT USAGE ON SEQUENCE verivaro_private.vv_ci_direct_grant_seq TO vv_ci_admission_a',
     'REVOKE USAGE ON SEQUENCE verivaro_private.vv_ci_direct_grant_seq FROM vv_ci_admission_a');
  }finally{await admin.query('DROP SEQUENCE verivaro_private.vv_ci_direct_grant_seq');}
  await admin.query("CREATE TYPE verivaro_private.vv_ci_direct_grant_type AS ENUM ('ready')");
  try{
   await rejectAfter('GRANT USAGE ON TYPE verivaro_private.vv_ci_direct_grant_type TO vv_ci_admission_a',
     'REVOKE USAGE ON TYPE verivaro_private.vv_ci_direct_grant_type FROM vv_ci_admission_a');
  }finally{await admin.query('DROP TYPE verivaro_private.vv_ci_direct_grant_type');}
  await rejectAfter('ALTER DEFAULT PRIVILEGES IN SCHEMA verivaro_private GRANT SELECT ON TABLES TO vv_ci_admission_a',
    'ALTER DEFAULT PRIVILEGES IN SCHEMA verivaro_private REVOKE SELECT ON TABLES FROM vv_ci_admission_a');
  // PostgreSQL 16 membership is insufficient: SET=FALSE makes the service
  // unusable, while INHERIT=TRUE creates ambient privilege exposure.
  async function rejectMembershipOptions(inherit,set){
   await admin.query('REVOKE verivaro_admission_service FROM vv_ci_admission_a');
   await admin.query('GRANT verivaro_admission_service TO vv_ci_admission_a WITH INHERIT '+inherit+', SET '+set+', ADMIN FALSE');
   try{
    const direct=await admin.query(String.raw`SELECT m.inherit_option,m.set_option,m.admin_option
     FROM pg_catalog.pg_auth_members m
     JOIN pg_catalog.pg_roles member ON member.oid=m.member
     JOIN pg_catalog.pg_roles grp ON grp.oid=m.roleid
     WHERE member.rolname='vv_ci_admission_a' AND grp.rolname='verivaro_admission_service'`);
    assert.equal(direct.rows.length,1);
    assert.equal(direct.rows[0].inherit_option,inherit==='TRUE');
    assert.equal(direct.rows[0].set_option,set==='TRUE');
    await assert.rejects(check(),/unsafe service login/);
    await assert.rejects(adapter.acquire('192.0.2.1',1024,signal),/admission operation failed/);
   }finally{
    await admin.query('REVOKE verivaro_admission_service FROM vv_ci_admission_a');
    await admin.query('GRANT verivaro_admission_service TO vv_ci_admission_a WITH INHERIT FALSE, SET TRUE, ADMIN FALSE');
   }
   await check();
  }
  await rejectMembershipOptions('FALSE','FALSE');
  await rejectMembershipOptions('TRUE','TRUE');
  // A group role made LOGIN is specifically forbidden for a pinned deployment.
  await rejectAfter('ALTER ROLE verivaro_admission_service LOGIN','ALTER ROLE verivaro_admission_service NOLOGIN');
  await check();
  const c=await pool.connect();try{await c.query('DISCARD ALL');await assertServiceLogin(c,role,login);await c.query('SET ROLE verivaro_admission_service');assert.equal((await c.query('SELECT current_user AS role')).rows[0].role,role);}finally{c.release(true);}
 }finally{await pool.end();await admin.end();}
});
