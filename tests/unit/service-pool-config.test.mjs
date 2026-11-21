import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,chmod,symlink,mkdir,rm} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {loadServicePoolConfig} from '../../src/security/service-pool-config.mjs';
import {assertServiceLogin,validateServiceIdentity} from '../../src/security/service-login.mjs';
test('fixed service role and pinned identity reject unsafe configuration and mismatched database response',async()=>{
 const role='verivaro_monitor_worker',calls=[];
 const client={query:async(sql,values)=>{calls.push({sql,values});return {rows:[{privileged:false,login_name:'wrong'}]};}};
 await assert.rejects(assertServiceLogin(client,role,'vv_worker'));
 assert.equal(calls[0].sql,'SET search_path TO pg_catalog');assert.deepEqual(calls[1].values,[role,'vv_worker']);
 assert.match(calls[1].sql,/m\.inherit_option=false/);
 assert.match(calls[1].sql,/m\.set_option=true/);
 assert.match(calls[1].sql,/m\.admin_option=false/);
 for(const catalogue of ['pg_catalog.pg_namespace','pg_catalog.pg_class',
  'pg_catalog.pg_proc','pg_catalog.pg_type','pg_catalog.pg_default_acl',
  'pg_catalog.pg_database'])assert.ok(calls[1].sql.includes(catalogue),
   'expected direct privilege inventory: '+catalogue);
 assert.match(calls[1].sql,/a\.grantee=l\.oid/);
 assert.throws(()=>validateServiceIdentity('postgres','vv_worker'));assert.throws(()=>validateServiceIdentity(role,role));
});
test('private credentials only; loopback exception explicit; no environment TLS downgrade',async t=>{
 const root=await mkdtemp(join(tmpdir(),'vv-service-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const pw=join(root,'password'),link=join(root,'link'),secret=randomBytes(32).toString('base64url');
 await writeFile(pw,secret+'\n',{mode:0o600});await symlink(pw,link);
 const env={PGHOST:'127.0.0.1',PGUSER:'vv_worker',PGDATABASE:'verivaro_test',VV_DB_PASSWORD_FILE:pw,VV_ALLOW_LOCAL_PLAINTEXT:'1',VV_LIVE_TEST:'1'};
 const role='verivaro_monitor_worker';
 const config=await loadServicePoolConfig({env,role});assert.equal(config.password,secret);assert.equal(config.ssl,false);assert.equal(config.user,'vv_worker');
 for(const bad of [{PGHOST:'db.example.invalid'},{PGPASSWORD:secret},{PGSSLMODE:'disable'},{NODE_TLS_REJECT_UNAUTHORIZED:'0'},{PGOPTIONS:'-c role=postgres'},{VV_DB_PASSWORD_FILE:link},{PGUSER:role},{VV_ALLOW_LOCAL_PLAINTEXT:undefined},{VV_LIVE_TEST:undefined},{VV_LIVE_TEST:'0'},{PGDATABASE:'verivaro_production'},{PGDATABASE:'other_test'},{VV_DB_CA_FILE:pw}])await assert.rejects(loadServicePoolConfig({role,env:{...env,...bad}}));
 // A secret's final inode can be safe while its parent is attacker-writable
 // or a symbolic link. Deny such paths before opening the private file.
 const indirect=join(root,'parent-link');await symlink(root,indirect);
 await assert.rejects(loadServicePoolConfig({role,env:{...env,VV_DB_PASSWORD_FILE:join(indirect,'password')}}));
 const weak=join(root,'weak');await mkdir(weak,{mode:0o700});
 await writeFile(join(weak,'password'),secret,{mode:0o600});
 await chmod(weak,0o777);
 await assert.rejects(loadServicePoolConfig({role,env:{...env,VV_DB_PASSWORD_FILE:join(weak,'password')}}));
 await chmod(weak,0o770);
 await assert.rejects(loadServicePoolConfig({role,env:{...env,VV_DB_PASSWORD_FILE:join(weak,'password')}}));
 await chmod(weak,0o700);
 assert.equal((await loadServicePoolConfig({role,env:{...env,VV_DB_PASSWORD_FILE:join(weak,'password')}})).user,'vv_worker');
 await assert.rejects(loadServicePoolConfig({role,env:{...env,VV_DB_PASSWORD_FILE:root+'/weak/../password'}}));
 await chmod(pw,0o644);await assert.rejects(loadServicePoolConfig({role,env}));
});
