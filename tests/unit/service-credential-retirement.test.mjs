import test from 'node:test';
import assert from 'node:assert/strict';
import {
 retireServiceCredential,
 CredentialRetirementStateUncertainError,
 CredentialRetirementSessionsUnverifiedError
} from '../../src/security/service-credential-retirement.mjs';

const args={role:'verivaro_monitor_reader',oldLogin:'vv_ci_tls_old',newLogin:'vv_ci_tls_new',confirm:'vv_ci_tls_old'};

function fixture({failAt=[],aligned=true,safe=true,afterCommit}={}){
 const queries=[],releases=[],failed=new Set(failAt);
 const lease={
  async query(sql){
   queries.push(sql);
   for(const prefix of failed)if(sql.startsWith(prefix))throw Error('synthetic transport fault');
   if(sql==='SELECT current_user=session_user AS aligned')return {rows:[{aligned}]};
   if(sql.includes('FROM pg_catalog.pg_roles l CROSS JOIN pg_catalog.pg_roles g'))
    return {rows:[{name:args.oldLogin,safe:true},{name:args.newLogin,safe}]};
   if(sql==='COMMIT')afterCommit?.();
   if(sql.includes('count(*)::int AS remaining'))return {rows:[{remaining:0}]};
   return {rows:[]};
  },
  release(error){releases.push(error);}
 };
 return {pool:{totalCount:1,connect:async()=>lease},queries,releases};
}
function expectDestroyed(f){
 assert.equal(f.releases.length,1);
 assert.ok(f.releases[0] instanceof Error,'pool lease must be destroyed, never recycled');
}
test('pool-owned retirement destroys privileged connection even after successful rotation',async()=>{
 const f=fixture();const result=await retireServiceCredential(f.pool,args);
 assert.deepEqual(result,{retired:true,remainingSessions:0});
 assert.ok(f.queries.includes('DISCARD ALL'));
 assert.ok(f.queries.includes('COMMIT'));
 assert.ok(f.queries.some(q=>q.startsWith('SELECT pg_catalog.pg_terminate_backend')));
 expectDestroyed(f);
});
test('client-style invocation cannot perform privileged retirement',async()=>{
 const client={query:async()=>({rows:[]}),connect:async()=>{}};
 await assert.rejects(retireServiceCredential(client,args),/dedicated administrator pool required/);
});
test('reused administrator role is rejected before BEGIN and the lease destroyed',async()=>{
 const f=fixture({aligned:false});
 await assert.rejects(retireServiceCredential(f.pool,args),/credential retirement failed/);
 assert.ok(!f.queries.includes('BEGIN'));expectDestroyed(f);
});
test('unsafe replacement rolls back and leaves the original credential active',async()=>{
 const f=fixture({safe:false});
 await assert.rejects(retireServiceCredential(f.pool,args),/credential retirement failed/);
 assert.ok(f.queries.includes('ROLLBACK'));
 assert.ok(!f.queries.some(q=>q.startsWith('ALTER ROLE')));
 assert.ok(!f.queries.includes('COMMIT'));expectDestroyed(f);
});
test('REVOKE failure performs rollback and destroys the session',async()=>{
 const f=fixture({failAt:['REVOKE']});
 await assert.rejects(retireServiceCredential(f.pool,args),/credential retirement failed/);
 assert.ok(f.queries.some(q=>q.startsWith('ALTER ROLE')));
 assert.ok(f.queries.includes('ROLLBACK'));
 assert.ok(!f.queries.includes('COMMIT'));expectDestroyed(f);
});
test('failed rollback creates explicit uncertain outcome; never reuses administrator socket',async()=>{
 const f=fixture({failAt:['REVOKE','ROLLBACK']});
 await assert.rejects(retireServiceCredential(f.pool,args),CredentialRetirementStateUncertainError);
 assert.ok(f.queries.includes('ROLLBACK'));expectDestroyed(f);
});
test('failed COMMIT is uncertain even if a later ROLLBACK appears to succeed',async()=>{
 const f=fixture({failAt:['COMMIT']});
 await assert.rejects(retireServiceCredential(f.pool,args),CredentialRetirementStateUncertainError);
 assert.ok(f.queries.includes('COMMIT'));
 assert.ok(f.queries.includes('ROLLBACK'));expectDestroyed(f);
});
test('backend termination failure after COMMIT reports incomplete, not rolled back',async()=>{
 const f=fixture({failAt:['SELECT pg_catalog.pg_terminate_backend']});
 await assert.rejects(retireServiceCredential(f.pool,args),CredentialRetirementSessionsUnverifiedError);
 assert.ok(f.queries.includes('COMMIT'));
 assert.ok(!f.queries.includes('ROLLBACK'));expectDestroyed(f);
});
test('abort immediately after COMMIT reports unverified backend termination',async()=>{
 const controller=new AbortController();
 const f=fixture({afterCommit:()=>controller.abort()});
 await assert.rejects(retireServiceCredential(f.pool,{...args,signal:controller.signal}),
  CredentialRetirementSessionsUnverifiedError);
 assert.ok(f.queries.includes('COMMIT'));
 assert.ok(!f.queries.some(q=>q.startsWith('SELECT pg_catalog.pg_terminate_backend')));
 expectDestroyed(f);
});
test('acquisition failure and invalid confirmation cannot run retirement DDL',async()=>{
 const f=fixture();
 await assert.rejects(retireServiceCredential(f.pool,{...args,confirm:'wrong'}),
  /explicit retirement confirmation required/);
 assert.equal(f.queries.length,0);assert.equal(f.releases.length,0);
 const failing={totalCount:0,connect:async()=>{throw Error('synthetic host secret');}};
 await assert.rejects(retireServiceCredential(failing,args),/credential retirement failed/);
});
