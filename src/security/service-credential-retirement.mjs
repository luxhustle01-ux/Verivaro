import {validateServiceIdentity,SERVICE_IDENTITY_UNSAFE} from './service-login.mjs';
import {setTimeout as delay} from 'node:timers/promises';
// Explicit admin-operated action, never invoked automatically by a service.
// Independently rechecks both identities using the same catalogue policy as
// service admission before the old credential can be disabled.
export async function retireServiceCredential(client,{role,oldLogin,newLogin,confirm}){
 validateServiceIdentity(role,oldLogin);validateServiceIdentity(role,newLogin);
 if(oldLogin===newLogin||confirm!==oldLogin)throw Error('explicit retirement confirmation required');
 let transaction=false;
 try{
  await client.query('BEGIN');transaction=true;
  // The operator's ambient search_path must not affect privilege resolution.
  await client.query('SET LOCAL search_path TO pg_catalog');
  // Both principals must be *exactly* the dedicated non-privileged service
  // logins, never an arbitrary group member or elevated replacement. Do not
  // trust inherited or transitive membership as a retirement precondition.
  const r=await client.query(String.raw`SELECT l.rolname::text AS name,
   (
    NOT (${SERVICE_IDENTITY_UNSAFE})
    -- An expired old credential may be retired, but the proposed replacement
    -- must still be valid now.
    AND (l.rolname::text<>$2 OR l.rolvaliduntil IS NULL
      OR l.rolvaliduntil>clock_timestamp())
   ) AS safe
   FROM pg_catalog.pg_roles l CROSS JOIN pg_catalog.pg_roles g
   WHERE l.rolname::text IN ($1,$2) AND g.rolname::text=$3`,[oldLogin,newLogin,role]);
  if(r.rows.length!==2||new Set(r.rows.map(x=>x.name)).size!==2||
     !r.rows.some(x=>x.name===oldLogin)||!r.rows.some(x=>x.name===newLogin)||
     r.rows.some(x=>x.safe!==true))
    throw Error('credential retirement precondition failed');
  // Identifiers are strictly bounded ASCII, never caller-provided SQL.
  await client.query('ALTER ROLE "'+oldLogin+'" NOLOGIN PASSWORD NULL');
  await client.query('REVOKE "'+role+'" FROM "'+oldLogin+'"');
  await client.query('COMMIT');transaction=false;
 }catch{
  if(transaction)try{await client.query('ROLLBACK');}catch{}
  throw Error('credential retirement failed');
 }
 // NOLOGIN prevents new authentication; terminating existing backends is
 // separate because changing a password alone does not invalidate sessions.
 for(let i=0;i<30;i++){
  await client.query('SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE usename=$1 AND pid<>pg_backend_pid()',[oldLogin]);
  const r=await client.query('SELECT count(*)::int AS remaining FROM pg_catalog.pg_stat_activity WHERE usename=$1',[oldLogin]);
  if(r.rows[0]?.remaining===0)return {retired:true,remainingSessions:0};
  await delay(100);
 }
 throw Error('credential retired; session termination not confirmed');
}
