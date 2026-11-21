import {validateServiceIdentity,SERVICE_IDENTITY_UNSAFE} from './service-login.mjs';
import {setTimeout as delay} from 'node:timers/promises';

// A failed COMMIT may have reached PostgreSQL even if the client observed
// an error; a failed ROLLBACK also leaves the transaction state uncertain.
export class CredentialRetirementStateUncertainError extends Error {
 constructor(){super('credential retirement state uncertain; manual role and session reconciliation required');this.name='CredentialRetirementStateUncertainError';}
}
// An old login can be NOLOGIN while its authenticated sessions remain active.
export class CredentialRetirementSessionsUnverifiedError extends Error {
 constructor(){super('credential retired; backend termination unverified; manual reconciliation required');this.name='CredentialRetirementSessionsUnverifiedError';}
}
// Explicit admin-operated action; caller must own an authorised pool. Never
// invoke automatically from a service or on an existing caller-held client.
async function retireWithLeasedClient(client,{role,oldLogin,newLogin,signal}){
 let transaction=false,commitAttempted=false;
 try{
  // Do not operate on a borrowed privileged session with leaked state.
  // DISCARD ALL itself fails when an earlier transaction remains active.
  await client.query('DISCARD ALL');
  const identity=await client.query('SELECT current_user=session_user AS aligned');
  if(identity.rows.length!==1||identity.rows[0].aligned!==true)
   throw Error('unsafe administrator session');
  signal?.throwIfAborted();
  await client.query('BEGIN');transaction=true;
  await client.query("SET LOCAL lock_timeout = '2s'");
  await client.query("SET LOCAL statement_timeout = '5s'");
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
  signal?.throwIfAborted();
  await client.query('ALTER ROLE "'+oldLogin+'" NOLOGIN PASSWORD NULL');
  await client.query('REVOKE "'+role+'" FROM "'+oldLogin+'"');
  signal?.throwIfAborted();
  commitAttempted=true;
  await client.query('COMMIT');transaction=false;
 }catch{
  let rolledBack=!transaction;
  if(transaction)try{await client.query('ROLLBACK');rolledBack=true;}catch{}
  if(commitAttempted||!rolledBack)throw new CredentialRetirementStateUncertainError();
  throw Error('credential retirement failed');
 }
 // NOLOGIN blocks new sessions, but terminating pre-existing backends is a
 // separate operation AFTER COMMIT; never imply it can be rolled back.
 try{
  for(let i=0;i<30;i++){
   signal?.throwIfAborted();
   await client.query('SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE usename=$1 AND pid<>pg_backend_pid()',[oldLogin]);
   const r=await client.query('SELECT count(*)::int AS remaining FROM pg_catalog.pg_stat_activity WHERE usename=$1',[oldLogin]);
   if(r.rows.length!==1||!Number.isInteger(r.rows[0].remaining)||r.rows[0].remaining<0)
    throw Error('invalid session inventory');
   if(r.rows[0].remaining===0)return {retired:true,remainingSessions:0};
   await delay(100,undefined,{signal});
  }
 }catch{
  throw new CredentialRetirementSessionsUnverifiedError();
 }
 throw new CredentialRetirementSessionsUnverifiedError();
}

// Privileged rotations own their pool checkout. Client-style callers and
// borrowed administrator sessions are rejected: no implicit pool reuse.
export async function retireServiceCredential(pool,{role,oldLogin,newLogin,confirm,signal}){
 validateServiceIdentity(role,oldLogin);validateServiceIdentity(role,newLogin);
 if(oldLogin===newLogin||confirm!==oldLogin)throw Error('explicit retirement confirmation required');
 if(signal!==undefined&&(!signal||typeof signal.throwIfAborted!=='function'))
  throw Error('invalid retirement cancellation signal');
 if(!pool||typeof pool.connect!=='function'||!Number.isInteger(pool.totalCount))
  throw Error('dedicated administrator pool required');
 let lease;
 try{
  lease=await pool.connect();
  if(!lease||typeof lease.query!=='function'||typeof lease.release!=='function')
   throw Error('invalid administrator pool lease');
  return await retireWithLeasedClient(lease,{role,oldLogin,newLogin,signal});
 }catch(e){
  if(e instanceof CredentialRetirementStateUncertainError||
     e instanceof CredentialRetirementSessionsUnverifiedError)throw e;
  throw Error('credential retirement failed');
 }finally{
  // pg.PoolClient.release(error) discards the privileged physical connection
  // on every exit path, including success and transaction/transport failures.
  if(lease&&typeof lease.release==='function'){
   try{lease.release(new Error('destroy privileged retirement session'));}
   catch{throw new CredentialRetirementStateUncertainError();}
  }
 }
}
