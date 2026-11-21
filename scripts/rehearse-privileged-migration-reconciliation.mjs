// Executable ONLY on the fixed throwaway PostgreSQL 16 GitHub CI fixture.
// Replays all 63 real migrations with NO CREATEROLE on the schema executor.
// No production connection, credentials or real release authority supported.
import {spawn,spawnSync} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {TextDecoder} from 'node:util';
import {assertDisposableDatabase,createMigrationSql,createExpectedLedger,checkLedgerRows}
 from './ci-migration-ledger.mjs';
import {auditRepositoryMigrationChain} from '../src/security/migration-chain-audit.mjs';
import {createLegacyReconciliationPlan,privilegedBootstrapSql,ROLE_DDL_ATTRIBUTES}
 from '../src/security/legacy-role-reconciliation.mjs';

const DB='verivaro_role_reconcile_ci';
const OWNER='vv_ci_reconcile_schema_owner';
const EXECUTOR='vv_ci_reconcile_executor';
const CUSTODIAN='vv_ci_reconcile_ledger_custodian';
const LOGIN='vv_ci_reconcile_login';
const refuse=msg=>{throw Error('restricted reconciliation rehearsal failed: '+msg);};
function exec(program,args,env,input,ok=true){
 const result=spawnSync(program,args,{env,input,encoding:'utf8',timeout:120000,maxBuffer:4*1024*1024});
 if(result.error||result.signal||((result.status===0)!==ok))
  refuse(program+' command rejected or failed');
 return result.stdout?.trim()??'';
}
function psql(env,input){
 return exec('psql',['-X','-q','-v','ON_ERROR_STOP=1','-f','-'],env,input);
}
const q=name=>{if(!/^[a-z][a-z0-9_]{2,63}$/.test(name))refuse('unsafe role');return name;};
async function plan(){
 await auditRepositoryMigrationChain();
 const lock=JSON.parse(await readFile('db/migration-lock.json','utf8'));
 const rows=await Promise.all(lock.migrations.map(async x=>({path:x.path,bytes:await readFile(x.path)})));
 return createLegacyReconciliationPlan(rows);
}
function fixtureRoleSql(reconciliation,secret){
 const appRoles=privilegedBootstrapSql(reconciliation,{
  ownerRole:OWNER,executorRole:EXECUTOR,loginRole:LOGIN
 });
 if(!/^[0-9a-f]{64}$/.test(secret))refuse('invalid ephemeral secret');
 // Explicit ledger custodian cannot be inherited or SET by the executor.
 return 'BEGIN;\nCREATE ROLE '+CUSTODIAN+' '+ROLE_DDL_ATTRIBUTES+';\n'+
 'CREATE ROLE '+LOGIN+' LOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD '+
 "'"+secret+"';\n"+appRoles.replace('BEGIN;\n','').replace(/\nCOMMIT;\n$/,'\n')+
 'COMMIT;\n';
}
function fixtureLedgerSql(){
 return 'BEGIN;\n'+
 'CREATE SCHEMA verivaro_migration AUTHORIZATION '+CUSTODIAN+';\n'+
 'SET LOCAL ROLE '+CUSTODIAN+';\n'+
 'CREATE TABLE verivaro_migration.history ('+
 'version integer PRIMARY KEY CHECK (version BETWEEN 1 AND 500),'+
 'migration_path text NOT NULL UNIQUE,'+
 "file_sha256 char(64) NOT NULL CHECK (file_sha256 ~ '^[a-f0-9]{64}$'),"+
 "previous_hash char(64) NOT NULL CHECK (previous_hash ~ '^[a-f0-9]{64}$'),"+
 "entry_hash char(64) NOT NULL UNIQUE CHECK (entry_hash ~ '^[a-f0-9]{64}$'),"+
 'applied_at timestamptz NOT NULL DEFAULT transaction_timestamp());\n'+
 'GRANT USAGE ON SCHEMA verivaro_migration TO '+EXECUTOR+';\n'+
 'GRANT SELECT,INSERT ON verivaro_migration.history TO '+EXECUTOR+';\n'+
 'COMMIT;\n';
}
export function restrictedReconcileSql(items,version,transformedSql){
 let script=createMigrationSql(items,version,transformedSql);
 const first='BEGIN;\nSELECT pg_advisory_xact_lock';
 const marker='\\else\n',insert='INSERT INTO verivaro_migration.history';
 if(!script.startsWith(first)||script.split(marker).length!==2||
  script.split(insert).length!==2)
  refuse('transaction renderer contract drifted');
 script='SET ROLE '+EXECUTOR+';\n'+script;
 script=script.replace(marker,marker+'SET LOCAL ROLE '+OWNER+';\n');
 script=script.replace(insert,'SET LOCAL ROLE '+EXECUTOR+';\n'+insert);
 return script+'RESET ROLE;\n';
}

function inspect(env,sql){
 return exec('psql',['-X','-A','-t','-v','ON_ERROR_STOP=1','-c',sql],env);
}
const UPGRADE_SOURCE='verivaro_upgrade_source_ci',UPGRADE_TARGET='verivaro_upgrade_target_ci';
const upgradeHashSql="SELECT md5(COALESCE(string_agg(id::text||':'||name,',' ORDER BY id),'')) FROM verivaro.tenants";
const upgradeHistorySql='SELECT version,migration_path,file_sha256,previous_hash,entry_hash FROM verivaro_migration.history ORDER BY version';

export function assertInterruptedUpgradeState({historyCount,changedTableAbsent,sourceFingerprint,restoredFingerprint}){
 if(historyCount!=='62'||changedTableAbsent!=='t'||!(/^[a-f0-9]{32}$/.test(sourceFingerprint))||
  sourceFingerprint!==restoredFingerprint)
  refuse('interrupted staged upgrade advanced ledger, retained DDL or altered data');
 return Object.freeze({interruptedBeforeCommit:true,ledgerRolledBack:true,dataPreserved:true});
}
// The source remains at v62; only a physical clone is upgraded to v63.
// Both scratch DBs and all roles are removed before the workflow ends.
function terminateVerifiedStagingBackend(client,admin,script){
 // The restricted schema executor has NO pg_signal_backend privilege.
 // Only this disposable CI controller is allowed to kill its exact staged
 // backend after the migration DDL and ledger INSERT have been executed.
 return new Promise((resolve,reject)=>{
  const child=spawn('psql',['-X','-q','-v','ON_ERROR_STOP=1','-f','-'],{
   env:client,stdio:['pipe','pipe','pipe']
  });
  let stdout='',stderr='',killed=false,errored=null,closed=false;
  const watchdog=setTimeout(()=>{
   errored=Error('staged backend barrier not observed within 30 seconds');
   child.kill('SIGKILL');
  },30000);
  child.stdout.on('data',bytes=>{
   stdout+=bytes.toString('utf8');
   if(stdout.length>8192){errored=Error('oversized staged barrier output');child.kill('SIGKILL');return;}
   const found=/(?:^|\n)VV_STAGE_READY_(\d+)(?:\r?\n|$)/.exec(stdout);
   if(!found||killed||errored)return;
   killed=true;
   try{
    const pid=Number(found[1]);
    if(!Number.isSafeInteger(pid)||pid<1||pid>2147483647)
     throw Error('invalid staged PostgreSQL backend PID');
    const active=inspect(admin,"SELECT count(*) FROM pg_stat_activity WHERE pid="+pid+
     " AND datname='"+UPGRADE_TARGET+"' AND usename='"+LOGIN+"' AND state='active'");
    if(active!=='1')throw Error('staged backend identity and database do not match');
    if(inspect(admin,'SELECT pg_terminate_backend('+pid+')')!=='t')
     throw Error('CI administrator did not terminate the staged backend');
   }catch(error){errored=error;child.kill('SIGKILL');}
  });
  child.stderr.on('data',bytes=>{
   stderr+=bytes.toString('utf8');
   if(stderr.length>32768){errored=Error('oversized staged backend error');child.kill('SIGKILL');}
  });
  child.on('error',error=>{errored=error;});
  child.on('close',(code)=>{
   if(closed)return;closed=true;clearTimeout(watchdog);
   if(errored)return reject(Error('staged admin kill was not verified: '+errored.message));
   if(!killed||code===0||!/terminating connection due to administrator command/i.test(stderr))
    return reject(Error('expected scoped PostgreSQL backend termination did not occur'));
   resolve(Object.freeze({backendIdentityVerified:true,
    privilegedCIControllerTerminationVerified:true,
    restrictedMigratorGrantedSignalPrivilege:false}));
  });
  child.stdin.on('error',()=>{});
  child.stdin.end(script);
 });
}

async function rehearseStagedUpgrade(test,ledger,admin,client){
 let sourceCreated=false,targetCreated=false;
 try{
  exec('createdb',['-w','--template=template0',UPGRADE_SOURCE],admin);
  sourceCreated=true;
  const sourceAdmin={...admin,PGDATABASE:UPGRADE_SOURCE};
  const sourceClient={...client,PGDATABASE:UPGRADE_SOURCE};
  psql(sourceAdmin,'REVOKE CREATE ON DATABASE '+UPGRADE_SOURCE+' FROM PUBLIC;\n'+
   'GRANT CREATE ON DATABASE '+UPGRADE_SOURCE+' TO '+OWNER+';\n');
  psql(sourceAdmin,fixtureLedgerSql());
  for(const m of test.migrations.slice(0,62))
   psql(sourceClient,restrictedReconcileSql(ledger,m.version,m.transformedSql));
  if(inspect(sourceAdmin,'SELECT count(*) FROM verivaro_migration.history')!=='62')
   refuse('stage source did not reach version 62');
  // The privileged fixture inserts synthetic application data, not customer data.
  psql(sourceAdmin,"INSERT INTO verivaro.tenants(id,name) VALUES"+
   "('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','Synthetic staged upgrade tenant');");
  const before=inspect(sourceAdmin,upgradeHashSql);
  exec('createdb',['-w','--template='+UPGRADE_SOURCE,UPGRADE_TARGET],admin);
  targetCreated=true;
  const targetAdmin={...admin,PGDATABASE:UPGRADE_TARGET};
  const targetClient={...client,PGDATABASE:UPGRADE_TARGET};
  const migration=restrictedReconcileSql(ledger,63,test.migrations[62].transformedSql);
  const last='\\endif\nCOMMIT;\nRESET ROLE;\n';
  if(migration.split(last).length!==2)refuse('migration transaction injection anchor missing');
  const killed=migration.replace(last,
   '\\endif\nSELECT pg_backend_pid() AS vv_stage_pid \\gset\n'+
   '\\echo VV_STAGE_READY_:vv_stage_pid\n'+
   'SELECT pg_sleep(20);\nCOMMIT;\nRESET ROLE;\n');
  const termination=await terminateVerifiedStagingBackend(targetClient,targetAdmin,killed);
  if(!termination.privilegedCIControllerTerminationVerified)
   refuse('staging backend termination witness absent');
  assertInterruptedUpgradeState({
   historyCount:inspect(targetAdmin,'SELECT count(*) FROM verivaro_migration.history'),
   changedTableAbsent:inspect(targetAdmin,
    "SELECT to_regclass('verivaro_private.ocr_transcription_corrections') IS NULL"),
   sourceFingerprint:before,
   restoredFingerprint:inspect(targetAdmin,upgradeHashSql)
  });
  psql(targetClient,migration);
  const verified=checkLedgerRows(ledger,inspect(targetAdmin,upgradeHistorySql).split('\n'));
  if(verified.verifiedVersions!==63||verified.head!==ledger[62].entry_hash||
   inspect(targetAdmin,upgradeHashSql)!==before||
   inspect(sourceAdmin,'SELECT count(*) FROM verivaro_migration.history')!=='62'||
   inspect(targetAdmin,
    "SELECT to_regclass('verivaro_private.ocr_transcription_corrections') IS NOT NULL")!=='t')
   refuse('staged upgrade did not preserve source, dataset, schema and history');
  // A separate process replay of the final migration must be idempotent.
  psql(targetClient,migration);
  if(inspect(targetAdmin,'SELECT count(*) FROM verivaro_migration.history')!=='63')
   refuse('replayed upgrade mutated the history');
  const acl=inspect(targetAdmin,
   "SELECT has_table_privilege('"+LOGIN+"','verivaro_migration.history','UPDATE')"+
   ",has_table_privilege('"+LOGIN+"','verivaro_migration.history','DELETE')");
  if(acl!=='f|f')refuse('staged upgrade exposed ledger write-back');
  return Object.freeze({sourceVersion:62,targetVersion:63,cloneFromExistingSchema:true,
   realMigrationInterrupted:true,rollbackVerified:true,safeRestartVerified:true,
   originalSourceUnchanged:true,syntheticTenantRecordsPreserved:true,
   persistedHistoryVerified:true,replaySafe:true,ledgerPrivilegeRestricted:true,
   productionEquivalentEnvironment:false,independentSignoff:false,productionApproved:false});
 }finally{
  if(targetCreated)exec('dropdb',['-w','--if-exists','--force',UPGRADE_TARGET],admin);
  if(sourceCreated)exec('dropdb',['-w','--if-exists','--force',UPGRADE_SOURCE],admin);
 }
}

async function run(){
 assertDisposableDatabase();
 if(process.env.PGDATABASE!=='verivaro_test'||process.env.VV_CI_ROLE_RECONCILE!=='1')
  refuse('not the approved isolated CI rehearsal');
 const test=await plan();
 if(test.migrations.length!==63||test.serviceRoles.length!==21)
  refuse('unexpected locked migration baseline');
 const admin={...process.env,PGCONNECT_TIMEOUT:'5'};
 const password=randomBytes(32).toString('hex');
 let created=false,rolesCreated=false;
 exec('createdb',['-w','--template=template0',DB],admin);created=true;
 try{
  psql(admin,fixtureRoleSql(test,password));rolesCreated=true;
  const root={...admin,PGDATABASE:DB};
  psql(root,'REVOKE CREATE ON DATABASE '+DB+' FROM PUBLIC;\n'+
   'GRANT CREATE ON DATABASE '+DB+' TO '+OWNER+';\n');
  psql(root,fixtureLedgerSql());
  const client={...root,PGUSER:LOGIN,PGPASSWORD:password};
  // The login must not inherit any schema or global role creation privilege.
  const before=psql(client,"DO $deny$ BEGIN "+
   "BEGIN EXECUTE 'CREATE ROLE vv_ci_reconcile_denied NOLOGIN';"+
   " RAISE EXCEPTION 'unexpected create role'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;"+
   "BEGIN EXECUTE 'CREATE SCHEMA vv_ci_reconcile_denied_schema';"+
   " RAISE EXCEPTION 'unexpected create schema'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;"+
   "END $deny$;");
  const ledger=createExpectedLedger(test.migrations.map(m=>({
   version:m.version,path:m.path,sha256:m.sourceSha256
  })));
  for(const m of test.migrations){
   const sql=restrictedReconcileSql(ledger,m.version,m.transformedSql);
   psql(client,sql);
  }
  const history=exec('psql',['-X','-A','-t','-v','ON_ERROR_STOP=1','-c',
   'SELECT version,migration_path,file_sha256,previous_hash,entry_hash '+
   'FROM verivaro_migration.history ORDER BY version'],root);
  const rows=history.split('\n');
  if(rows.length!==63)refuse('incomplete 63-migration restricted rollout');
  for(let i=0;i<rows.length;i++){
   const l=ledger[i],expected=[l.version,l.path,l.sha256,l.previous_hash,l.entry_hash].join('|');
   if(rows[i]!==expected)refuse('restricted rollout history mismatch at '+(i+1));
  }
  const roleProbe=exec('psql',['-X','-A','-t','-v','ON_ERROR_STOP=1','-c',
   "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'verivaro_%' "+
   'AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication '+
   'AND NOT rolbypassrls AND NOT rolinherit AND NOT rolcanlogin'],root);
  if(roleProbe!=='21')refuse('service role catalogue unexpectedly widened');
  const denied=exec('psql',['-X','-A','-t','-v','ON_ERROR_STOP=1','-c',
   "SELECT has_table_privilege('"+LOGIN+"','verivaro_migration.history','UPDATE')"+
   ",has_table_privilege('"+LOGIN+"','verivaro_migration.history','DELETE')"+
   ",has_table_privilege('"+EXECUTOR+"','verivaro_migration.history','INSERT')"],root);
  if(denied!=='f|f|t')refuse('persistent ledger privilege leak');
  const stagedUpgrade=await rehearseStagedUpgrade(test,ledger,admin,client);
  return {restrictedMigrationsApplied:63,serviceRolesProvisioned:21,
   schemaExecutorCreateRoleDenied:true,unprivilegedLoginSchemaCreateDenied:true,
   ledgerWriteOnlyToExecutor:true,historyVerified:true,
   head:ledger.at(-1).entry_hash,stagedUpgrade,productionApproved:false};
 }finally{
  if(created){
   exec('dropdb',['-w','--if-exists','--force',DB],admin);
   if(rolesCreated){
    const remove=[LOGIN,EXECUTOR,OWNER,CUSTODIAN,...test.serviceRoles].map(q);
    psql(admin,'DROP ROLE '+remove.join(',')+';\n');
   }
  }
 }
}
if(process.argv[1]&&import.meta.url===new URL('file://'+process.argv[1]).href){
 try{process.stdout.write(JSON.stringify(await run())+'\n');}
 catch(e){process.stderr.write(e.message+'\n');process.exitCode=1;}
}
