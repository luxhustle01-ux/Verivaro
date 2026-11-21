// P0-B synthetic PostgreSQL recovery rehearsal. Never use for production rollout.
// Exercises transactional DDL+ledger writes against CI's disposable database.
import {spawnSync} from 'node:child_process';
import {createHash,randomBytes} from 'node:crypto';
import {mkdtemp,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

function requireDisposableCI(){
 const e=process.env;
 if(e.GITHUB_ACTIONS!=='true'||e.VV_CI_PG_REHEARSAL!=='1'||
    e.PGHOST!=='localhost'||e.PGPORT!=='5432'||
    e.PGUSER!=='postgres'||e.PGDATABASE!=='verivaro_test'||
    e.PGPASSWORD!=='ci-only'||e.PGHOSTADDR||e.PGSERVICE||e.PGSERVICEFILE||
    e.PGOPTIONS||e.PGURI||e.DATABASE_URL){
  throw Error('migration recovery rehearsal requires the approved disposable CI database');
 }
}
function invoke(args){
 const r=spawnSync('psql',['-X','-v','ON_ERROR_STOP=1',...args],{
  encoding:'utf8',timeout:20000,maxBuffer:1024*1024,
  env:{...process.env,PGCONNECT_TIMEOUT:'5'}
 });
 if(r.error||r.signal)throw Error('rehearsal psql did not complete');
 return {ok:r.status===0,output:r.stdout?.trim()??''};
}
function runSql(statement){
 const r=invoke(['-q','-t','-A','-c',statement]);
 if(!r.ok)throw Error('rehearsal query failed');
 return r.output;
}
function ensure(ok,description){
 if(!ok)throw Error('migration recovery gate failed: '+description);
}

export async function rehearseMigrationRecovery(){
 requireDisposableCI();
 const schema='vv_rehearsal_'+randomBytes(10).toString('hex');
 const directory=await mkdtemp(join(tmpdir(),'vv-migration-gate-'));
 let schemaCreated=false;
 try{
  runSql(`CREATE SCHEMA ${schema}`);
  schemaCreated=true;
  runSql(`CREATE TABLE ${schema}.history (
    version integer PRIMARY KEY CHECK (version BETWEEN 1 AND 100),
    sha256 char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$')
  )`);
  // Only generated, non-user-controlled SQL files and numeric versions reach psql.
  async function apply(version,sql){
   ensure(Number.isInteger(version)&&version>=1&&version<=100,'invalid version');
   const digest=createHash('sha256').update(sql,'utf8').digest('hex');
   const stored=runSql(`SELECT sha256 FROM ${schema}.history WHERE version=${version}`);
   if(stored){
    ensure(stored===digest,'applied migration fingerprint changed');
    return 'already-applied';
   }
   const file=join(directory,`fixture-${version}-${digest}.sql`);
   await writeFile(file,sql,{mode:0o600,flag:'wx'});
   // --single-transaction encloses the lock, SQL file and history insert.
   // ON_ERROR_STOP ensures a failed statement prevents a successful commit.
   const result=invoke([
    '--single-transaction','-q','-v',`fixture_schema=${schema}`,
    '-c',`SELECT pg_advisory_xact_lock(734210,${version})`,
    '-f',file,
    '-c',`INSERT INTO ${schema}.history(version,sha256) VALUES (${version},'${digest}')`
   ]);
   if(!result.ok)throw Error('rehearsal migration transaction failed');
   ensure(runSql(`SELECT sha256 FROM ${schema}.history WHERE version=${version}`)===digest,
    'history write missing after migration');
   return 'applied';
  }
  const first=`CREATE TABLE :"fixture_schema".evidence(id integer PRIMARY KEY);\nINSERT INTO :"fixture_schema".evidence VALUES(7);\n`;
  const interrupted=`CREATE TABLE :"fixture_schema".partial(id integer PRIMARY KEY);\nINSERT INTO :"fixture_schema".partial VALUES(1);\nSELECT 1/0;\n`;
  const corrected=`CREATE TABLE :"fixture_schema".completed(id integer PRIMARY KEY);\nINSERT INTO :"fixture_schema".completed VALUES(9);\n`;
  ensure(await apply(1,first)==='applied','first installation');
  ensure(await apply(1,first)==='already-applied','idempotent replay');
  let failed=false;
  try{await apply(2,interrupted);}catch(error){
   if(error.message==='rehearsal migration transaction failed')failed=true;
   else throw error;
  }
  ensure(failed,'injected failure was not rejected');
  ensure(runSql(`SELECT count(*) FROM ${schema}.history`)==='1','failed version recorded');
  ensure(runSql(`SELECT to_regclass('${schema}.partial') IS NULL`)==='t',
   'partial DDL survived rollback');
  ensure(await apply(2,corrected)==='applied','corrected retry');
  ensure(await apply(2,corrected)==='already-applied','corrected replay');
  let driftRejected=false;
  try{await apply(2,interrupted);}catch(error){
   if(error.message==='migration recovery gate failed: applied migration fingerprint changed')
    driftRejected=true;
   else throw error;
  }
  ensure(driftRejected,'previously applied fingerprint drift accepted');
  ensure(runSql(`SELECT count(*) FROM ${schema}.history`)==='2','history count');
  ensure(runSql(`SELECT count(*) FROM ${schema}.evidence`)==='1','original row count');
  ensure(runSql(`SELECT count(*) FROM ${schema}.completed`)==='1','retry row count');
  ensure(runSql(`SELECT to_regclass('${schema}.partial') IS NULL`)==='t',
   'failed migration left a table');
  return Object.freeze({
   transactionFailureRolledBack:true,correctedRetry:true,
   duplicateReplaySkipped:true,checksumDriftDenied:true,recordedVersions:2,
   productionMigrationApproved:false
  });
 }finally{
  try{if(schemaCreated)runSql(`DROP SCHEMA ${schema} CASCADE`);}
  finally{await rm(directory,{recursive:true,force:true});}
 }
}
if(process.argv[1]&&import.meta.url===new URL('file://'+process.argv[1]).href){
 try{
  const result=await rehearseMigrationRecovery();
  process.stdout.write(JSON.stringify(result)+'\n');
 }catch(error){
  process.stderr.write(error.message+'\n');
  process.exitCode=1;
 }
}
