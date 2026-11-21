// CI-only isolated PostgreSQL restart drill with *actual* locked migrations 0001/0002.
import {spawnSync} from 'node:child_process';
import {assertDisposableDatabase} from './ci-migration-ledger.mjs';
const database='verivaro_migration_restart_ci';
function command(bin,args,env=process.env){
 const r=spawnSync(bin,args,{env,encoding:'utf8',timeout:120000,maxBuffer:1024*1024});
 return {ok:!r.error&&!r.signal&&r.status===0,output:(r.stdout||'').trim()};
}
const must=(condition,message)=>{if(!condition)throw Error('restart drill failed: '+message);};
const migrated=name=>'db/migrations/'+name+'.sql';
async function drill(){
 assertDisposableDatabase();
 must(process.env.PGDATABASE==='verivaro_test','requires original disposable database');
 const env={...process.env,PGDATABASE:database};
 const script='scripts/ci-migration-ledger.mjs';
 const apply=(number,name,more={})=>command(process.execPath,[script,'apply',migrated(name)],{...env,...more});
 const sql=query=>{
  const r=command('psql',['-X','-v','ON_ERROR_STOP=1','-A','-t','-c',query],env);
  must(r.ok,'inspection query failed');return r.output;
 };
 const created=command('createdb',['-w','--template=template0',database]);
 must(created.ok,'unable to create empty isolated restart database');
 try{
  must(command(process.execPath,[script,'init'],env).ok,'cannot initialise protected ledger');
  must(apply(1,'0001_tenant_foundation').ok,'migration 0001');
  must(!apply(3,'0003_signed_context').ok,'out-of-order migration accepted');
  must(!apply(2,'0002_evidence_immutability',{VV_CI_MIGRATION_ABORT:'1'}).ok,
   'backend termination did not interrupt SQL transaction');
  must(sql('SELECT count(*) FROM verivaro_migration.history')==='1',
   'interrupted migration advanced ledger');
  must(sql("SELECT to_regprocedure('verivaro.reject_evidence_mutation()') IS NULL")==='t',
   'interrupted migration retained function DDL');
  must(apply(2,'0002_evidence_immutability').ok,'new connection failed to resume migration 0002');
  must(sql('SELECT count(*) FROM verivaro_migration.history')==='2',
   'resumed migration did not advance ledger');
  must(sql("SELECT to_regprocedure('verivaro.reject_evidence_mutation()') IS NOT NULL")==='t',
   'resumed migration lacks expected function');
  must(apply(1,'0001_tenant_foundation').ok,'already-applied migration not replay-safe');
  must(sql('SELECT count(*) FROM verivaro_migration.history')==='2',
   'replay duplicated migration ledger');
  sql("UPDATE verivaro_migration.history SET entry_hash=repeat('f',64) WHERE version=1");
  must(!apply(2,'0002_evidence_immutability').ok,
   'manipulated hash chain was not detected');
  return {realMigrationsTested:[1,2],backendKilledBeforeCommit:true,
   rollbackVerified:true,restartVerified:true,orderRejected:true,replaySafe:true,
   tamperingRejected:true,productionApproved:false};
 }finally{
  must(command('dropdb',['-w','--if-exists',database]).ok,'isolated restart database cleanup');
 }
}
try{process.stdout.write(JSON.stringify(await drill())+'\n');}
catch(e){process.stderr.write(e.message+'\n');process.exitCode=1;}
