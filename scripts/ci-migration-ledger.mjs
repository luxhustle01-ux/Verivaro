// CI-only, source-locked PostgreSQL migration ledger. Not a production migrator.
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {TextDecoder} from 'node:util';
import {auditRepositoryMigrationChain} from '../src/security/migration-chain-audit.mjs';

const SCHEMA='verivaro_migration';
const ZERO='0'.repeat(64);
const digest=value=>createHash('sha256').update(value).digest('hex');
const refuse=message=>{throw Error('CI migration ledger rejected: '+message);};

export function assertDisposableDatabase(env=process.env){
 if(env.GITHUB_ACTIONS!=='true'||env.VV_CI_PG_MIGRATOR!=='1'||
  env.PGHOST!=='localhost'||env.PGPORT!=='5432'||
  env.PGUSER!=='postgres'||env.PGPASSWORD!=='ci-only'||
  !['verivaro_test','verivaro_migration_restart_ci'].includes(env.PGDATABASE)||
  env.PGHOSTADDR||env.PGSERVICE||env.PGSERVICEFILE||env.PGOPTIONS||
  env.PGURI||env.DATABASE_URL||env.PGPASSFILE){
  refuse('requires the fixed disposable GitHub Actions PostgreSQL fixture');
 }
}
export function unwrapTransactionalMigration(source){
 if(typeof source!=='string'||source.includes('\0'))refuse('migration is not UTF-8 text');
 const starts=[...source.matchAll(/^BEGIN[ \t]*;[ \t]*$/gm)];
 const ends=[...source.matchAll(/^COMMIT[ \t]*;[ \t]*$/gm)];
 if(starts.length!==1||ends.length!==1||starts[0].index>=ends[0].index)
  refuse('migration must have one enclosing BEGIN/COMMIT');
 const header=source.slice(0,starts[0].index);
 const trailer=source.slice(ends[0].index+ends[0][0].length);
 if(header.replace(/^\s*--[^\r\n]*(?:\r?\n|$)/gm,'').trim()||
    trailer.replace(/^\s*--[^\r\n]*(?:\r?\n|$)/gm,'').trim())
  refuse('unsupported SQL outside transaction envelope');
 if(source.split('\n').some(line=>/^\\/.test(line)))refuse('psql meta commands are not allowed in locked SQL');
 return source.slice(starts[0].index+starts[0][0].length,ends[0].index);
}
export function createExpectedLedger(migrations){
 if(!Array.isArray(migrations)||migrations.length<1||migrations.length>500)
  refuse('invalid catalogue');
 let previous=ZERO;
 return migrations.map((entry,index)=>{
  if(entry.version!==index+1||typeof entry.path!=='string'||
   !/^db\/migrations\/[0-9]{4}_[a-z0-9_]+\.sql$/.test(entry.path)||
   typeof entry.sha256!=='string'||!/^[a-f0-9]{64}$/.test(entry.sha256))
   refuse('invalid catalogue row');
  const head=digest(['VV_LEDGER_V1',entry.version,entry.path,entry.sha256,previous].join('\n'));
  const item={...entry,previous_hash:previous,entry_hash:head};
  previous=head;
  return item;
 });
}
function psql(args,input){
 const run=spawnSync('psql',['-X','-v','ON_ERROR_STOP=1','-q',...args],{
  input,encoding:'utf8',timeout:120000,maxBuffer:2*1024*1024,
  env:{...process.env,PGCONNECT_TIMEOUT:'5'}
 });
 if(run.error||run.signal||run.status!==0)refuse('PostgreSQL command did not complete');
 return (run.stdout||'').trim();
}
async function catalogue(){
 await auditRepositoryMigrationChain();
 const manifest=JSON.parse(await readFile('db/migration-lock.json','utf8'));
 const bytes=await Promise.all(manifest.migrations.map(e=>readFile(e.path)));
 const decoder=new TextDecoder('utf-8',{fatal:true});
 return {items:createExpectedLedger(manifest.migrations.map((e,i)=>({
  version:e.number,path:e.path,sha256:digest(bytes[i])
 }))),sources:bytes.map(b=>decoder.decode(b))};
}
function tuples(items){
 return items.map(e=>'('+e.version+",'"+e.path+"','"+e.sha256+"','"+
  e.previous_hash+"','"+e.entry_hash+"')").join(',\n');
}
export function createMigrationSql(items,version,source,{abort=false}={}){
 const entry=items[version-1];
 if(!entry||entry.version!==version)refuse('unregistered migration');
 const body=unwrapTransactionalMigration(source);
 // Under a *single transaction*, serialise migrators, verify all previous
 // recorded versions, then run the SQL and append exactly one ledger row.
 // Skipping already-applied versions happens after taking the same lock.
 return 'BEGIN;\n'+
 'SELECT pg_advisory_xact_lock(634220,20261121);\n'+
 'DO $vv_ledger_guard$\nDECLARE count_records bigint; latest bigint;\nBEGIN\n'+
 'IF EXISTS (SELECT 1 FROM '+SCHEMA+'.history h LEFT JOIN (VALUES\n'+
 tuples(items)+'\n) AS expected(version,migration_path,file_sha256,previous_hash,entry_hash)'+
 ' ON h.version=expected.version WHERE expected.version IS NULL OR '+
 'h.migration_path IS DISTINCT FROM expected.migration_path OR '+
 'h.file_sha256 IS DISTINCT FROM expected.file_sha256 OR '+
 'h.previous_hash IS DISTINCT FROM expected.previous_hash OR '+
 'h.entry_hash IS DISTINCT FROM expected.entry_hash) THEN\n'+
 " RAISE EXCEPTION 'migration ledger contents do not match repository baseline';\nEND IF;\n"+
 'SELECT count(*),COALESCE(max(version),0) INTO count_records,latest FROM '+SCHEMA+'.history;\n'+
 "IF count_records<>latest THEN RAISE EXCEPTION 'migration ledger has a gap'; END IF;\n"+
 'IF NOT EXISTS(SELECT 1 FROM '+SCHEMA+'.history WHERE version='+version+')'+
 ' AND count_records<>'+String(version-1)+" THEN\n RAISE EXCEPTION 'migration attempted out of order'; END IF;\n"+
 'END $vv_ledger_guard$;\n'+
 'SELECT EXISTS(SELECT 1 FROM '+SCHEMA+'.history WHERE version='+version+') AS vv_skip \\gset\n'+
 '\\if :vv_skip\n'+
 '\\echo already-applied-migration-'+version+'\n'+
 '\\else\n'+body+'\n'+
 'INSERT INTO '+SCHEMA+'.history(version,migration_path,file_sha256,previous_hash,entry_hash) VALUES ('+
 version+",'"+entry.path+"','"+entry.sha256+"','"+entry.previous_hash+"','"+entry.entry_hash+"');\n"+
 (abort?'SELECT pg_terminate_backend(pg_backend_pid());\n':'')+
 '\\endif\nCOMMIT;\n';
}
function bootstrap(){
 psql(['-c','BEGIN; CREATE SCHEMA '+SCHEMA+'; REVOKE ALL ON SCHEMA '+SCHEMA+
  ' FROM PUBLIC; CREATE TABLE '+SCHEMA+'.history ('+
  'version integer PRIMARY KEY CHECK (version BETWEEN 1 AND 500),'+
  'migration_path text NOT NULL UNIQUE,'+
  "file_sha256 char(64) NOT NULL CHECK (file_sha256 ~ '^[a-f0-9]{64}$'),"+
  "previous_hash char(64) NOT NULL CHECK (previous_hash ~ '^[a-f0-9]{64}$'),"+
  "entry_hash char(64) NOT NULL UNIQUE CHECK (entry_hash ~ '^[a-f0-9]{64}$'),"+
  'applied_at timestamptz NOT NULL DEFAULT transaction_timestamp());'+
  'REVOKE ALL ON '+SCHEMA+'.history FROM PUBLIC; COMMIT;']);
 return {ledgerInitialized:true};
}
export function checkLedgerRows(items,rows,expectedCount=items.length){
 if(!Number.isSafeInteger(expectedCount)||expectedCount<0||expectedCount>items.length)
  refuse('invalid expected count');
 if(rows.length!==expectedCount)refuse('ledger row count');
 for(let i=0;i<rows.length;i++){
  const e=items[i];
  const expected=[String(e.version),e.path,e.sha256,e.previous_hash,e.entry_hash].join('|');
  if(rows[i]!==expected)refuse('ledger checksum, hash chain or ordering mismatch');
 }
 return {verifiedVersions:rows.length,head:rows.length?items[rows.length-1].entry_hash:ZERO,
  independentlyWitnessed:false,productionApproved:false};
}
async function verify(items,expectedCount=items.length){
 const out=psql(['-A','-t','-F','|','-c',
  'SELECT version,migration_path,file_sha256,previous_hash,entry_hash FROM '+
  SCHEMA+'.history ORDER BY version']);
 return checkLedgerRows(items,out?out.split('\n'):[],expectedCount);
}
export async function run(command,filename){
 assertDisposableDatabase();
 if(!['init','apply','verify'].includes(command))refuse('unsupported mode');
 const {items,sources}=await catalogue();
 if(command==='init')return bootstrap();
 if(command==='verify')return verify(items,items.length);
 const index=items.findIndex(e=>e.path===filename);
 if(index<0)refuse('migration path not in audited manifest');
 const version=index+1;
 const abort=process.env.VV_CI_MIGRATION_ABORT==='1';
 if(abort&&process.env.PGDATABASE!=='verivaro_migration_restart_ci')
  refuse('injected interruption only allowed in isolated restart database');
 const script=createMigrationSql(items,version,sources[index],{abort});
 psql(['-f','-'],script);
 return {version,ledgerVerified:true,sourceSha256:items[index].sha256,
  interrupted:false,productionApproved:false};
}
if(process.argv[1]&&import.meta.url===new URL('file://'+process.argv[1]).href){
 try{process.stdout.write(JSON.stringify(await run(process.argv[2],process.argv[3]))+'\n');}
 catch(error){process.stderr.write(error.message+'\n');process.exitCode=1;}
}
