// P0-B: deterministic PostgreSQL migration-source drift gate.
// Git blob SHA-1 detects accidental repository drift; it is NOT an
// independently signed migration ledger or collision-resistant provenance.
import {createHash} from 'node:crypto';
import {readFile,readdir,lstat,realpath} from 'node:fs/promises';
import {resolve,join} from 'node:path';

const MIGRATION=/^db\/migrations\/([0-9]{4})_[a-z0-9_]+\.sql$/;
const OID=/^[a-f0-9]{40}$/;
const fail=()=>{throw Error('migration chain preflight rejected');};
const isObject=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const exact=(x,names)=>isObject(x)&&
 Object.keys(x).sort().join(',')===names.slice().sort().join(',');
export function gitBlobSha1(bytes){
 if(!Buffer.isBuffer(bytes))fail();
 return createHash('sha1').update(Buffer.from('blob '+bytes.length+'\0','utf8'))
  .update(bytes).digest('hex');
}
export function verifyMigrationChainSnapshot({
 manifest,files,workflowText
}={}){
 if(!exact(manifest,['schemaVersion','manifestType','baselineCommit',
  'hashAlgorithm','sourceScope','productionMigrationApproved',
  'independentlySigned','migrations'])||
  manifest.schemaVersion!==1||
  manifest.manifestType!=='VERIVARO_P0B_MIGRATION_CHAIN'||
  manifest.hashAlgorithm!=='git-blob-sha1'||
  manifest.sourceScope!=='repository-migrations-only'||
  manifest.productionMigrationApproved!==false||
  manifest.independentlySigned!==false||
  !OID.test(manifest.baselineCommit)||
  !Array.isArray(manifest.migrations)||
  manifest.migrations.length<1||manifest.migrations.length>500||
  !isObject(files)||typeof workflowText!=='string')fail();
 const expected=[];
 for(let i=0;i<manifest.migrations.length;i++){
  const entry=manifest.migrations[i];
  if(!exact(entry,['number','path','gitBlobSha1','byteLength'])||
   entry.number!==i+1||
   typeof entry.path!=='string'||!MIGRATION.test(entry.path)||
   Number(entry.path.match(MIGRATION)[1])!==i+1||
   typeof entry.gitBlobSha1!=='string'||!OID.test(entry.gitBlobSha1)||
   !Number.isSafeInteger(entry.byteLength)||entry.byteLength<1||
   entry.byteLength>2*1024*1024)fail();
  const content=files[entry.path];
  if(!Buffer.isBuffer(content)||content.length!==entry.byteLength||
   gitBlobSha1(content)!==entry.gitBlobSha1)fail();
  expected.push(entry.path);
 }
 const actual=Object.keys(files).sort();
 if(actual.some(x=>!MIGRATION.test(x))||
  JSON.stringify(actual)!==JSON.stringify([...expected].sort()))fail();
 // Require a dedicated preflight in its own CI step before the *first*
 // migration application. Refuse any unrecognised migration command.
 const preflight='node scripts/verify-migration-chain.mjs';
 const runner='node scripts/ci-migration-ledger.mjs apply ';
 const first=workflowText.indexOf(runner+'db/migrations/');
 const pre=workflowText.indexOf('node scripts/verify-migration-chain.mjs');
 const init=workflowText.indexOf('node scripts/ci-migration-ledger.mjs init');
 const finished=workflowText.indexOf('node scripts/ci-migration-ledger.mjs verify');
 if(pre<0||init<=pre||first<=init||finished<=first)fail();
 const applied=[];
 for(const line of workflowText.split('\n')){
  if(!line.includes('db/migrations/'))continue;
  const match=/^\s*node scripts\/ci-migration-ledger\.mjs apply (db\/migrations\/[0-9]{4}_[a-z0-9_]+\.sql)\s*$/.exec(line);
  if(!match)fail();
  applied.push(match[1]);
 }
 if(JSON.stringify(applied)!==JSON.stringify(expected))fail();
 const finalGate=workflowText.lastIndexOf(
  'psql -X -v ON_ERROR_STOP=1 -f db/tests/full_security_gate.sql');
 const last=workflowText.lastIndexOf(runner+expected.at(-1));
 if(last<first||finished<last||finalGate<finished)fail();
 return Object.freeze({
  checkedCount:expected.length,
  first:expected[0],last:expected.at(-1),
  baselineCommit:manifest.baselineCommit,
  independentSignoff:false,productionMigrationApproved:false
 });
}
export async function auditRepositoryMigrationChain({root=process.cwd()}={}){
 if(typeof root!=='string'||!root)fail();
 const base=resolve(root),dir=join(base,'db/migrations');
 const [st,migrationPaths,rawManifest,workflowText]=await Promise.all([
  lstat(dir),readdir(dir),
  readFile(join(base,'db/migration-lock.json'),'utf8'),
  readFile(join(base,'.github/workflows/postgres-g1.yml'),'utf8')
 ]);
 if(!st.isDirectory()||await realpath(dir)!==dir)fail();
 let manifest;
 try{manifest=JSON.parse(rawManifest);}catch{fail();}
 const files=Object.create(null);
 for(const name of migrationPaths){
  if(!/^[0-9]{4}_[a-z0-9_]+\.sql$/.test(name))fail();
  const path=join(dir,name),stat=await lstat(path);
  if(!stat.isFile()||stat.isSymbolicLink()||
   stat.size>2*1024*1024||stat.size<1)fail();
  const contents=await readFile(path);
  if(contents.length!==stat.size)fail();
  files['db/migrations/'+name]=contents;
 }
 return verifyMigrationChainSnapshot({manifest,files,workflowText});
}
