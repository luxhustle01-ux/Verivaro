// Read-only release manifest preparation / independent offline verification.
// Deliberately contains no signer, no private keys and no deployment operation.
import {readFile,lstat,realpath,open} from 'node:fs/promises';
import {constants} from 'node:fs';
import {resolve,join,sep,dirname} from 'node:path';
import {spawnSync} from 'node:child_process';
import {auditRepositoryMigrationChain} from '../src/security/migration-chain-audit.mjs';
import {makeMigrationReleaseManifest,verifyMigrationReleaseAttestation}
 from '../src/security/migration-release-attestation.mjs';
const reject=reason=>{throw Error('offline migration release CLI rejected: '+reason);};
const root=resolve(process.cwd());
export const ADDITIONAL_SIGNED_PATHS=Object.freeze([
 'db/migration-lock.json',
 'db/security/production-migration-roles.sql',
 'src/security/migration-role-policy.mjs',
 'src/security/migration-chain-audit.mjs',
 'src/security/migration-release-attestation.mjs',
 'scripts/ci-migration-ledger.mjs',
 'scripts/verify-migration-chain.mjs',
 'scripts/migration-release-cli.mjs',
 '.github/workflows/postgres-g1.yml',
 'db/security/privileged-service-role-bootstrap.sql',
 'db/security/verify-installed-migration-state.sql',
 'src/security/legacy-role-reconciliation.mjs',
 'scripts/rehearse-privileged-migration-reconciliation.mjs',
 'scripts/rehearse-migration-signing-acceptance.mjs',
 'db/tests/least_privilege_migrator.sql',
 'docs/engineering/G1_PRIVILEGED_BOOTSTRAP_AND_SIGNING_ACCEPTANCE_20261121.md',
 'docs/engineering/G1_INDEPENDENT_SIGNING_ACCEPTANCE_20261121.json'
]);
function head(){
 const r=spawnSync('git',['rev-parse','--verify','HEAD'],{
  cwd:root,encoding:'utf8',timeout:5000,env:{...process.env,GIT_OPTIONAL_LOCKS:'0'}
 });
 if(r.error||r.status!==0||!/^[a-f0-9]{40}$/.test(r.stdout.trim()))
  reject('no verifiable Git HEAD');
 return r.stdout.trim();
}
async function regularFile(path,{outside=false}={}){
 const full=resolve(path);
 if(!outside&&!(full.startsWith(root+sep)))reject('source path escaped checkout');
 if(outside&&(full===root||full.startsWith(root+sep)))reject('approval artifact must be outside repository checkout');
 const begin=outside?resolve(full, '..'):root;
 if(!outside){
  let pathPart=root;
  for(const item of full.slice(root.length+1).split(sep).slice(0,-1)){
   pathPart=join(pathPart,item);
   const st=await lstat(pathPart);
   if(!st.isDirectory()||st.isSymbolicLink())reject('source directory symlink or not a directory');
  }
 }
 const fd=await open(full,constants.O_RDONLY|constants.O_NOFOLLOW);
 try{
  const st=await fd.stat();
  if(!st.isFile()||st.size<1||st.size>2*1024*1024)reject('invalid file size/type');
  const data=await fd.readFile();
  if(data.length!==st.size)reject('file changed during read');
  return data;
 }finally{await fd.close();}
}
async function sourceFiles(){
 await auditRepositoryMigrationChain({root});
 const lock=JSON.parse((await regularFile(join(root,'db/migration-lock.json'))).toString('utf8'));
 const paths=[...lock.migrations.map(m=>m.path),...ADDITIONAL_SIGNED_PATHS];
 if(new Set(paths).size!==paths.length)reject('duplicate source path');
 const files=[];
 for(const path of paths)files.push({path,bytes:await regularFile(join(root,path))});
 return files;
}
export async function draftManifest(sequence,commit){
 if(!Number.isSafeInteger(sequence)||sequence<1||
  !/^[a-f0-9]{40}$/.test(commit)||head()!==commit)
  reject('release sequence or checkout SHA mismatch');
 const files=await sourceFiles();
 return makeMigrationReleaseManifest({sequence,sourceCommit:commit,files});
}
export async function verifyOffline({manifestPath,policyPath,pin,sigOwnerPath,sigReviewerPath}){
 if(typeof pin!=='string'||!/^[a-f0-9]{64}$/.test(pin))
  reject('operator-supplied external policy SHA-256 pin required');
 const [manifestBytes,policyBytes,owner,reviewer,files]=await Promise.all([
  regularFile(manifestPath,{outside:true}),regularFile(policyPath,{outside:true}),
  regularFile(sigOwnerPath,{outside:true}),regularFile(sigReviewerPath,{outside:true}),
  sourceFiles()
 ]);
 const expectedPaths=files.map(f=>f.path);
 const fileMap=new Map(files.map(f=>[f.path,f.bytes]));
 const result=verifyMigrationReleaseAttestation({manifestBytes,policyBytes,
  pinnedPolicySha256:pin,signatures:[owner,reviewer],expectedPaths,filesByPath:fileMap});
 const manifest=JSON.parse(manifestBytes.toString('utf8'));
 if(manifest.sourceCommit!==head())reject('manifest sourceCommit differs from checkout HEAD');
 return result;
}
if(process.argv[1]&&import.meta.url===new URL('file://'+process.argv[1]).href){
 try{
  const mode=process.argv[2];
  if(mode==='draft'&&process.argv.length===5){
   const seq=Number(process.argv[3]),commit=process.argv[4];
   process.stdout.write(await draftManifest(seq,commit));
  }else if(mode==='verify'&&process.argv.length===8){
   const [manifestPath,policyPath,pin,sigOwnerPath,sigReviewerPath]=process.argv.slice(3);
   process.stdout.write(JSON.stringify(await verifyOffline({
    manifestPath,policyPath,pin,sigOwnerPath,sigReviewerPath
   }))+'\n');
  }else reject('use draft <sequence> <exactGitSHA> or verify <manifest> <externalPolicy> <externalPin> <ownerSig> <reviewerSig>');
 }catch(error){
  process.stderr.write(error.message+'\n');
  process.exitCode=1;
 }
}
