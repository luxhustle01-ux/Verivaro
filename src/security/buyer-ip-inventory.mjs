// Deterministic acquisition-diligence inventory of repository-declared dependencies.
// Lockfile licence fields are unverified metadata; this is NOT legal clearance or a complete SBOM.
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash} from 'node:crypto';

const lockPaths=Object.freeze([
 'package-lock.json',
 'services/application/driver/package-lock.json',
 'services/security-monitor/driver/package-lock.json',
 'tests/integration/driver/package-lock.json'
]);
const workflows=Object.freeze([
 '.github/workflows/browser-workspace.yml',
 '.github/workflows/buyer-bundle.yml',
 '.github/workflows/ci.yml',
 '.github/workflows/clamav-engine.yml',
 '.github/workflows/postgres-g1.yml',
 '.github/workflows/recovery-capacity.yml'
]);
const sha=b=>createHash('sha256').update(b).digest('hex');
const strictRevision=r=>typeof r==='string'&&/^[a-f0-9]{40}$/.test(r);
const fail=message=>{throw Error('buyer IP inventory rejected: '+message);};
const plain=o=>o!==null&&typeof o==='object'&&!Array.isArray(o);
const equal=(a,b)=>JSON.stringify(Object.entries(a||{}).sort())===JSON.stringify(Object.entries(b||{}).sort());
const pkgName=location=>{
 if(!/^node_modules\/(?:@[\w.-]+\/)?[\w.-]+$/.test(location))fail('unsupported package location');
 return location.slice('node_modules/'.length);
};
const validRegistry=location=>{
 let u;
 try{u=new URL(location);}catch{fail('invalid registry URL');}
 if(u.protocol!=='https:'||u.hostname!=='registry.npmjs.org'||u.username||u.password||u.search||u.hash||!u.pathname.endsWith('.tgz'))
  fail('non-registry dependency');
};
const fields=['dependencies','devDependencies','optionalDependencies'];
export async function buildBuyerIpInventory({root=process.cwd(),readText=null,sourceRevision=null}={}){
 if(typeof root!=='string'||!root||readText!==null&&typeof readText!=='function'||
  sourceRevision!==null&&!strictRevision(sourceRevision))fail('invalid inventory options');
 const read=readText||((name)=>readFile(join(root,name),'utf8'));
 const packages=new Map(),locks=[];
 for(const lockPath of lockPaths){
  let lock,manifest,raw;
  try{
   raw=await read(lockPath);
   lock=JSON.parse(raw);
   manifest=JSON.parse(await read(lockPath.replace(/package-lock\.json$/,'package.json')));
  }catch{fail('missing or invalid manifest '+lockPath);}
  if(!plain(lock)||lock.lockfileVersion!==3||!plain(lock.packages)||
   !plain(lock.packages[''])||!plain(manifest)||lock.name!==manifest.name||
   lock.version!==manifest.version||lock.packages[''].name!==manifest.name||
   lock.packages[''].version!==manifest.version)fail('lockfile root mismatch '+lockPath);
  for(const field of fields)
   if(!equal(manifest[field],lock.packages[''][field]))fail('unlocked root dependency '+lockPath);
  let count=0;
  for(const [location,p] of Object.entries(lock.packages).sort(([a],[b])=>a.localeCompare(b,'en'))){
   if(location==='')continue;
   const name=pkgName(location);
   if(!plain(p)||typeof p.version!=='string'||!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(p.version)||
    typeof p.integrity!=='string'||!/^sha512-[0-9A-Za-z+/]+={0,2}$/.test(p.integrity)||
    typeof p.resolved!=='string')fail('unverified locked package '+lockPath+':'+name);
   validRegistry(p.resolved);
   const key=name+'@'+p.version;
   const license=typeof p.license==='string'&&p.license.trim()?p.license:null;
   const candidate={name,version:p.version,licenseFromLockfile:license,
    resolved:p.resolved,integrity:p.integrity};
   const item=packages.get(key);
   if(item){
    for(const field of ['name','version','licenseFromLockfile','resolved','integrity'])
     if(item[field]!==candidate[field])fail('conflicting duplicated lock metadata '+key);
    item.locations.push({lockfile:lockPath,path:location,optional:p.optional===true});
   }else packages.set(key,{...candidate,locations:[{lockfile:lockPath,path:location,optional:p.optional===true}]});
   count++;
  }
  locks.push({path:lockPath,sha256:sha(Buffer.from(raw)),packages:count,rootDependencies:Object.keys(manifest.dependencies||{}).length});
 }
 const actionMap=new Map();
 for(const path of workflows){
  let raw;
  try{raw=await read(path);}catch{fail('missing workflow '+path);}
  const uses=raw.split('\n').filter(line=>/^\s*-\s*uses\s*:/.test(line));
  for(const line of uses){
   const m=/^\s*-\s*uses:\s*([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)@([a-f0-9]{40})(?:\s+#.*)?\s*$/.exec(line);
   if(!m)fail('unpinned or unsupported workflow action '+path);
   const key=m[1]+'@'+m[2];
   const item=actionMap.get(key);
   if(item)item.workflows.push(path);
   else actionMap.set(key,{action:m[1],revision:m[2],workflows:[path]});
  }
 }
 const [browser,postgres,scanner]=await Promise.all([
  read('.github/workflows/browser-workspace.yml'),
  read('.github/workflows/postgres-g1.yml'),
  read('.github/workflows/clamav-engine.yml')
 ]);
 if(!/playwright@1\.56\.1\b/.test(browser)||!/image:\s*postgres:16\b/.test(postgres)||
  !/install -y --no-install-recommends clamav-daemon\b/.test(scanner))
  fail('reviewed external-tool references changed');
 const dependencies=[...packages.values()].sort((a,b)=>a.name.localeCompare(b.name,'en')||a.version.localeCompare(b.version,'en'));
 for(const p of dependencies)p.locations.sort((a,b)=>a.lockfile.localeCompare(b.lockfile,'en')||a.path.localeCompare(b.path,'en'));
 const actions=[...actionMap.values()].sort((a,b)=>a.action.localeCompare(b.action,'en')||a.revision.localeCompare(b.revision,'en'));
 for(const a of actions)a.workflows.sort((a,b)=>a.localeCompare(b,'en'));
 return {
  schemaVersion:1,kind:'VERIVARO_ACQUISITION_DEPENDENCY_INVENTORY',
  sourceRevision,dataClass:'REPOSITORY_LOCKFILES_AND_WORKFLOWS_ONLY',
  releaseApproved:false,legalIpCleared:false,sourceOwnershipVerified:false,
  completeSbomVerified:false,externalLicensesIndependentlyReviewed:false,
  scope:{lockfiles:locks,workflowFiles:workflows,
   rootPackageHasRuntimeDependencies:locks[0].rootDependencies>0},
  distinctNpmPackages:dependencies.length,packages:dependencies,githubActions:actions,
  externalToolReferences:[
   {name:'Playwright',declaredVersion:'1.56.1',source:'browser-workspace.yml',metadataVerified:false},
   {name:'PostgreSQL',declaredVersion:'16 image tag',source:'postgres-g1.yml',metadataVerified:false},
   {name:'ClamAV',declaredVersion:'runner package version unspecified',source:'clamav-engine.yml',metadataVerified:false}
  ],
  exclusions:[
   'npm lockfile licence values are unverified registry metadata, not full licence texts or legal rights',
   'Playwright transitive downloads, operating system packages, PostgreSQL and ClamAV are not enumerated as locked npm packages',
   'GitHub Actions and Docker image transitive components, service configurations and marketplace terms are not independently checked',
   'Repository source authorship, third-party code copying, contributor assignment, trademark and domain clearance are not independently verified',
   'No declaration of title, license compliance, source origin, permission to transfer, independent SBOM completeness or commercial demand is made'
  ]
 };
}
export const buyerIpInventoryPaths=Object.freeze({lockfiles:lockPaths,workflows});
