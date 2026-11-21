import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {buildBuyerIpInventory} from '../../src/security/buyer-ip-inventory.mjs';

const files=async name=>readFile(name,'utf8');
const altered=(path,transform)=>async name=>name===path?transform(await files(name)):files(name);
const lock='services/application/driver/package-lock.json';
const mutLock=change=>altered(lock,raw=>{
 const data=JSON.parse(raw);
 change(data);
 return JSON.stringify(data);
});

test('buyer inventory is deterministic, scope-limited and fails closed on legal claims',async()=>{
 const a=await buildBuyerIpInventory(),b=await buildBuyerIpInventory();
 assert.deepEqual(a,b);
 assert.equal(a.schemaVersion,1);
 assert.equal(a.dataClass,'REPOSITORY_LOCKFILES_AND_WORKFLOWS_ONLY');
 assert.equal(a.sourceRevision,null);
 assert.equal(a.distinctNpmPackages,14);
 assert.equal(a.scope.lockfiles.length,4);
 assert.equal(a.scope.workflowFiles.length,6);
 assert.equal(a.scope.rootPackageHasRuntimeDependencies,false);
 assert.equal(a.legalIpCleared,false);
 assert.equal(a.releaseApproved,false);
 assert.equal(a.sourceOwnershipVerified,false);
 assert.equal(a.completeSbomVerified,false);
 assert.equal(a.externalLicensesIndependentlyReviewed,false);
 assert.equal(a.packages.find(p=>p.name==='pg').version,'8.16.3');
 assert.equal(a.packages.find(p=>p.name==='pg-int8').licenseFromLockfile,'ISC');
 assert.ok(a.packages.every(p=>p.locations.length===3));
 assert.ok(a.packages.every(p=>p.integrity.startsWith('sha512-')));
 assert.ok(a.githubActions.length>0);
 assert.ok(a.githubActions.every(x=>/^[a-f0-9]{40}$/.test(x.revision)));
 assert.ok(a.exclusions.some(x=>/source authorship/i.test(x)));
});
test('revision identity is exact, optional and not publisher authentication',async()=>{
 const rev='a'.repeat(40),a=await buildBuyerIpInventory({sourceRevision:rev});
 assert.equal(a.sourceRevision,rev);
 assert.equal(a.legalIpCleared,false);
 await assert.rejects(buildBuyerIpInventory({sourceRevision:'main'}),/inventory rejected/);
});
test('rejects unpinned root dependency in package manifest',async()=>{
 const readText=altered('services/application/driver/package.json',raw=>{
  const j=JSON.parse(raw);
  j.dependencies.pg='8.16.4';
  return JSON.stringify(j);
 });
 await assert.rejects(buildBuyerIpInventory({readText}),/unlocked root dependency/);
});
test('rejects tampered upstream integrity, untrusted registry and divergent duplicate versions',async()=>{
 for(const change of [
  j=>{j.packages['node_modules/pg'].integrity='sha512-INVALID';},
  j=>{j.packages['node_modules/pg'].resolved='https://evil.example/pg.tgz';},
  j=>{j.packages['node_modules/pg'].license='Proprietary';}
 ])await assert.rejects(buildBuyerIpInventory({readText:mutLock(change)}),/inventory rejected/);
});
test('rejects workflow action tags and unpinned tool changes',async()=>{
 const path='.github/workflows/ci.yml';
 const readText=altered(path,raw=>raw.replace(/uses: actions\/checkout@[a-f0-9]{40}/,'uses: actions/checkout@v4'));
 await assert.rejects(buildBuyerIpInventory({readText}),/unpinned or unsupported workflow action/);
 const browser='.github/workflows/browser-workspace.yml';
 await assert.rejects(buildBuyerIpInventory({
  readText:altered(browser,raw=>raw.replace('playwright@1.56.1','playwright@latest'))
 }),/external-tool references changed/);
});
