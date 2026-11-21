import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawn,spawnSync} from 'node:child_process';
import {mkdtemp,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {request} from 'node:http';
import {createPortableBuyerBundle,verifyPortableBuyerBundle} from '../../src/demo/buyer-portable-bundle.mjs';
import {zip} from '../../src/security/verification-report-export.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
function entries(archive){
 const result=[];let offset=0;
 while(archive.readUInt32LE(offset)===0x04034b50){
  const n=archive.readUInt16LE(offset+26),size=archive.readUInt32LE(offset+22);
  result.push([archive.subarray(offset+30,offset+30+n).toString('ascii'),
   Buffer.from(archive.subarray(offset+30+n,offset+30+n+size))]);
  offset+=30+n+size;
 }
 return result;
}
test('buyer ZIP is reproducible, portable and always labelled synthetic',async()=>{
 const [a,b]=await Promise.all([createPortableBuyerBundle(),createPortableBuyerBundle()]);
 assert.equal(a.archiveSha256,b.archiveSha256);
 assert.ok(a.archive.equals(b.archive));
 assert.equal(a.synthetic,true);
 assert.equal(a.authenticityVerified,false);
 assert.equal(a.fileCount,8);
 const valid=verifyPortableBuyerBundle(a.archive,{expectedArchiveSha256:a.archiveSha256});
 assert.equal(valid.integrityVerified,true);
 assert.equal(valid.authenticityVerified,false);
 const files=entries(a.archive);
 assert.deepEqual(files.map(x=>x[0]),[
  'index.html','buyer-showcase.css','buyer-showcase.js',
  'buyer-demo.json','README.txt','preview.mjs','buyer-offline.html','manifest.json'
 ]);
 const html=files[0][1].toString(),script=files[2][1].toString();
 assert.match(html,/href="\.\/buyer-showcase\.css"/);
 assert.match(html,/src="\.\/buyer-showcase\.js"/);
 assert.match(script,/new URL\('\.\/buyer-demo\.json',document\.baseURI\)/);
 const fixture=JSON.parse(files[3][1].toString()),m=JSON.parse(files[7][1].toString());
 assert.deepEqual(fixture.stages.map(x=>x.blockers),[1,1,1,0]);
 assert.equal(fixture.handover.authenticityVerified,false);
 assert.equal(m.releaseApproved,false);
 assert.equal(m.files.length,7);
 assert.ok(files[4][1].toString().includes('No real users'));
 const offline=files[6][1].toString('utf8');
 assert.match(offline,/Content-Security-Policy/);
 assert.match(offline,/connect-src 'none'/);
 assert.match(offline,/script-src 'sha256-/);
 assert.match(offline,/style-src 'sha256-/);
 assert.match(offline,/const offlinePayload=/);
 assert.match(offline,/const response=\{ok:true,json:async\(\)=>offlinePayload\}/);
 assert.doesNotMatch(offline,/<script[^>]*src=/);
 assert.doesNotMatch(offline,/<link[^>]*href=/);
 assert.doesNotMatch(offline,/fetch\('\/buyer-demo\.json'/);

 const syntax=spawnSync(process.execPath,['--check','--input-type=module','-'],{
  input:files[5][1],encoding:'utf8'
 });
 assert.equal(syntax.status,0,syntax.stderr);
});
test('immutable source revision binding rejects wrong expected commit identity',async()=>{
 const revision='a'.repeat(40);
 const x=await createPortableBuyerBundle({sourceRevision:revision});
 assert.equal(x.sourceRevision,revision);
 const confirmed=verifyPortableBuyerBundle(x.archive,{
  expectedArchiveSha256:x.archiveSha256,expectedSourceRevision:revision
 });
 assert.equal(confirmed.sourceRevision,revision);
 assert.equal(confirmed.authenticityVerified,false);
 assert.throws(()=>verifyPortableBuyerBundle(x.archive,{
  expectedArchiveSha256:x.archiveSha256,expectedSourceRevision:'b'.repeat(40)
 }),/verification failed/);
 assert.throws(()=>verifyPortableBuyerBundle(x.archive,{
  expectedArchiveSha256:x.archiveSha256,expectedSourceRevision:null
 }),/verification failed/);
 await assert.rejects(createPortableBuyerBundle({sourceRevision:'main'}),/verification failed/);
 const files=entries(x.archive),manifest=JSON.parse(files.at(-1)[1]);
 assert.equal(manifest.sourceRevision,revision);
 assert.equal(manifest.archiveAuthenticityVerified,false);
});

test('ZIP verification fails closed on changed bytes, changed metadata and spoofed readiness',async()=>{
 const p=await createPortableBuyerBundle();
 assert.throws(()=>verifyPortableBuyerBundle(p.archive,{expectedArchiveSha256:'0'.repeat(64)}),
  /verification failed/);
 const broken=Buffer.from(p.archive);broken[50]^=1;
 assert.throws(()=>verifyPortableBuyerBundle(broken,{expectedArchiveSha256:p.archiveSha256}),
  /verification failed/);
 // Even if an adversary recomputes the ZIP hash, a silent byte flip must fail
 // the canonical STORE / CRC / directory validation.
 assert.throws(()=>verifyPortableBuyerBundle(broken,{expectedArchiveSha256:sha(broken)}),
  /verification failed/);
 const files=entries(p.archive);
 const falsified=files.map(([name,data])=>[name,Buffer.from(data)]);
 const fixture=JSON.parse(falsified[3][1].toString());
 fixture.releaseApproved=true;
 falsified[3][1]=Buffer.from(JSON.stringify(fixture));
 const rebundled=zip(falsified);
 assert.throws(()=>verifyPortableBuyerBundle(rebundled,{expectedArchiveSha256:sha(rebundled)}),
  /verification failed/);
 // A refreshed, internally consistent manifest is still rejected if it
 // attempts to upgrade the synthetic release status.
 const manifest=JSON.parse(falsified[7][1].toString());
 manifest.files[3].bytes=falsified[3][1].length;
 manifest.files[3].sha256=sha(falsified[3][1]);
 manifest.releaseApproved=true;
 falsified[7][1]=Buffer.from(JSON.stringify(manifest));
 const upgraded=zip(falsified);
 assert.throws(()=>verifyPortableBuyerBundle(upgraded,{expectedArchiveSha256:sha(upgraded)}),
  /verification failed/);
 // A complete self-held rehash of a changed offline viewer is not enough:
 // the rendered page must exactly regenerate from the canonical fixture/assets.
 const diverted=entries(p.archive).map(([name,data])=>[name,Buffer.from(data)]);
 const before=diverted[6][1].toString('utf8');
 const after=before.replace('<title>Verivaro | Evidence lifecycle showcase</title>',
  '<title>Changed buyer claim</title>');
 assert.notEqual(before,after);
 diverted[6][1]=Buffer.from(after,'utf8');
 const m=JSON.parse(diverted[7][1].toString('utf8'));
 m.files[6].bytes=diverted[6][1].length;
 m.files[6].sha256=sha(diverted[6][1]);
 diverted[7][1]=Buffer.from(JSON.stringify(m));
 const coherent=zip(diverted);
 assert.throws(()=>verifyPortableBuyerBundle(coherent,{
  expectedArchiveSha256:sha(coherent)
 }),/verification failed/);
});

test('packaged preview serves only local read-only synthetic assets',{timeout:20000},async t=>{
 const built=await createPortableBuyerBundle();
 const dir=await mkdtemp(join(tmpdir(),'verivaro-buyer-fixture-'));
 t.after(()=>rm(dir,{recursive:true,force:true}));
 for(const [name,data] of entries(built.archive))
  await writeFile(join(dir,name),data,{flag:'wx',mode:0o600});
 const child=spawn(process.execPath,['preview.mjs'],{
  cwd:dir,stdio:['ignore','pipe','pipe']
 });
 t.after(()=>{if(child.exitCode===null)child.kill('SIGTERM');});
 const base=await new Promise((resolve,reject)=>{
  let stdout='',stderr='';
  const timeout=setTimeout(()=>{
   child.kill('SIGTERM');
   reject(Error('local preview startup timeout: '+stderr));
  },8000);
  const finish=(fn,value)=>{clearTimeout(timeout);fn(value);};
  child.stderr.on('data',x=>{stderr+=String(x);});
  child.on('error',e=>finish(reject,e));
  child.on('exit',code=>finish(reject,Error('local preview exited '+code+': '+stderr)));
  child.stdout.on('data',chunk=>{
   stdout+=String(chunk);
   const match=stdout.match(/http:\/\/127\.0\.0\.1:\d+\//);
   if(match)finish(resolve,match[0]);
  });
 });
 const [html,fixture,js,css]=await Promise.all([
  fetch(base),fetch(base+'buyer-demo.json'),
  fetch(base+'buyer-showcase.js'),fetch(base+'buyer-showcase.css')
 ]);
 assert.deepEqual([html.status,fixture.status,js.status,css.status],[200,200,200,200]);
 assert.equal(html.headers.get('cache-control'),'no-store');
 assert.match(html.headers.get('content-security-policy'),/default-src 'none'/);
 assert.match(await html.text(),/SYNTHETIC WALKTHROUGH/);
 assert.equal((await fixture.json()).releaseApproved,false);
 assert.equal((await fetch(base+'hidden',{method:'GET'})).status,404);
 assert.equal((await fetch(base+'buyer-demo.json',{method:'POST'})).status,405);
 const spoof=await new Promise((resolve,reject)=>{
  const parsed=new URL(base);
  const req=request({
   host:'127.0.0.1',port:Number(parsed.port),
   path:'/buyer-demo.json',method:'GET',
   headers:{host:'remote.example'}
  },response=>{
   response.resume();response.on('end',()=>resolve(response.statusCode));
  });
  req.on('error',reject);req.end();
 });
 assert.equal(spoof,403);
});
