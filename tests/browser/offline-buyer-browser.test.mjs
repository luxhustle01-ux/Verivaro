// Real browser exercise of the self-contained offline buyer page.
// No localhost listener, app service, credentials, download or network call.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {createPortableBuyerBundle} from '../../src/demo/buyer-portable-bundle.mjs';

if(!process.env.VV_BROWSER_DIR||!['chromium','webkit'].includes(process.env.VV_BROWSER_ENGINE))
 throw Error('explicit Chromium/WebKit browser fixture required');
const driver=createRequire(resolve(process.env.VV_BROWSER_DIR,'package.json'))('playwright');

test('single-file offline buyer walkthrough runs at mobile and desktop widths with no network',
 {timeout:120000},async t=>{
 const bundle=await createPortableBuyerBundle();
 let offset=0,html;
 while(offset+4<=bundle.archive.length&&bundle.archive.readUInt32LE(offset)===0x04034b50){
  const nameSize=bundle.archive.readUInt16LE(offset+26),
   size=bundle.archive.readUInt32LE(offset+22);
  const name=bundle.archive.subarray(offset+30,offset+30+nameSize).toString('ascii');
  if(name==='buyer-offline.html')
   html=Buffer.from(bundle.archive.subarray(offset+30+nameSize,offset+30+nameSize+size));
  offset+=30+nameSize+size;
 }
 if(!html)throw Error('missing offline viewer');
 const dir=await mkdtemp(join(tmpdir(),'vv-offline-showcase-'));
 t.after(()=>rm(dir,{recursive:true,force:true}));
 const path=join(dir,'buyer-offline.html');
 await writeFile(path,html,{flag:'wx',mode:0o600});
 const browser=await driver[process.env.VV_BROWSER_ENGINE].launch({headless:true});
 t.after(()=>browser.close());
 for(const width of [320,390,1280]){
  const context=await browser.newContext({viewport:{width,height:850},isMobile:width<500,hasTouch:width<500});
  try{
   const page=await context.newPage(),httpRequests=[],pageErrors=[];
   page.on('request',r=>{if(/^https?:\/\//i.test(r.url()))httpRequests.push(r.url());});
   page.on('pageerror',e=>pageErrors.push(e.message));
   await page.goto(pathToFileURL(path).href,{waitUntil:'load'});
   await page.locator('#loadState').getByText('REAL ENGINE · SYNTHETIC DATA').waitFor();
   assert.match(await page.locator('#stageBody').textContent(),/No proof supplied/);
   assert.equal(await page.locator('#stageNav button').count(),4);
   await page.locator('#stageNav button[data-step="1"]').click();
   assert.match(await page.locator('.status-pill').textContent(),/CONFLICTING EVIDENCE/);
   await page.locator('#stageNav button[data-step="2"]').click();
   assert.match(await page.locator('#readiness').textContent(),/Not ready/);
   await page.locator('#stageNav button[data-step="3"]').click();
   assert.match(await page.locator('#readiness').textContent(),/Checks satisfied/);
   assert.match(await page.locator('#handoverResult').textContent(),/independent trust NOT verified/i);
   assert.equal(httpRequests.length,0,'Offline viewer made unexpected network calls');
   assert.deepEqual(pageErrors,[]);
   const dimensions=await page.evaluate(()=>({
    viewport:innerWidth,scroll:document.documentElement.scrollWidth
   }));
   assert.ok(dimensions.scroll<=dimensions.viewport+1,
    'Offline viewer horizontal overflow at '+width);
  }finally{await context.close();}
 }
});
