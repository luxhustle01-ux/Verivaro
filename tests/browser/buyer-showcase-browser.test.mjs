import test from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {createBuyerShowcaseServer} from '../../src/demo/buyer-showcase-server.mjs';
import {buildBuyerShowcasePayload} from '../../src/demo/buyer-showcase.mjs';

if(!process.env.VV_BROWSER_DIR||!['chromium','webkit'].includes(process.env.VV_BROWSER_ENGINE))
 throw Error('explicit Chromium/WebKit browser fixture required');
const driver=createRequire(resolve(process.env.VV_BROWSER_DIR,'package.json'))('playwright');
const engine=process.env.VV_BROWSER_ENGINE;

test('real mobile and desktop browsers explain the complete four-step synthetic proof lifecycle',
 {timeout:120000},async t=>{
 const server=await createBuyerShowcaseServer();
 server.listen(0,'127.0.0.1');
 await once(server,'listening');
 t.after(()=>new Promise(resolve=>server.close(resolve)));
 const url='http://127.0.0.1:'+server.address().port+'/';
 const browser=await driver[engine].launch({headless:true});
 t.after(()=>browser.close());
 for(const width of [320,390,1280]){
  const context=await browser.newContext({
   viewport:{width,height:850},isMobile:width<500,hasTouch:width<500
  });
  try{
   const page=await context.newPage(),errors=[];
   page.on('pageerror',e=>errors.push(e.message));
   await page.goto(url,{waitUntil:'networkidle'});
   await page.locator('#loadState').getByText('REAL ENGINE · SYNTHETIC DATA').waitFor();
   assert.equal(await page.locator('#stageNav button').count(),4);
   assert.match(await page.locator('.status-pill').textContent(),/MISSING PROOF/);
   assert.match(await page.locator('#readiness').textContent(),/Not ready/);
   assert.match(await page.locator('#handoverResult').textContent(),/Unavailable/);
   assert.equal(await page.locator('#prevStage').isDisabled(),true);
   await page.locator('#nextStage').click();
   assert.match(await page.locator('.status-pill').textContent(),/CONFLICTING EVIDENCE/);
   assert.match(await page.locator('#evidenceList').textContent(),/HVAC-002/);
   await page.locator('#stageNav button[data-step="2"]').click();
   assert.match(await page.locator('.status-pill').textContent(),/AWAITING REVIEW/);
   assert.match(await page.locator('#readiness').textContent(),/Not ready/);
   assert.match(await page.locator('#evidenceList').textContent(),/PENDING/);
   await page.locator('#nextStage').click();
   assert.match(await page.locator('.status-pill').textContent(),/CONFIGURED CHECKS PASSED/);
   assert.match(await page.locator('#readiness').textContent(),/Checks satisfied/);
   assert.match(await page.locator('#handoverResult').textContent(),/self-held hashes/i);
   assert.match(await page.locator('#handoverResult').textContent(),/Authenticity and independent trust NOT verified/i);
   assert.equal(await page.locator('#nextStage').isDisabled(),true);
   await page.locator('#prevStage').click();
   assert.match(await page.locator('.status-pill').textContent(),/AWAITING REVIEW/);
   assert.match(await page.locator('#readiness').textContent(),/Not ready/);
   assert.equal(errors.length,0,errors.join('; '));
   const geometry=await page.evaluate(()=>({
    viewport:window.innerWidth,scroll:document.documentElement.scrollWidth,
    nav:[...document.querySelectorAll('#stageNav button')].map(x=>({
     height:x.getBoundingClientRect().height,width:x.getBoundingClientRect().width
    }))
   }));
   assert.ok(geometry.scroll<=geometry.viewport+1,
    'Horizontal viewport overflow at '+width+': '+JSON.stringify(geometry));
   assert.ok(geometry.nav.every(x=>x.height>=44),
    'Step tap targets must be at least 44 CSS pixels high');
  }finally{await context.close();}
 }
});
test('malicious source text remains text, not executable markup; invalid fixture denies readiness',
 {timeout:60000},async t=>{
 const server=await createBuyerShowcaseServer();
 server.listen(0,'127.0.0.1');await once(server,'listening');
 t.after(()=>new Promise(resolve=>server.close(resolve)));
 const browser=await driver[engine].launch({headless:true});
 t.after(()=>browser.close());
 const url='http://127.0.0.1:'+server.address().port+'/';
 const fixture=structuredClone(await buildBuyerShowcasePayload());
 fixture.stages[0].sourceExcerpt[0].text='<img src=x onerror=alert("XSS")>';
 const page=await browser.newPage(),dialogs=[];
 page.on('dialog',d=>{dialogs.push(d.message());return d.dismiss();});
 await page.route('**/buyer-demo.json',route=>route.fulfill({
  status:200,contentType:'application/json',body:JSON.stringify(fixture)
 }));
 await page.goto(url,{waitUntil:'networkidle'});
 await page.locator('#loadState').getByText('REAL ENGINE · SYNTHETIC DATA').waitFor();
 assert.match(await page.locator('#evidenceList').textContent(),/onerror=alert/);
 assert.equal(await page.locator('#evidenceList img').count(),0);
 assert.deepEqual(dialogs,[]);
 await page.unroute('**/buyer-demo.json');
 await page.route('**/buyer-demo.json',route=>route.fulfill({
  status:200,contentType:'application/json',
  body:JSON.stringify({...fixture,releaseApproved:true})
 }));
 await page.reload({waitUntil:'networkidle'});
 await page.locator('#loadState').getByText('DEMO UNAVAILABLE').waitFor();
 assert.equal(await page.locator('#nextStage').isDisabled(),true);
 assert.match(await page.locator('#stageBody').textContent(),/Unable to verify/);
});
