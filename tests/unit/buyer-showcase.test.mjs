import test from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {request} from 'node:http';
import {buildBuyerShowcasePayload} from '../../src/demo/buyer-showcase.mjs';
import {createBuyerShowcaseServer} from '../../src/demo/buyer-showcase-server.mjs';

test('showcase payload comes from domain truth and preserves conservative readiness',async()=>{
 const result=await buildBuyerShowcasePayload();
 assert.equal(result.dataClass,'SYNTHETIC_ONLY');
 assert.equal(result.releaseApproved,false);
 assert.equal(result.commercialDemandValidated,false);
 assert.equal(result.independentCustodyVerified,false);
 assert.deepEqual(result.stages.map(s=>s.status),[
  'missing','conflicting','provisional','verified-configured-checks'
 ]);
 assert.deepEqual(result.stages.map(s=>s.blockers),[1,1,1,0]);
 assert.equal(result.stages[0].sourceExcerpt[0].text,'Required serial: HVAC-001');
 assert.equal(result.stages[1].sourceExcerpt[1].text,'HVAC-002');
 assert.equal(result.stages[2].proofStates.at(-1).review,'pending');
 assert.equal(result.stages[3].proofStates.at(-1).review,'approved');
 assert.equal(result.handover.selfHeldHashIntegrity,true);
 assert.equal(result.handover.authenticityVerified,false);
 assert.equal(result.handover.independentDigestCustody,false);
 assert.match(result.handover.archiveSha256,/^[0-9a-f]{64}$/);
});
test('showcase renders deterministic synthetic state with no writable endpoint',async t=>{
 const server=await createBuyerShowcaseServer();
 t.after(()=>new Promise(resolve=>server.close(resolve)));
 server.listen(0,'127.0.0.1');
 await once(server,'listening');
 const base='http://127.0.0.1:'+server.address().port;
 const [html,css,script,json]=await Promise.all([
  fetch(base+'/'),fetch(base+'/buyer-showcase.css'),
  fetch(base+'/buyer-showcase.js'),fetch(base+'/buyer-demo.json')
 ]);
 assert.deepEqual([html.status,css.status,script.status,json.status],[200,200,200,200]);
 assert.match(html.headers.get('content-security-policy'),/default-src 'none'/);
 assert.match(html.headers.get('content-security-policy'),/script-src 'self'/);
 assert.equal(html.headers.get('x-content-type-options'),'nosniff');
 assert.equal(html.headers.get('cache-control'),'no-store');
 const page=await html.text(),code=await script.text(),payload=await json.json();
 assert.match(page,/viewport-fit=cover/);
 assert.match(page,/SYNTHETIC WALKTHROUGH/);
 assert.match(code,/textContent/);
 assert.equal(payload.stages.length,4);
 assert.equal((await fetch(base+'/no-such-page')).status,404);
 assert.equal((await fetch(base+'/buyer-demo.json',{method:'POST'})).status,405);
 const hostSpoofStatus=await new Promise((resolve,reject)=>{
  const req=request({
   host:'127.0.0.1',port:server.address().port,
   path:'/buyer-demo.json',method:'GET',
   headers:{host:'remote.example'}
  },res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});
  req.on('error',reject);req.end();
 });
 assert.equal(hostSpoofStatus,403);
 assert.equal((await fetch(base+'/buyer-demo.json',{method:'HEAD'})).headers.get('cache-control'),'no-store');
});
