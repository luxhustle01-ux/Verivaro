// Offline, dependency-free synthetic buyer demonstration package.
// Not a real customer export, a signed release, independent evidence custody,
// or permission to deploy. This is a reproducible acquisition-review fixture.
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {zip} from '../security/verification-report-export.mjs';
import {buildBuyerShowcasePayload} from './buyer-showcase.mjs';

const hash=b=>createHash('sha256').update(b).digest('hex');
const expected=['index.html','buyer-showcase.css','buyer-showcase.js',
 'buyer-demo.json','README.txt','preview.mjs','buyer-offline.html','manifest.json'];
const strictHash=h=>typeof h==='string'&&/^[a-f0-9]{64}$/.test(h);
const strictRevision=h=>typeof h==='string'&&/^[a-f0-9]{40}$/.test(h);
const fail=()=>{throw Error('portable buyer bundle verification failed');};
const utf8=b=>new TextDecoder('utf-8',{fatal:true}).decode(b);
const guide=[
 'VERIVARO — SYNTHETIC BUYER REVIEW BUNDLE',
 '========================================',
 'This is a deterministic demo, not a customer release, hosted SaaS,',
 'production security assessment, legal compliance or sale validation.',
 '',
 'Offline viewer: open buyer-offline.html in a local HTML/JavaScript-capable browser.',
 'It requires NO Node.js, hosting or network access. Some mobile file viewers',
 'disable local JavaScript; that device compatibility is NOT yet certified.',
 'For the optional loopback preview, Node.js 22.16.0 is required.',
 '1. Extract every file to one directory. Keep all filenames unchanged.',
 '2. In that directory, run: node preview.mjs',
 '3. Open the 127.0.0.1 URL shown in the terminal on the SAME device.',
 '   The viewer cannot be opened from another device or public network.',
 '4. Inspect missing -> conflicting -> pending -> configured checks passed.',
 '5. Read manifest.json for file byte counts and SHA-256 values.',
 '   A trusted archive SHA-256 must come from a separate trusted channel',
 '   before it can independently authenticate an acquired archive.',
 '',
 'Files: index.html, buyer-showcase.css, buyer-showcase.js,',
 'buyer-demo.json, README.txt, preview.mjs, buyer-offline.html,',
 'manifest.json. Each has a SHA-256 inventory entry.',
 'No real users, reviewer signatures, independent custody or customer data.',
 'The archive may be sold as a SOURCE/DEMO asset only, subject to due diligence.',
 ''
].join('\n');
const preview=[
 "import {createServer} from 'node:http';",
 "import {readFile} from 'node:fs/promises';",
 "const paths=new Map([['/','index.html'],['/index.html','index.html'],",
 " ['/buyer-showcase.css','buyer-showcase.css'],",
 " ['/buyer-showcase.js','buyer-showcase.js'],",
 " ['/buyer-demo.json','buyer-demo.json']]);",
 "const types={'index.html':'text/html','buyer-showcase.css':'text/css',",
 " 'buyer-showcase.js':'text/javascript','buyer-demo.json':'application/json'};",
 "const files=new Map();",
 "for(const name of new Set(paths.values()))files.set(name,",
 " await readFile(new URL('./'+name,import.meta.url)));",
 "const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',",
 " 'X-Frame-Options':'DENY','Referrer-Policy':'no-referrer',",
 " 'Content-Security-Policy':\"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'none'\",",
 " 'Permissions-Policy':'camera=(), microphone=(), geolocation=(), payment=()'};",
 "const server=createServer((req,res)=>{",
 " const local=req.socket.localAddress,host=req.headers.host||'';",
 " const allowed=local==='127.0.0.1'&&",
 " /^((127\\.0\\.0\\.1)|(localhost))(:[0-9]{1,5})?$/.test(host);",
 " const okMethod=['GET','HEAD'].includes(req.method);",
 " const name=paths.get(req.url);",
 " const status=!allowed?403:!okMethod?405:!name?404:200;",
 " const body=status===200?files.get(name):Buffer.from('Unavailable\\n');",
 " res.writeHead(status,{...headers,'Content-Type':status===200?types[name]+'; charset=utf-8':'text/plain; charset=utf-8','Content-Length':body.length});",
 " res.end(req.method==='HEAD'?undefined:body);",
 "});",
 "server.listen(0,'127.0.0.1',()=>{",
 " console.log('Verivaro synthetic buyer preview: http://127.0.0.1:'+server.address().port+'/');",
 "});",
 ''
].join('\n');

function syntheticOnly(p){
 if(p?.version!==1||p.dataClass!=='SYNTHETIC_ONLY'||
  p.releaseApproved!==false||p.commercialDemandValidated!==false||
  p.independentCustodyVerified!==false||
  p.handover?.authenticityVerified!==false||
  p.handover?.independentDigestCustody!==false||
  !Array.isArray(p.stages)||p.stages.length!==4||
  p.stages.some((s,i)=>s.status!==['missing','conflicting','provisional','verified-configured-checks'][i]||
   s.ready!==(i===3)||s.blockers!==(i===3?0:1)))fail();
}

function createOfflineViewer({rawHtml,rawCss,rawJs,payload}){
 const fetchLine="const response=await fetch('/buyer-demo.json',{cache:'no-store',credentials:'omit'});";
 const cssTag='<link rel="stylesheet" href="/buyer-showcase.css">';
 const jsTag='<script defer src="/buyer-showcase.js"></script>';
 if(!rawHtml.includes(cssTag)||!rawHtml.includes(jsTag)||
  !rawJs.includes(fetchLine)||/<\/style\b/i.test(rawCss)||
  /<\/script\b/i.test(rawJs))fail();
 // JSON is inserted as a JavaScript literal, never as unescaped HTML text.
 // Escaping < prevents a synthetic source string from closing our script tag.
 const safeJson=JSON.stringify(payload).replace(/[<>&\u2028\u2029]/g,ch=>({
  '<':'\\u003c','>':'\\u003e','&':'\\u0026',
  '\u2028':'\\u2028','\u2029':'\\u2029'
 })[ch]);
 const script="const offlinePayload="+safeJson+";\n"+
  rawJs.replace(fetchLine,"const response={ok:true,json:async()=>offlinePayload};");
 const b64=s=>createHash('sha256').update(s,'utf8').digest('base64');
 const csp="default-src 'none'; script-src 'sha256-"+b64(script)+
  "'; style-src 'sha256-"+b64(rawCss)+
  "'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'";
 const html=rawHtml.replace(cssTag,
  '<meta http-equiv="Content-Security-Policy" content="'+csp+'">\n<style>'+rawCss+'</style>')
  .replace(jsTag,'<script>'+script+'</script>');
 if(html.includes('src="/buyer-showcase.js"')||
  html.includes('href="/buyer-showcase.css"')||
  html.includes('fetch(\'/buyer-demo.json\''))fail();
 return html;
}

export async function createPortableBuyerBundle({sourceRevision=null}={}){
 if(sourceRevision!==null&&!strictRevision(sourceRevision))fail();
 const p=await buildBuyerShowcasePayload();
 syntheticOnly(p);
 const [rawHtml,rawCss,rawJs]=await Promise.all([
  'buyer-showcase.html','buyer-showcase.css','buyer-showcase.js'
 ].map(name=>readFile(new URL(name,import.meta.url),'utf8')));
 // The existing loopback preview stays unchanged. Make the ZIP portable
 // to a subpath/static server without relying on root-absolute URLs.
 const html=rawHtml.replace('href="/buyer-showcase.css"','href="./buyer-showcase.css"')
  .replace('src="/buyer-showcase.js"','src="./buyer-showcase.js"');
 const js=rawJs.replace("fetch('/buyer-demo.json',",
  "fetch(new URL('./buyer-demo.json',document.baseURI),");
 if(html===rawHtml||js===rawJs||
  html.includes('href="/buyer-showcase.css"')||
  html.includes('src="/buyer-showcase.js"')||
  js.includes("fetch('/buyer-demo.json',"))fail();
 const files=[
  ['index.html',Buffer.from(html)],
  ['buyer-showcase.css',Buffer.from(rawCss)],
  ['buyer-showcase.js',Buffer.from(js)],
  ['buyer-demo.json',Buffer.from(JSON.stringify(p,null,2)+'\n')],
  ['README.txt',Buffer.from(guide)],
  ['preview.mjs',Buffer.from(preview)],
  ['buyer-offline.html',Buffer.from(createOfflineViewer({rawHtml,rawCss,rawJs,payload:p}))]
 ];
 const manifest=Buffer.from(JSON.stringify({
  schemaVersion:1,kind:'VERIVARO_SYNTHETIC_BUYER_DEMO',
  dataClass:'SYNTHETIC_ONLY',releaseApproved:false,
  commercialDemandValidated:false,independentCustodyVerified:false,
  archiveAuthenticityVerified:false,
  sourceRevision,
  files:files.map(([name,b])=>({name,bytes:b.length,sha256:hash(b)}))
 },null,2)+'\n');
 files.push(['manifest.json',manifest]);
 const archive=zip(files);
 const archiveSha256=hash(archive);
 const verified=verifyPortableBuyerBundle(archive,{expectedArchiveSha256:archiveSha256,expectedSourceRevision:sourceRevision});
 if(!verified.integrityVerified||verified.authenticityVerified)fail();
 return {archive,archiveSha256,manifestSha256:hash(manifest),sourceRevision,
  fileCount:files.length,integrityVerified:true,
  authenticityVerified:false,synthetic:true};
}

// Verifies the exact canonical STORE ZIP bytes, entries, directory and CRC
// against a supplied digest. The caller must acquire that digest through an
// independently trusted channel for external tamper/authorship assurance.
export function verifyPortableBuyerBundle(archive,{expectedArchiveSha256,expectedSourceRevision}={}){
 if(expectedSourceRevision!==undefined&&expectedSourceRevision!==null&&!strictRevision(expectedSourceRevision))fail();
 if(!Buffer.isBuffer(archive)||archive.length<22||archive.length>524288||
  !strictHash(expectedArchiveSha256)||hash(archive)!==expectedArchiveSha256)fail();
 let pos=0;const files=[];
 while(pos+4<=archive.length&&archive.readUInt32LE(pos)===0x04034b50){
  if(files.length>=expected.length||pos+30>archive.length)fail();
  const nameLength=archive.readUInt16LE(pos+26),size=archive.readUInt32LE(pos+22);
  if(nameLength<1||nameLength>64||size<1||size>262144||
   archive.readUInt16LE(pos+6)!==0||archive.readUInt16LE(pos+8)!==0||
   archive.readUInt16LE(pos+28)!==0||
   archive.readUInt32LE(pos+18)!==size||
   pos+30+nameLength+size>archive.length)fail();
  const name=utf8(archive.subarray(pos+30,pos+30+nameLength));
  if(name!==expected[files.length])fail();
  files.push([name,archive.subarray(pos+30+nameLength,pos+30+nameLength+size)]);
  pos+=30+nameLength+size;
 }
 if(files.length!==expected.length)fail();
 const recreated=zip(files);
 try{if(!recreated.equals(archive))fail();}
 finally{recreated.fill(0);}
 let manifest,payload;
 try{
  manifest=JSON.parse(utf8(files.at(-1)[1]));
  payload=JSON.parse(utf8(files[3][1]));
 }catch{fail();}
 if(manifest?.schemaVersion!==1||
  manifest.kind!=='VERIVARO_SYNTHETIC_BUYER_DEMO'||
  manifest.dataClass!=='SYNTHETIC_ONLY'||
  manifest.releaseApproved!==false||
  manifest.commercialDemandValidated!==false||
  manifest.independentCustodyVerified!==false||
  manifest.archiveAuthenticityVerified!==false||
  !(manifest.sourceRevision===null||strictRevision(manifest.sourceRevision))||
  (expectedSourceRevision!==undefined&&manifest.sourceRevision!==expectedSourceRevision)||
  !Array.isArray(manifest.files)||manifest.files.length!==expected.length-1)fail();
 for(let i=0;i<files.length-1;i++){
  const x=manifest.files[i], [name,b]=files[i];
  if(!x||Object.keys(x).sort().join(',')!=='bytes,name,sha256'||
   x.name!==name||x.bytes!==b.length||x.sha256!==hash(b))fail();
 }
 syntheticOnly(payload);
 const offline=utf8(files[6][1]);
 if(!offline.includes('http-equiv="Content-Security-Policy"')||
  !offline.includes("connect-src 'none'")||
  !offline.includes("const offlinePayload=")||
  !offline.includes('const response={ok:true,json:async()=>offlinePayload};')||
  offline.includes('src="/buyer-showcase.js"')||
  offline.includes('href="/buyer-showcase.css"'))fail();
 // Re-derive the one-file viewer from the canonical multi-file sources and
 // the validated fixture. Reject separately edited HTML, even if its ZIP
 // inventory was rehashed to appear internally self-consistent.
 let regenerated;
 try{
  const sourceHtml=utf8(files[0][1])
   .replace('href="./buyer-showcase.css"','href="/buyer-showcase.css"')
   .replace('src="./buyer-showcase.js"','src="/buyer-showcase.js"');
  const sourceJs=utf8(files[2][1])
   .replace("fetch(new URL('./buyer-demo.json',document.baseURI),",
    "fetch('/buyer-demo.json',");
  regenerated=createOfflineViewer({
   rawHtml:sourceHtml,rawCss:utf8(files[1][1]),rawJs:sourceJs,payload
  });
 }catch{fail();}
 if(regenerated!==offline)fail();
 if(!utf8(files[0][1]).includes('href="./buyer-showcase.css"')||
  !utf8(files[0][1]).includes('src="./buyer-showcase.js"')||
  !utf8(files[2][1]).includes("fetch(new URL('./buyer-demo.json',document.baseURI),"))fail();
 return Object.freeze({integrityVerified:true,authenticityVerified:false,
  archiveSha256:hash(archive),fileCount:files.length,
  manifestSha256:hash(files.at(-1)[1]),sourceRevision:manifest.sourceRevision,dataClass:'SYNTHETIC_ONLY'});
}
