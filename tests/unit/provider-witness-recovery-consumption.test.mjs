import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {mkdtemp,mkdir,rm,readFile,writeFile,unlink,readdir} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {
 createUnsignedRecoveryReviewStatement,canonicalRecoveryReviewStatement,
 recoveryReviewEvidenceHash
} from '../../src/security/provider-witness-recovery-approval.mjs';
import {
 encodeReferenceRecoveryApprovalGenesis,verifyReferenceRecoveryApprovalLog,
 openReferenceRecoveryApprovalConsumption
} from '../../src/security/provider-witness-recovery-consumption.mjs';

const execAsync=promisify(execFile);
const scope={issuer:'https://issuer.example.invalid',audience:'verivaro-internal'};
const floor={count:2,headHash:'b'.repeat(64)};
const firstId='1'.repeat(32),secondId='2'.repeat(32);
const date='2026-11-21T04:00:00.000Z';
const assessment=Object.freeze({
 status:'MANUAL_REVIEW_REQUIRED',evidenceConsistentAtInspection:true,
 automaticRecoveryPermitted:false,
 authenticatedHead:{count:2,headHash:floor.headHash,
  checkpoint:{sequence:2,digest:'2'.repeat(64)}},
 writerLocks:{journal:true,publisher:true},
 pendingPublisherFiles:['.receipt-01234567.pending']
});
async function lab(t){
 const root=await mkdtemp(join(tmpdir(),'vv-approval-register-'));
 t.after(()=>rm(root,{recursive:true,force:true}));
 const directory=join(root,'register');
 await mkdir(directory,{mode:0o700});
 const keys={owner:generateKeyPairSync('ed25519'),security:generateKeyPairSync('ed25519')};
 const genesis=encodeReferenceRecoveryApprovalGenesis({...scope,serial:6});
 const path=join(directory,'recovery-review-consumption.jsonl');
 await writeFile(path,genesis.bytes,{mode:0o600});
 const pinned={serial:6,headHash:genesis.headHash};
 const config=(updatedFloor=pinned)=>({
  directory,...scope,trustedRegisterFloor:updatedFloor,trustedFloor:floor,
  trustedReviewerKeys:{owner:keys.owner.publicKey,security:keys.security.publicKey},
  clock:()=>new Date(date)
 });
 function make(serial=7,approvalId=firstId,evidence=assessment){
  const statement=createUnsignedRecoveryReviewStatement({...scope,
   approvalId,serial,evidenceHash:recoveryReviewEvidenceHash(evidence,{
    ...scope,trustedFloor:floor
   }),issuedAt:'2026-11-21T03:00:00.000Z',
   expiresAt:'2026-11-21T05:00:00.000Z'
  });
  const bytes=canonicalRecoveryReviewStatement(statement);
  return {statement,signatures:[
   {role:'owner',signature:sign(null,bytes,keys.owner.privateKey).toString('base64url')},
   {role:'security',signature:sign(null,bytes,keys.security.privateKey).toString('base64url')}
  ]};
 }
 const request=(serial=7,approvalId=firstId)=>({
  assessment,envelope:make(serial,approvalId),expectedApprovalId:approvalId
 });
 const open=(newFloor=pinned)=>openReferenceRecoveryApprovalConsumption(config(newFloor));
 return {root,directory,path,keys,pinned,genesis,config,make,request,open};
}
test('signed review consumption is single-use, increasing and never authorizes recovery',async t=>{
 const f=await lab(t),register=await f.open();
 const accepted=await register.consume(f.request());
 assert.equal(accepted.decision,'REVIEW_APPROVAL_CONSUMED_ONLY');
 assert.equal(accepted.serial,7);
 assert.equal(accepted.automaticRecoveryPermitted,false);
 assert.equal(accepted.manualReconciliationRequired,true);
 await assert.rejects(register.consume(f.request()),/conflict/);
 assert.equal((await register.audit()).serial,7);
 const next=await register.consume(f.request(8,secondId));
 assert.equal(next.serial,8);
 assert.equal((await register.audit()).count,3);
 await register.close();
});
test('16 concurrent requests consume exactly one approval serial',async t=>{
 const f=await lab(t),register=await f.open();
 const results=await Promise.allSettled(Array.from({length:16},
  ()=>register.consume(f.request())));
 assert.equal(results.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(results.filter(x=>x.status==='rejected').length,15);
 assert.equal((await register.audit()).serial,7);
 await register.close();
});
test('second active register process cannot acquire a competing writer lease',async t=>{
 const f=await lab(t),register=await f.open();
 await assert.rejects(f.open(),/unavailable/);
 await register.close();
 const reopened=await f.open();
 assert.equal((await reopened.audit()).serial,6);
 await reopened.close();
});
test('stale independently pinned register floor refuses restart after consumption',async t=>{
 const f=await lab(t),reg=await f.open();
 await reg.consume(f.request());
 const updated=await reg.audit();
 await reg.close();
 await assert.rejects(f.open(),/unavailable/);
 const fresh=await f.open({serial:updated.serial,headHash:updated.headHash});
 assert.equal((await fresh.audit()).serial,7);
 await assert.rejects(fresh.consume(f.request()),/conflict/);
 await fresh.close();
});
test('failed evidence, wrong signer and stale ID reject prewrite without poisoning register',async t=>{
 const f=await lab(t),reg=await f.open();
 const wrong={...assessment,writerLocks:{journal:false,publisher:true}};
 await assert.rejects(reg.consume({
  ...f.request(),assessment:wrong
 }),/conflict/);
 await assert.rejects(reg.consume({
  ...f.request(),expectedApprovalId:secondId
 }),/conflict/);
 const forged=f.make();
 forged.signatures[0].signature='a'.repeat(86);
 await assert.rejects(reg.consume({
  ...f.request(),envelope:forged
 }),/conflict/);
 assert.equal((await reg.audit()).serial,6);
 await reg.consume(f.request());
 await reg.close();
});
test('rollback, chain truncation and corrupt hash are denied with fresh external floor',async t=>{
 const f=await lab(t),reg=await f.open(),original=await readFile(f.path);
 await reg.consume(f.request());
 const updated=await reg.audit();
 await reg.close();
 await writeFile(f.path,original);
 await assert.rejects(f.open({serial:updated.serial,headHash:updated.headHash}),/unavailable/);
 await writeFile(f.path,original.subarray(0,-4));
 await assert.rejects(f.open(),/unavailable/);
 const damaged=Buffer.from(original.toString('utf8').replace('"serial":6','"serial":5'));
 await writeFile(f.path,damaged);
 await assert.rejects(f.open(),/unavailable/);
});
test('out-of-band live register mutation permanently faults and preserves writer lock',async t=>{
 const f=await lab(t),reg=await f.open();
 const original=await readFile(f.path);
 await writeFile(f.path,Buffer.from(original.toString().replace('"serial":6','"serial":5')));
 await assert.rejects(reg.audit(),/unavailable/);
 await writeFile(f.path,original);
 await assert.rejects(reg.consume(f.request()),/unavailable/);
 await reg.close();
 await assert.rejects(f.open(),/unavailable/);
});
test('interrupted post-fsync acknowledgement latches and cannot retry',async t=>{
 const f=await lab(t);
 const reg=await openReferenceRecoveryApprovalConsumption({
  ...f.config(),enableTestFaultInjection:true,
  faultInjection:phase=>{if(phase==='after-log-fsync')throw Error('synthetic lost ack');}
 });
 await assert.rejects(reg.consume(f.request()),/unavailable/);
 const bytes=await readFile(f.path);
 assert.equal(bytes.toString().trimEnd().split('\n').length,2);
 await assert.rejects(reg.consume(f.request()),/unavailable/);
 await reg.close();
 assert.equal((await readdir(f.directory)).includes('.recovery-review-consumption.lock'),true);
 await assert.rejects(f.open(),/unavailable/);
});
test('real child process crash after fsync preserves committed serial and abandoned lock',async t=>{
 const f=await lab(t);
 const argsFile=join(f.root,'test-only-data.json');
 const keysDir=join(f.root,'test-only-keys');
 await mkdir(keysDir,{mode:0o700});
 const ownerPath=join(keysDir,'owner.pem'),securityPath=join(keysDir,'security.pem');
 await writeFile(ownerPath,f.keys.owner.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});
 await writeFile(securityPath,f.keys.security.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});
 const data={directory:f.directory,...scope,trustedRegisterFloor:f.pinned,
  trustedFloor:floor,assessment,expectedApprovalId:firstId,
  envelope:f.make()};
 await writeFile(argsFile,JSON.stringify(data),{mode:0o600});
 const code=String.raw`
import {readFileSync} from 'node:fs';
import {createPrivateKey,createPublicKey} from 'node:crypto';
import {openReferenceRecoveryApprovalConsumption} from './src/security/provider-witness-recovery-consumption.mjs';
try{
 const data=JSON.parse(readFileSync(process.env.VV_ARGS,'utf8'));
 const owner=createPublicKey(createPrivateKey(readFileSync(process.env.VV_OWNER)));
 const security=createPublicKey(createPrivateKey(readFileSync(process.env.VV_SECURITY)));
 const register=await openReferenceRecoveryApprovalConsumption({
  ...data,trustedReviewerKeys:{owner,security},
  clock:()=>new Date('2026-11-21T04:00:00.000Z'),
  enableTestFaultInjection:true,
  faultInjection:phase=>{if(phase==='after-log-fsync')process.exit(77);}
 });
 await register.consume({envelope:data.envelope,assessment:data.assessment,
  expectedApprovalId:data.expectedApprovalId});
 process.exit(78);
}catch{process.exit(79);}
`;
 await assert.rejects(execAsync(process.execPath,['--input-type=module','-e',code],{
  cwd:process.cwd(),timeout:10000,
  env:{...process.env,VV_ARGS:argsFile,VV_OWNER:ownerPath,VV_SECURITY:securityPath}
 }),e=>e.code===77);
 const bytes=await readFile(f.path);
 const last=JSON.parse(bytes.toString().trimEnd().split('\n').at(-1));
 const recovered=verifyReferenceRecoveryApprovalLog(bytes,{
  ...scope,trustedHead:last.hash
 });
 assert.equal(recovered.serial,7);
 assert.equal((await readdir(f.directory)).includes('.recovery-review-consumption.lock'),true);
 await assert.rejects(f.open(),/unavailable/);
 await assert.rejects(f.open({
  serial:recovered.serial,headHash:recovered.headHash
 }),/unavailable/);
 // No synthetic cleanup here: recovery needs explicit authorisation.
});
test('non-canonical or forged ledger records never acquire registry writer lease',async t=>{
 const f=await lab(t);
 const contents=await readFile(f.path);
 await writeFile(f.path,Buffer.from(contents.toString().replace(
  '"kind":"genesis"','"kind":"consume"')));
 await assert.rejects(f.open(),/unavailable/);
 await writeFile(f.path,contents.subarray(0,contents.length-1));
 await assert.rejects(f.open(),/unavailable/);
 assert.equal((await readdir(f.directory)).includes('.recovery-review-consumption.lock'),false);
});
test('unexpected file and abandoned lock deny startup without automatic removal',async t=>{
 const f=await lab(t),extra=join(f.directory,'orphan.pending');
 await writeFile(extra,'suspicious metadata',{mode:0o600});
 await assert.rejects(f.open(),/unavailable/);
 await unlink(extra);
 const lock=join(f.directory,'.recovery-review-consumption.lock');
 await writeFile(lock,'reserved\n',{mode:0o600});
 await assert.rejects(f.open(),/unavailable/);
 assert.equal(await readFile(lock,'utf8'),'reserved\n');
});


test('approval ID cannot be signed and reused under a new serial',async t=>{
 const f=await lab(t),reg=await f.open();
 await reg.consume(f.request());
 await assert.rejects(reg.consume(f.request(8,firstId)),/conflict/);
 assert.equal((await reg.audit()).serial,7);
 const accepted=await reg.consume(f.request(8,secondId));
 assert.equal(accepted.serial,8);
 assert.equal(accepted.automaticRecoveryPermitted,false);
 await reg.close();
});

test('duplicate IDs are denied even in a canonical, rehashed forged chain',async t=>{
 const f=await lab(t),reg=await f.open();
 await reg.consume(f.request());
 await reg.consume(f.request(8,secondId));
 await reg.close();
 const original=(await readFile(f.path,'utf8')).trimEnd().split('\n');
 const last=JSON.parse(original.at(-1));
 const body={version:1,kind:'consume',issuer:scope.issuer,audience:scope.audience,
  serial:last.serial,approvalId:firstId,evidenceHash:last.evidenceHash,
  previousHash:last.previousHash};
 const forgedHash=createHash('sha256')
  .update('verivaro-g1-consumed-review-v1\0')
  .update(Buffer.from(JSON.stringify(body),'utf8')).digest('hex');
 const forged={...body,hash:forgedHash};
 const tampered=original.slice(0,-1).concat(JSON.stringify(forged)).join('\n')+'\n';
 await writeFile(f.path,tampered,{mode:0o600});
 await assert.rejects(f.open({serial:8,headHash:forgedHash}),/unavailable/);
 assert.equal((await readdir(f.directory)).includes('.recovery-review-consumption.lock'),false);
});
