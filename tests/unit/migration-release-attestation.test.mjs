import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {makeMigrationReleaseManifest,releaseSigningPayload,verifyMigrationReleaseAttestation,
 canonicalReleaseJson,releaseSha256} from '../../src/security/migration-release-attestation.mjs';

const files=[
 {path:'db/migrations/0001_one.sql',bytes:Buffer.from('BEGIN;\nSELECT 1;\nCOMMIT;\n')},
 {path:'db/migrations/0002_two.sql',bytes:Buffer.from('BEGIN;\nSELECT 2;\nCOMMIT;\n')},
 {path:'db/migration-lock.json',bytes:Buffer.from('{"migrations":2}\n')}
];
const pathList=files.map(f=>f.path);
function fixture(sequence=5){
 const owner=generateKeyPairSync('ed25519'),reviewer=generateKeyPairSync('ed25519');
 const manifestBytes=makeMigrationReleaseManifest({sequence,sourceCommit:'a'.repeat(40),files});
 const keys=[{id:'owner-key',role:'owner',publicKeyPem:owner.publicKey.export({type:'spki',format:'pem'}),revoked:false},
  {id:'review-key',role:'independent-reviewer',publicKeyPem:reviewer.publicKey.export({type:'spki',format:'pem'}),revoked:false}];
 const policy={schemaVersion:1,type:'VERIVARO_EXTERNAL_RELEASE_TRUST_V1',
  minimumSequence:4,threshold:2,keys};
 const policyBytes=canonicalReleaseJson(policy);
 const signatures=[owner,reviewer].map((key,i)=>canonicalReleaseJson({
  schemaVersion:1,type:'VERIVARO_ED25519_RELEASE_SIGNATURE_V1',keyId:keys[i].id,
  manifestSha256:releaseSha256(manifestBytes),
  signature:sign(null,releaseSigningPayload(manifestBytes),key.privateKey).toString('base64')
 }));
 return {manifestBytes,policyBytes,pinnedPolicySha256:releaseSha256(policyBytes),
  signatures,expectedPaths:pathList,filesByPath:new Map(files.map(f=>[f.path,f.bytes]))};
}
function rejected(modify){
 const f=fixture();modify(f);
 assert.throws(()=>verifyMigrationReleaseAttestation(f),/release attestation rejected/);
}
test('offline Ed25519 policy pin, two independent signers, exact files and ledger head verify',()=>{
 const result=verifyMigrationReleaseAttestation(fixture());
 assert.equal(result.cryptographicallyVerified,true);
 assert.deepEqual(result.signerRoles,['owner','independent-reviewer']);
 assert.equal(result.fileCount,3);
 assert.equal(result.productionApproved,false);
 assert.equal(result.independentlyCustodied,false);
});
test('an absent reviewer, duplicate signature or unsigned release fails closed',()=>{
 rejected(f=>{f.signatures.pop();});
 rejected(f=>{f.signatures[1]=f.signatures[0];});
 rejected(f=>{f.signatures=[];});
});
test('policy replacement, missing external pin, stale floor, revoked key and single-role signer fail',()=>{
 rejected(f=>{f.pinnedPolicySha256='0'.repeat(64);});
 rejected(f=>{delete f.pinnedPolicySha256;});
 rejected(f=>{const p=JSON.parse(f.policyBytes);p.minimumSequence=7;
  f.policyBytes=canonicalReleaseJson(p);
  f.pinnedPolicySha256=releaseSha256(f.policyBytes);});
 rejected(f=>{const p=JSON.parse(f.policyBytes);p.keys[1].revoked=true;
  f.policyBytes=canonicalReleaseJson(p);f.pinnedPolicySha256=releaseSha256(f.policyBytes);});
 rejected(f=>{const p=JSON.parse(f.policyBytes);p.keys[1].role='owner';
  f.policyBytes=canonicalReleaseJson(p);f.pinnedPolicySha256=releaseSha256(f.policyBytes);});
});
test('modified signed manifest, duplicate member, ambiguous JSON and wrong commit contract reject',()=>{
 rejected(f=>{f.manifestBytes=Buffer.from(f.manifestBytes.toString().replace('"sequence":5','"sequence":6'));});
 rejected(f=>{f.manifestBytes=Buffer.from(f.manifestBytes.toString().replace('"sequence":5','"sequence":5,"sequence":5'));});
 rejected(f=>{f.manifestBytes=Buffer.from(f.manifestBytes.toString().replace('"sourceCommit":"'+ 'a'.repeat(40)+'"', '"sourceCommit":"bad"'));});
 rejected(f=>{f.manifestBytes=Buffer.from(f.manifestBytes.toString().replace('"sequence":5','"sequence" : 5'));});
});
test('tampered source, path omission, extra files and symlink-like manifests reject',()=>{
 rejected(f=>{f.filesByPath.set(files[0].path,Buffer.from('BEGIN;\nDROP TABLE private;\nCOMMIT;'));});
 rejected(f=>{f.filesByPath.delete(files[1].path);});
 rejected(f=>{f.expectedPaths=[files[1].path,files[0].path,files[2].path];});
 rejected(f=>{f.filesByPath.set('db/migrations/0003_other.sql',Buffer.from('SELECT 3;'));});
});
test('invalid signer algorithm, signature truncation and altered signature fail',()=>{
 rejected(f=>{const s=JSON.parse(f.signatures[0]);s.signature=s.signature.slice(0,10);
  f.signatures[0]=canonicalReleaseJson(s);});
 rejected(f=>{const s=JSON.parse(f.signatures[0]);s.signature='A'+s.signature.slice(1);
  f.signatures[0]=canonicalReleaseJson(s);});
 rejected(f=>{const p=JSON.parse(f.policyBytes);
  const {publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  p.keys[0].publicKeyPem=publicKey.export({type:'spki',format:'pem'});
  f.policyBytes=canonicalReleaseJson(p);f.pinnedPolicySha256=releaseSha256(f.policyBytes);});
});
test('draft creation refuses repeated path, bad release number, malformed source digest order',()=>{
 assert.throws(()=>makeMigrationReleaseManifest({sequence:0,sourceCommit:'a'.repeat(40),files}),/release attestation rejected/);
 assert.throws(()=>makeMigrationReleaseManifest({sequence:1,sourceCommit:'bad',files}),/release attestation rejected/);
 assert.throws(()=>makeMigrationReleaseManifest({sequence:1,sourceCommit:'a'.repeat(40),files:[...files,files[0]]}),/release attestation rejected/);
 assert.throws(()=>makeMigrationReleaseManifest({sequence:1,sourceCommit:'a'.repeat(40),files:[files[1],files[0],files[2]]}),/release attestation rejected/);
});
