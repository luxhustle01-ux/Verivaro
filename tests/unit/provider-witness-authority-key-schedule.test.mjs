import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {
 recoveryFloorAuthorityKeyId,createTrustedRecoveryFloorAuthorityKeySchedule,
 resolveTrustedRecoveryFloorAuthorityPublicKey
} from '../../src/security/provider-witness-authority-key-schedule.mjs';
import {
 createUnsignedRecoveryFloorAuthorityStatement,canonicalRecoveryFloorAuthorityStatement,
 verifySignedRecoveryFloorAuthority
} from '../../src/security/provider-witness-recovery-floor-publication.mjs';

const keys=()=>generateKeyPairSync('ed25519');
const keyId=k=>createHash('sha256').update(k.publicKey.export({type:'spki',format:'der'})).digest('hex');
const scope={issuer:'https://issuer.example.invalid',audience:'verivaro-internal'};
const nonce='A'.repeat(43),now='2026-11-21T04:00:00.000Z';
function fixture(){
 const old=keys(),next=keys();
 const schedule=createTrustedRecoveryFloorAuthorityKeySchedule({epochs:[
  {firstSerial:0,lastSerial:6,keyId:keyId(old),publicKey:old.publicKey},
  {firstSerial:7,lastSerial:null,keyId:keyId(next),publicKey:next.publicKey}
 ]});
 const receipt=(serial,who,override={})=>{
  const statement=createUnsignedRecoveryFloorAuthorityStatement({
   ...scope,serial,headHash:'f'.repeat(64),requestNonce:nonce,
   issuedAt:now,expiresAt:'2026-11-21T04:00:10.000Z',...override
  });
  const signature=sign(null,canonicalRecoveryFloorAuthorityStatement(statement),who.privateKey).toString('base64url');
  return {statement,signature};
 };
 const verify=e=>verifySignedRecoveryFloorAuthority(e,{
  ...scope,trustedAuthorityKeySchedule:schedule,
  expectedRequestNonce:nonce,now
 });
 return {old,next,schedule,receipt,verify};
}
test('explicit verified key fingerprints bind every serial to exactly one signer',()=>{
 const f=fixture();
 assert.equal(f.schedule.epochs.length,2);
 assert.equal(f.schedule.epochs[0].lastSerial,6);
 assert.equal(f.schedule.epochs[1].firstSerial,7);
 assert.equal(recoveryFloorAuthorityKeyId(f.old.publicKey),keyId(f.old));
 assert.equal(resolveTrustedRecoveryFloorAuthorityPublicKey(f.schedule,6),f.old.publicKey);
 assert.equal(resolveTrustedRecoveryFloorAuthorityPublicKey(f.schedule,7),f.next.publicKey);
 assert.deepEqual(f.verify(f.receipt(6,f.old)),{serial:6,headHash:'f'.repeat(64)});
 assert.deepEqual(f.verify(f.receipt(7,f.next)),{serial:7,headHash:'f'.repeat(64)});
 assert.throws(()=>f.verify(f.receipt(7,f.old)),/rejected/);
 assert.throws(()=>f.verify(f.receipt(6,f.next)),/rejected/);
});
test('rejects key schedule gaps, overlaps, reversed epochs, duplicate keys and false fingerprints',()=>{
 const a=keys(),b=keys(),x=id=>({firstSerial:0,lastSerial:6,keyId:keyId(a),publicKey:a.publicKey});
 const p=firstSerial=>({firstSerial,lastSerial:null,keyId:keyId(b),publicKey:b.publicKey});
 for(const epochs of [
  [p(1)],
  [x(),p(6)],
  [x(),p(8)],
  [p(0),x()],
  [x()],
  [x(),{...p(7),keyId:keyId(a),publicKey:a.publicKey}],
  [{...x(),keyId:'0'.repeat(64)},p(7)],
  [x(),{...p(7),lastSerial:6}],
  [x(),{...p(7),firstSerial:'7'}],
  [x(),{...p(7),unexpected:true}]
 ])assert.throws(()=>createTrustedRecoveryFloorAuthorityKeySchedule({epochs}),/rejected/);
 assert.throws(()=>resolveTrustedRecoveryFloorAuthorityPublicKey({epochs:[]},7),/rejected/);
 assert.throws(()=>recoveryFloorAuthorityKeyId(a.privateKey),/rejected/);
 assert.throws(()=>recoveryFloorAuthorityKeyId(a.privateKey.export({type:'pkcs8',format:'pem'})),/rejected/);
 assert.throws(()=>createTrustedRecoveryFloorAuthorityKeySchedule({epochs:[
  {...p(0),publicKey:b.privateKey.export({type:'pkcs8',format:'pem'})}
 ]}),/rejected/);
});
test('signature cannot opt into an unrelated or legacy key when a rotation policy is pinned',()=>{
 const f=fixture(),oldReceipt=f.receipt(6,f.old),newReceipt=f.receipt(7,f.next);
 assert.throws(()=>verifySignedRecoveryFloorAuthority(newReceipt,{
  ...scope,trustedAuthorityKeySchedule:f.schedule,
  trustedAuthorityKey:f.next.publicKey,expectedRequestNonce:nonce,now
 }),/rejected/);
 assert.throws(()=>verifySignedRecoveryFloorAuthority(oldReceipt,{
  ...scope,trustedAuthorityKeySchedule:{epochs:f.schedule.epochs},
  expectedRequestNonce:nonce,now
 }),/rejected/);
 assert.throws(()=>f.verify(f.receipt(7,f.next,{requestNonce:'B'.repeat(43)})),/rejected/);
 assert.throws(()=>f.verify(f.receipt(7,f.next,{issuedAt:'2026-11-20T04:00:00.000Z'})),/rejected/);
});
