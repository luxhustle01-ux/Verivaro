// End-to-end release signer acceptance rehearsal with disposable, in-memory keys.
// This is never a production release signature or key-provisioning operation.
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateKeyPairSync,sign} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {draftManifest,verifyOffline} from './migration-release-cli.mjs';
import {canonicalReleaseJson,releaseSha256,releaseSigningPayload}
 from '../src/security/migration-release-attestation.mjs';

const fail=msg=>{throw Error('signing acceptance drill failed: '+msg);};
function gitHead(){
 const r=spawnSync('git',['rev-parse','--verify','HEAD'],{encoding:'utf8',timeout:5000});
 if(r.status!==0||!/^[a-f0-9]{40}$/.test(r.stdout.trim()))fail('unverifiable checkout');
 return r.stdout.trim();
}
async function drill(){
 if(process.env.GITHUB_ACTIONS!=='true'||process.env.VV_CI_RELEASE_SIGNING!=='1')
  fail('not the approved ephemeral-key CI fixture');
 const folder=await mkdtemp(join(tmpdir(),'vv-signing-acceptance-'));
 const paths=['manifest.json','policy.json','owner.json','reviewer.json'].map(n=>join(folder,n));
 try{
  const bytes=await draftManifest(7,gitHead());
  const m=JSON.parse(bytes.toString('utf8'));
  if(m.productionApproved!==false||m.files.length<72||m.sequence!==7)
   fail('unsigned source manifest contract');
  const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
  const policy={
   schemaVersion:1,type:'VERIVARO_EXTERNAL_RELEASE_TRUST_V1',minimumSequence:7,
   threshold:2,keys:keys.map((k,i)=>({
    id:i?'fixture-reviewer':'fixture-owner',
    role:i?'independent-reviewer':'owner',
    publicKeyPem:k.publicKey.export({type:'spki',format:'pem'}),revoked:false
   }))
  };
  const policyBytes=canonicalReleaseJson(policy);
  const digest=releaseSha256(policyBytes);
  const envelope=i=>canonicalReleaseJson({
   schemaVersion:1,type:'VERIVARO_ED25519_RELEASE_SIGNATURE_V1',
   keyId:policy.keys[i].id,manifestSha256:releaseSha256(bytes),
   signature:sign(null,releaseSigningPayload(bytes),keys[i].privateKey).toString('base64')
  });
  await Promise.all([
   writeFile(paths[0],bytes,{mode:0o600}),
   writeFile(paths[1],policyBytes,{mode:0o600}),
   writeFile(paths[2],envelope(0),{mode:0o600}),
   writeFile(paths[3],envelope(1),{mode:0o600})
  ]);
  const args={manifestPath:paths[0],policyPath:paths[1],pin:digest,
   sigOwnerPath:paths[2],sigReviewerPath:paths[3]};
  const result=await verifyOffline(args);
  if(!result.cryptographicallyVerified||result.productionApproved!==false||
   result.independentlyCustodied!==false||result.fileCount!==m.files.length)
   fail('ephemeral acceptance result unexpectedly promoted authority');
  for(const [label,override] of [
   ['wrong trust pin',{pin:'f'.repeat(64)}],
   ['duplicate signer',{sigReviewerPath:paths[2]}],
   ['missing external signature',{sigReviewerPath:join(folder,'absent.json')}]
  ]){
   let rejected=false;
   try{await verifyOffline({...args,...override});}catch{rejected=true;}
   if(!rejected)fail(label+' was accepted');
  }
  return {ephemeralKeyFixtureOnly:true,realSourceFilesVerified:m.files.length,
   releaseSequence:m.sequence,twoRoleEd25519Verified:true,trustPinRejected:true,
   duplicateReviewerRejected:true,missingReviewerRejected:true,
   independentlyCustodied:false,productionApproved:false};
 }finally{await rm(folder,{recursive:true,force:true});}
}
if(process.argv[1]&&import.meta.url===new URL('file://'+process.argv[1]).href){
 try{process.stdout.write(JSON.stringify(await drill())+'\n');}
 catch(e){process.stderr.write(e.message+'\n');process.exitCode=1;}
}
