// Explicit local artifact creation only. No publish, hosting or network calls.
import {writeFile} from 'node:fs/promises';
import {createPortableBuyerBundle,verifyPortableBuyerBundle} from './src/demo/buyer-portable-bundle.mjs';
const target=process.argv[2];
if(process.argv.length!==3||!target||!target.endsWith('.zip'))
 throw Error('Usage: node --experimental-strip-types buyer-bundle.mjs <new-output.zip>');
const sourceRevision=process.env.VV_SOURCE_REVISION??null;
const bundle=await createPortableBuyerBundle({sourceRevision});
try{
 verifyPortableBuyerBundle(bundle.archive,{expectedArchiveSha256:bundle.archiveSha256,expectedSourceRevision:sourceRevision});
 await writeFile(target,bundle.archive,{flag:'wx',mode:0o600});
 process.stdout.write(JSON.stringify({
  file:target,sourceRevision:bundle.sourceRevision,archiveSha256:bundle.archiveSha256,
  manifestSha256:bundle.manifestSha256,fileCount:bundle.fileCount,
  integrityVerified:true,authenticityVerified:false,
  dataClass:'SYNTHETIC_ONLY',releaseApproved:false
 },null,2)+'\n');
}finally{bundle.archive.fill(0);}
