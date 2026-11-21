// Buyer-safe JSON inventory. Never overwrites a previously generated receipt.
import {open,unlink} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {buildBuyerIpInventory} from './src/security/buyer-ip-inventory.mjs';

if(process.argv.length!==3)throw Error('usage: node buyer-ip-inventory.mjs <new-output.json>');
const target=resolve(process.argv[2]);
const inventory=await buildBuyerIpInventory({sourceRevision:process.env.VV_SOURCE_REVISION??null});
const bytes=Buffer.from(JSON.stringify(inventory,null,2)+'\n');
let h,ok=false;
try{
 h=await open(target,'wx',0o600);
 await h.writeFile(bytes);
 await h.sync();
 ok=true;
}finally{
 await h?.close();
 if(!ok&&h)await unlink(target).catch(()=>{});
}
process.stdout.write(JSON.stringify({file:target,sha256:createHash('sha256').update(bytes).digest('hex'),
 sourceRevision:inventory.sourceRevision,distinctNpmPackages:inventory.distinctNpmPackages,
 legalIpCleared:false,completeSbomVerified:false})+'\n');
