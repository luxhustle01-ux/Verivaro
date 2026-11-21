import {runSyntheticBuyerDemo} from './src/demo/buyer-evidence-lifecycle.mjs';
const result=await runSyntheticBuyerDemo();
process.stdout.write(JSON.stringify(result,null,2)+'\n');
