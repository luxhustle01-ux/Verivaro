// Local-only developer/buyer preview; requires a machine with Node 22.16.
// This is deliberately NOT a public deployment or production listener.
import {createBuyerShowcaseServer} from './src/demo/buyer-showcase-server.mjs';
import {once} from 'node:events';
const server=await createBuyerShowcaseServer();
server.listen(0,'127.0.0.1');
await once(server,'listening');
process.stdout.write('Synthetic read-only Verivaro buyer preview: http://127.0.0.1:'+
 server.address().port+'/\n');
process.stdout.write('No external connections or real customer data. Ctrl+C to stop.\n');
