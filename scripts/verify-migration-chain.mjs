import {auditRepositoryMigrationChain} from '../src/security/migration-chain-audit.mjs';
const result=await auditRepositoryMigrationChain();
process.stdout.write(JSON.stringify({
 ...result,proofType:'repository-source-drift-only',
 independentSignoff:false,productionMigrationApproved:false
})+'\n');
