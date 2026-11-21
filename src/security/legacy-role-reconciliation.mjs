// Deterministic, fail-closed plan for the 63 immutable G1 SQL migrations.
// Planning/rewriting is NOT permission to execute on a production database.
import {createHash} from 'node:crypto';
import {createExpectedLedger,unwrapTransactionalMigration}
 from '../../scripts/ci-migration-ledger.mjs';

const fail=message=>{throw Error('privileged migration reconciliation rejected: '+message);};
export const LEGACY_ROLE_DECLARATIONS=Object.freeze([
 [4,'verivaro_runtime'],
 [6,'verivaro_identity_service'],[6,'verivaro_recovery_service'],
 [7,'verivaro_recovery_approver'],
 [8,'verivaro_share_gateway'],[8,'verivaro_release_service'],
 [10,'verivaro_recipient_gateway'],
 [11,'verivaro_admission_service'],[11,'verivaro_admission_reconciler'],
 [12,'verivaro_monitor_worker'],[12,'verivaro_incident_operator'],
 [13,'verivaro_monitor_reader'],[14,'verivaro_alert_sender'],
 [15,'verivaro_restore_reviewer'],[16,'verivaro_identity_provisioner'],
 [18,'verivaro_identity_events'],[19,'verivaro_api_admission'],
 [21,'verivaro_evidence_ingestor'],[23,'verivaro_evidence_reader'],
 [24,'verivaro_evidence_auditor'],[31,'verivaro_tenant_operator']
].map(row=>Object.freeze(row)));
export const ROLE_DDL_ATTRIBUTES=
 'NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS';
export const AUDITED_G1_LEDGER_HEAD='7a5dccee57dcdd9b9f7f63074077a2be6db6ac4987d29f62f0259721481ecc55';
const AUDITED_ROLE_NAMES=Object.freeze(LEGACY_ROLE_DECLARATIONS.map(([,name])=>name));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const exactly=(path,i)=>new RegExp('^db/migrations/'+String(i).padStart(4,'0')+'_[a-z0-9_]+\\.sql$').test(path);
const roleLine=name=>'CREATE ROLE '+name+' '+ROLE_DDL_ATTRIBUTES+';';
export function createLegacyReconciliationPlan(sourceRows){
 if(!Array.isArray(sourceRows)||sourceRows.length!==63)
  fail('exactly 63 locked migration source rows required');
 const migrations=[],seenRoles=[];
 for(let i=0;i<sourceRows.length;i++){
  const version=i+1,r=sourceRows[i];
  if(!r||typeof r.path!=='string'||!exactly(r.path,version)||
   !Buffer.isBuffer(r.bytes)||r.bytes.length<1||r.bytes.length>2*1024*1024)
   fail('invalid or unordered locked SQL');
  const source=r.bytes.toString('utf8');
  if(!Buffer.from(source,'utf8').equals(r.bytes))fail('invalid SQL encoding');
  unwrapTransactionalMigration(source);
  const expected=LEGACY_ROLE_DECLARATIONS.filter(x=>x[0]===version).map(x=>x[1]);
  let transformed=source;
  for(const name of expected){
   const target=roleLine(name);
   const matches=transformed.split('\n').filter(line=>line===target);
   if(matches.length!==1)fail('privileged statement absent, duplicated or altered: '+name);
   transformed=transformed.replace(target,'-- independently provisioned role: '+name);
   seenRoles.push(name);
  }
  // The only privileged migrations allowed by this reference plan are the 21
  // exact role declarations, plus the reviewed PG16 trusted pgcrypto install
  // in migration 0003. A new/elevated statement stops the plan.
  if(/^\s*(?:CREATE|ALTER|DROP)\s+ROLE\b/gmi.test(transformed)||
   /^\s*GRANT\s+(?:[a-z_][a-z_0-9]*)\s+TO\s+(?:[a-z_][a-z_0-9]*)\s*(?:;|WITH)/gmi.test(transformed)||
   /\b(?:ALTER\s+SYSTEM|CREATE\s+DATABASE|CREATE\s+TABLESPACE)\b/gi.test(transformed))
   fail('unreviewed global role or system administration statement');
  const extensionLines=transformed.split('\n').filter(line=>
   /^\s*(?:CREATE|ALTER|DROP)\s+EXTENSION\b/i.test(line));
  if(version===3){
   if(extensionLines.length!==1||
    extensionLines[0]!=='CREATE EXTENSION pgcrypto WITH SCHEMA verivaro_private;')
    fail('pgcrypto extension install no longer matches reviewed boundary');
  }else if(extensionLines.length)fail('unreviewed extension statement');
  migrations.push(Object.freeze({version,path:r.path,
   sourceSha256:sha(r.bytes),transformedSha256:sha(Buffer.from(transformed)),
   strippedRoles:Object.freeze(expected),transformedSql:transformed}));
 }
 if(seenRoles.length!==21||new Set(seenRoles).size!==21||
  LEGACY_ROLE_DECLARATIONS.some(([,name])=>!seenRoles.includes(name)))
  fail('role inventory incomplete');
 const ledger=createExpectedLedger(migrations.map(m=>({
  version:m.version,path:m.path,sha256:m.sourceSha256
 })));
 if(ledger.at(-1).entry_hash!==AUDITED_G1_LEDGER_HEAD)
  fail('unexpected immutable G1 ledger baseline: independent review required');
 return Object.freeze({version:1,type:'VERIVARO_P0B_PRIVILEGED_RECONCILIATION',
  migrations:Object.freeze(migrations),serviceRoles:Object.freeze(seenRoles),ledgerHead:ledger.at(-1).entry_hash,
  extensionApprovalRequired:true,privilegedRoleBootstrapRequired:true,
  initialInstallApproved:false,existingInstallBackfillApproved:false,
  independentlySigned:false});
}
export function privilegedBootstrapSql(plan,{ownerRole,executorRole,loginRole}){
 if(!plan||plan.type!=='VERIVARO_P0B_PRIVILEGED_RECONCILIATION'||
  plan.ledgerHead!==AUDITED_G1_LEDGER_HEAD||
  !Array.isArray(plan.migrations)||plan.migrations.length!==63||
  !Array.isArray(plan.serviceRoles)||plan.serviceRoles.length!==AUDITED_ROLE_NAMES.length||
  plan.serviceRoles.some((name,i)=>name!==AUDITED_ROLE_NAMES[i]))
  fail('unverified or forged reconciliation plan');
 for(const v of [ownerRole,executorRole,loginRole])
  if(typeof v!=='string'||!/^vv_ci_reconcile_[a-z_]+$/.test(v))
   fail('only CI disposable role names supported by executable fixture');
 // SQL identifiers derive only from audited constants, not supplied strings.
 const rows=AUDITED_ROLE_NAMES.map(name=>roleLine(name));
 if(new Set(rows).size!==21)fail('role list not unique');
 return ['BEGIN;',...rows,
  'CREATE ROLE '+ownerRole+' '+ROLE_DDL_ATTRIBUTES+';',
  'CREATE ROLE '+executorRole+' '+ROLE_DDL_ATTRIBUTES+';',
  'GRANT '+ownerRole+' TO '+executorRole+' WITH INHERIT FALSE, SET TRUE;',
  // CI LOGIN created by the isolated test harness with a cryptographically
  // random password. This plan does not authorize operational credentials.
  'GRANT '+executorRole+' TO '+loginRole+' WITH INHERIT FALSE, SET TRUE;',
  'COMMIT;',''].join('\n');
}
export function assertExistingInstallReconciliation({
 observedHistory,expectedHistory,roleInventory,approvedExistingInstall=false
}={}){
 if(!Array.isArray(observedHistory)||!Array.isArray(expectedHistory)||
  expectedHistory.length!==63||observedHistory.length!==63||
  expectedHistory.some(v=>typeof v!=='string'||!/^[a-f0-9]{64}$/.test(v))||
  observedHistory.some((v,i)=>v!==expectedHistory[i])||
  !Array.isArray(roleInventory)||roleInventory.length!==21)
  fail('existing deployment cannot be inferred from schema or unverified partial history');
 for(const r of roleInventory){
  if(!r||!LEGACY_ROLE_DECLARATIONS.some(x=>x[1]===r.name)||
   r.login!==false||r.superuser!==false||r.inherit!==false||
   r.createRole!==false||r.createDb!==false||r.replication!==false||
   r.bypassRls!==false||r.unexpectedMembership!==false)
   fail('unsafe existing service role detected');
 }
 if(new Set(roleInventory.map(r=>r.name)).size!==21)
  fail('missing or duplicate existing role');
 if(approvedExistingInstall!==true)
  fail('independent existing-install release review not provided');
 return Object.freeze({historyReconciled:true,roleAttributesReconciled:true,
  independentOperatorApprovalFlagOnly:true,productionApproved:false});
}
