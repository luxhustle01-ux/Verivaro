import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';
const root=process.cwd();
const file=path=>resolve(root,path);
const manifest=JSON.parse(readFileSync(file('docs/engineering/G1_BUYER_EVIDENCE_MANIFEST_20261121.json'),'utf8'));
const statuses=new Set(['PARTIAL_CI','REFERENCE_ONLY','NOT_VERIFIED','NOT_CLEARED','NOT_VALIDATED','INDEPENDENTLY_VERIFIED']);
test('buyer evidence register uses an exact, explicit, non-certified release decision',()=>{
 assert.equal(manifest.schemaVersion,1);
 assert.equal(manifest.productReleaseApproved,false);
 assert.equal(manifest.productionSecurityCertified,false);
 assert.equal(manifest.commercialDemandValidated,false);
 assert.equal(manifest.approvedForAutomaticRecovery,false);
 assert.match(manifest.evidenceClass,/synthetic-CI/);
 assert.equal(manifest.subject,'Verivaro engineering review branch; PR #4');
});
test('every buyer-readiness gate has a unique identifier, grounded source and unresolved justification',()=>{
 assert.ok(manifest.states.length>=8);
 const ids=new Set();
 for(const gate of manifest.states){
  assert.match(gate.id,/^[A-Z][A-Z0-9_]+$/);
  assert.ok(!ids.has(gate.id));ids.add(gate.id);
  assert.ok(statuses.has(gate.status));
  assert.ok(Array.isArray(gate.sources)&&gate.sources.length>0);
  assert.ok(typeof gate.blocker==='string'&&gate.blocker.length>=35);
  for(const path of gate.sources){
   assert.match(path,/^[\w.][\w./-]+$/);
   assert.ok(!path.includes('..'));
   assert.ok(existsSync(file(path)), 'Missing buyer evidence path: '+path);
  }
 }
});
test('P0-D buyer handover claims only scoped historical CI, never production clearance',()=>{
 const gate=manifest.states.find(x=>x.id==='G1_P0D_HANDOVER');
 assert.ok(gate,'Missing G1 handover gate');
 assert.equal(gate.status,'PARTIAL_CI');
 for(const name of [
  'tests/unit/buyer-portable-bundle.test.mjs',
  'tests/browser/offline-buyer-browser.test.mjs',
  'tests/integration/live-requirement-graph.test.mjs',
  'docs/engineering/G1_P0D_HANDOVER_OFFLINE_GATE_20261121.md',
  '.github/workflows/buyer-bundle.yml'
 ]){
  assert.ok(gate.sources.includes(name),'Missing P0-D evidence path '+name);
 }
 assert.match(gate.blocker,/86b9977f|Requalification is required/i);
 assert.equal(manifest.productReleaseApproved,false);
 assert.equal(manifest.commercialDemandValidated,false);
});

test('IP and license inventory remain explicitly NOT_CLEARED',()=>{
 const gate=manifest.states.find(x=>x.id==='BUYER_IP');
 assert.equal(gate.status,'NOT_CLEARED');
 assert.ok(gate.sources.includes('src/security/buyer-ip-inventory.mjs'));
 assert.ok(gate.sources.includes('tests/unit/buyer-ip-inventory.test.mjs'));
 assert.ok(gate.sources.includes('docs/engineering/G1_P0E_IP_DUE_DILIGENCE_20261121.md'));
 assert.match(gate.blocker,/legal|licence|ownership|trademark/i);
});
test('P0-A signer rotation is reference-only and never implies independent custody',()=>{
 const gate=manifest.states.find(x=>x.id==='G1_WITNESS');
 assert.equal(gate.status,'REFERENCE_ONLY');
 assert.ok(gate.sources.includes('src/security/provider-witness-authority-key-schedule.mjs'));
 assert.ok(gate.sources.includes('tests/unit/provider-witness-authority-key-schedule.test.mjs'));
 assert.ok(gate.sources.includes('docs/engineering/G1_REVIEW_FLOOR_AUTHORITY_REFERENCE_20261121.md'));
 assert.match(gate.blocker,/independently administered governance signer|atomic authority-side revocation\+CAS/i);
 for(const p of [
  'src/security/provider-witness-authority-trust-policy.mjs',
  'tests/unit/provider-witness-authority-trust-policy.test.mjs',
  'docs/engineering/G1_P0A_REMOTE_AUTHORITY_CONTRACT_20261121.md'
 ])assert.ok(gate.sources.includes(p),'Missing reference trust policy evidence '+p);
 assert.match(gate.blocker,/atomic authority-side revocation\+CAS/i);
 assert.equal(manifest.productionSecurityCertified,false);
 assert.equal(manifest.approvedForAutomaticRecovery,false);
});

test('P0-A buyer contract lists all unsupported production trust requirements',()=>{
 const contract=JSON.parse(readFileSync(file(
  'docs/engineering/G1_P0A_BUYER_ACCEPTANCE_REGISTER_20261121.json'),'utf8'));
 assert.equal(contract.schemaVersion,1);
 assert.equal(contract.productReleaseApproved,false);
 assert.equal(contract.productionAuthorityDeployed,false);
 assert.equal(contract.independentCustodyProven,false);
 assert.equal(contract.distributedCASProven,false);
 assert.equal(contract.automaticRecoveryPermitted,false);
 assert.equal(contract.requirements.length,8);
 for(const requirement of contract.requirements){
  assert.match(requirement.id,/^P0A-0[1-8]$/);
  assert.equal(requirement.status,'NOT_VERIFIED');
  assert.ok(requirement.externalProof.length>45);
 }
 for(const source of contract.auditedReferenceSource){
  assert.ok(existsSync(file(source)), 'Missing P0-A source '+source);
 }
 const gate=manifest.states.find(x=>x.id==='G1_WITNESS');
 assert.equal(gate.status,'REFERENCE_ONLY');
 for(const name of [
  'src/security/provider-witness-reference-atomic-floor-model.mjs',
  'tests/unit/provider-witness-reference-atomic-floor-model.test.mjs',
  'docs/engineering/G1_P0A_BUYER_ACCEPTANCE_REGISTER_20261121.json'
 ])assert.ok(gate.sources.includes(name),'Missing P0-A reference evidence '+name);
});

test('P0-B tenancy gate includes exact migration provenance while production stays blocked',()=>{
 const gate=manifest.states.find(x=>x.id==='G1_TENANCY');
 assert.equal(gate.status,'PARTIAL_CI');
 for(const source of [
  'db/migration-lock.json',
  'src/security/migration-chain-audit.mjs',
  'scripts/verify-migration-chain.mjs',
  'tests/unit/migration-chain-audit.test.mjs',
  'docs/engineering/G1_P0B_MIGRATION_CHAIN_20261121.md',
  'scripts/ci-migration-ledger.mjs',
  'scripts/rehearse-real-migration-restart.mjs',
  'tests/unit/ci-migration-ledger.test.mjs',
  'docs/engineering/G1_P0B_ACTUAL_MIGRATION_LEDGER_20261121.md',
  'db/security/production-migration-roles.sql',
  'db/tests/least_privilege_migrator.sql',
  'src/security/migration-role-policy.mjs',
  'src/security/migration-release-attestation.mjs',
  'scripts/migration-release-cli.mjs',
  'tests/unit/migration-release-attestation.test.mjs',
  'tests/unit/migration-role-policy.test.mjs',
  'docs/engineering/G1_PRODUCTION_MIGRATION_SIGNING_CONTRACT_20261121.md',
  'src/security/legacy-role-reconciliation.mjs',
  'scripts/rehearse-privileged-migration-reconciliation.mjs',
  'scripts/rehearse-migration-signing-acceptance.mjs',
  'db/security/privileged-service-role-bootstrap.sql',
  'db/security/verify-installed-migration-state.sql',
  'docs/engineering/G1_INDEPENDENT_SIGNING_ACCEPTANCE_20261121.json'
 ])assert.ok(gate.sources.includes(source),'Missing P0-B source '+source);
 assert.match(gate.blocker,/actual external owner and reviewer signatures/i);
 assert.match(gate.blocker,/production migrator identity/i);
 assert.match(gate.blocker,/production recovery witness/i);
 assert.match(gate.blocker,/release approval denied/i);
 const workflow=readFileSync(file('.github/workflows/postgres-g1.yml'),'utf8');
 const orderedCommands=[
  'node scripts/verify-migration-chain.mjs',
  'node scripts/ci-migration-ledger.mjs init',
  'node scripts/rehearse-real-migration-restart.mjs',
  'node scripts/ci-migration-ledger.mjs apply db/migrations/0001_tenant_foundation.sql',
  'node scripts/ci-migration-ledger.mjs apply db/migrations/0063_ocr_transcription_corrections.sql',
  'node scripts/ci-migration-ledger.mjs verify',
  'psql -X -v ON_ERROR_STOP=1 -f db/tests/full_security_gate.sql'
 ];
 let previous=-1;
 for(const command of orderedCommands){
  const index=workflow.indexOf(command);
  assert.ok(index>previous,'Missing or misplaced CI migration command '+command);
  previous=index;
 }
 assert.equal(manifest.productReleaseApproved,false);
});

test('production, sale and automated recovery claims are blocked while unresolved gates remain',()=>{
 const unresolved=manifest.states.filter(x=>x.status!=='INDEPENDENTLY_VERIFIED');
 assert.ok(unresolved.length>0);
 if(unresolved.length){
  assert.equal(manifest.productReleaseApproved,false);
  assert.equal(manifest.productionSecurityCertified,false);
  assert.equal(manifest.commercialDemandValidated,false);
  assert.equal(manifest.approvedForAutomaticRecovery,false);
 }
});
test('release-facing README and status link the audited evidence register and accurate cautions',()=>{
 const readme=readFileSync(file('README.md'),'utf8');
 const status=readFileSync(file('docs/engineering/STATUS.md'),'utf8');
 const audit=readFileSync(file('docs/engineering/G1_PRODUCTION_TRUST_BOUNDARY_BUYER_AUDIT_20261121.md'),'utf8');
 assert.match(readme,/G1_BUYER_EVIDENCE_MANIFEST_20261121\.json/);
 assert.match(readme,/not a production-ready or sale-validated application/i);
 assert.match(status,/Release status: NOT APPROVED/);
 assert.match(audit,/no independently evidenced demand or valuation range/i);
});
test('maximum recovery capacity CI includes the active unmerged audit branch',()=>{
 const workflow=readFileSync(file('.github/workflows/recovery-capacity.yml'),'utf8');
 assert.match(workflow,/audit\/g1-restore-catalog-verification-20261121/);
 assert.match(workflow,/matrix:\s*\n\s*capacity:\s*\[database, evidence\]/);
 assert.match(workflow,/tests\/stress\/maximum-recovery\.test\.mjs/);
});
