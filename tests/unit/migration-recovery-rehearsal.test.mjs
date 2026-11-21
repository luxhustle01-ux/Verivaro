import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';

const script=new URL('../../scripts/rehearse-migration-recovery.mjs',import.meta.url);
const approved={
 GITHUB_ACTIONS:'true',VV_CI_PG_REHEARSAL:'1',PGHOST:'localhost',
 PGPORT:'5432',PGUSER:'postgres',PGDATABASE:'verivaro_test',PGPASSWORD:'ci-only'
};
function run(overrides){
 const env={PATH:process.env.PATH,...approved,...overrides};
 return spawnSync(process.execPath,[script.pathname],{env,encoding:'utf8',timeout:4000});
}
test('migration rehearsal refuses unapproved database targets before invoking psql',()=>{
 for(const overrides of [
  {GITHUB_ACTIONS:'false'},
  {VV_CI_PG_REHEARSAL:'0'},
  {PGHOST:'remote.example'},
  {PGDATABASE:'customer_db'},
  {PGUSER:'migration_owner'},
  {PGHOSTADDR:'10.0.0.8'},
  {PGSERVICE:'external'},
  {PGOPTIONS:'-c search_path=public'},
  {DATABASE_URL:'postgresql://example.com/production'}
 ]){
  const out=run(overrides);
  assert.equal(out.status,1,JSON.stringify(overrides));
  assert.match(out.stderr,/requires the approved disposable CI database/);
  assert.equal(out.stdout,'');
 }
});
