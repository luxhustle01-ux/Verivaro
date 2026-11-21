// G1 reference-only authority public-key schedule.
// The policy must originate from an independently administered, rollback-
// resistant channel. This module does not fetch, sign, rotate or revoke keys.
import {createPublicKey,createHash} from 'node:crypto';

const schedules=new WeakMap();
const ID=/^[a-f0-9]{64}$/;
const lastSafe=Number.MAX_SAFE_INTEGER-3;
const fail=()=>{throw Error('floor authority key schedule rejected');};
const exact=(v,keys)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&
 Object.keys(v).sort().join(',')===keys.slice().sort().join(',');
const serial=n=>Number.isSafeInteger(n)&&n>=0&&n<=lastSafe;
const fingerprint=publicKey=>createHash('sha256')
 .update(publicKey.export({type:'spki',format:'der'})).digest('hex');
const asPublicKey=input=>{
 if(input?.type!=='public'&&
  !(typeof input==='string'&&input.startsWith('-----BEGIN PUBLIC KEY-----')))fail();
 let key;
 try{key=input?.type==='public'?input:createPublicKey(input);}catch{fail();}
 if(key.type!=='public'||key.asymmetricKeyType!=='ed25519')fail();
 return key;
};

export function recoveryFloorAuthorityKeyId(input){
 return fingerprint(asPublicKey(input));
}

// Each floor serial maps to exactly one signer; key epochs are contiguous,
// never overlapping, and the final epoch must remain explicitly open-ended.
// Key reuse across epochs is disallowed. Rotation policy is not inferred from
// a received signature, network response, or attacker-supplied key ID.
export function createTrustedRecoveryFloorAuthorityKeySchedule({epochs}={}){
 if(!Array.isArray(epochs)||epochs.length<1||epochs.length>16)fail();
 let expected=0,open=false;
 const ids=new Set(),privateEntries=[],publicEntries=[];
 for(const e of epochs){
  if(!exact(e,['firstSerial','lastSerial','keyId','publicKey'])||
   !serial(e.firstSerial)||e.firstSerial!==expected||
   !(e.lastSerial===null||serial(e.lastSerial)&&e.lastSerial>=e.firstSerial)||
   typeof e.keyId!=='string'||!ID.test(e.keyId)||open)fail();
  const key=asPublicKey(e.publicKey);
  if(fingerprint(key)!==e.keyId||ids.has(e.keyId))fail();
  ids.add(e.keyId);
  privateEntries.push({firstSerial:e.firstSerial,lastSerial:e.lastSerial,key});
  publicEntries.push(Object.freeze({
   firstSerial:e.firstSerial,lastSerial:e.lastSerial,keyId:e.keyId
  }));
  if(e.lastSerial===null)open=true;
  else expected=e.lastSerial+1;
 }
 if(!open)fail();
 const result=Object.freeze({
  kind:'VERIVARO_G1_REFERENCE_AUTHORITY_KEY_EPOCHS',
  epochs:Object.freeze(publicEntries)
 });
 schedules.set(result,Object.freeze(privateEntries.map(x=>Object.freeze(x))));
 return result;
}
export function resolveTrustedRecoveryFloorAuthorityPublicKey(schedule,headSerial){
 if(!serial(headSerial))fail();
 const entries=schedules.get(schedule);
 if(!entries)fail();
 for(const e of entries)
  if(e.firstSerial<=headSerial&&(e.lastSerial===null||headSerial<=e.lastSerial))
   return e.key;
 fail();
}
