import {open,lstat} from 'node:fs/promises';
import {constants} from 'node:fs';
import {isAbsolute,join,parse,sep} from 'node:path';
import {isIP} from 'node:net';
import {X509Certificate} from 'node:crypto';
import {validateServiceIdentity} from './service-login.mjs';
const name=/^[a-z][a-z0-9_]{0,62}$/;
// Path ancestry must not redirect a credential lookup through a symlink or
// another user's writable directory. Root-owned sticky /tmp is permitted for
// explicitly private CI fixtures: the following child must still be owner-only.
// This is startup validation, not a substitute for protected mounts and OS
// isolation from a malicious process running with the same UID.
async function verifyCredentialAncestry(path){
 const root=parse(path).root,parts=path.slice(root.length).split(sep);
 if(!root||parts.some(p=>!p||p==='.'||p==='..'))throw Error('unsafe credential path');
 const directories=[root];let next=root;
 for(const piece of parts.slice(0,-1)){next=join(next,piece);directories.push(next);}
 for(const location of directories){
  const s=await lstat(location),mode=s.mode&0o7777;
  if(!s.isDirectory()||(typeof process.getuid==='function'&&s.uid!==0&&s.uid!==process.getuid()))
   throw Error('unsafe credential ancestor');
  const rootSticky=s.uid===0&&(mode&0o1000)!==0&&(mode&0o002)!==0;
  if((mode&0o022)!==0&&!rootSticky)throw Error('writable credential ancestor');
 }
}
export async function readPrivate(path,max){
 if(typeof path!=='string'||!isAbsolute(path))throw Error('absolute credential path required');
 await verifyCredentialAncestry(path);
 const f=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const s=await f.stat();
  if(!s.isFile()||(s.mode&0o077)!==0||s.size<1||s.size>max||(typeof process.getuid==='function'&&s.uid!==process.getuid()))throw Error('unsafe credential file');
  const data=Buffer.alloc(s.size);let offset=0;
  while(offset<data.length){const r=await f.read(data,offset,data.length-offset,offset);if(!r.bytesRead)throw Error('truncated credential');offset+=r.bytesRead;}
  const after=await f.stat(),current=await lstat(path);
  if(after.size!==s.size||after.mtimeMs!==s.mtimeMs||after.ctimeMs!==s.ctimeMs||
     after.ino!==s.ino||after.dev!==s.dev||after.mode!==s.mode||
     !current.isFile()||current.ino!==s.ino||current.dev!==s.dev){
   data.fill(0);throw Error('changed credential file');
  }
  return data;
 }finally{await f.close();}
}
const loopback=h=>h==='127.0.0.1'||h==='::1';
const dns=h=>typeof h==='string'&&h.length<=253&&h.split('.').every(s=>/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(s));
export async function loadServicePoolConfig({env=process.env,role,max=2}){
 const {PGHOST:host,PGUSER:user,PGDATABASE:database}=env;
 validateServiceIdentity(role,user);
 if(typeof user!=='string'||!name.test(database??'')||typeof host!=='string'||(!loopback(host)&&(!dns(host)||isIP(host)))||
 !Number.isInteger(max)||max<1||max>8||['PGPASSWORD','PGOPTIONS','PGSERVICE','PGSERVICEFILE','PGSSLMODE','PGSSLROOTCERT','PGSSLCERT','PGSSLKEY','PGPASSFILE','DATABASE_URL','NODE_TLS_REJECT_UNAUTHORIZED'].some(k=>env[k]!==undefined))throw Error('unsafe service database configuration');
 const port=Number(env.PGPORT??5432);if(!Number.isInteger(port)||port<1||port>65535)throw Error('invalid database port');
 const local=env.VV_ALLOW_LOCAL_PLAINTEXT==='1';
 if(env.VV_ALLOW_LOCAL_PLAINTEXT!==undefined&&!local)throw Error('invalid plaintext policy');
 if(local&&(!loopback(host)||database!=='verivaro_test'||env.VV_LIVE_TEST!=='1'||env.VV_DB_CA_FILE!==undefined))throw Error('plaintext permitted only for disposable loopback CI test');
 let ssl;
 if(local)ssl=false;
 else{
  if(isIP(host)||!dns(host))throw Error('TLS requires configured DNS certificate name');
  const ca=await readPrivate(env.VV_DB_CA_FILE,65536);
  try{
   const pem=ca.toString('utf8');
   // Require a nonempty, valid PEM certificate bundle.
   const certs=pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
   if(!certs||certs.length>16||pem.replace(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g,'').trim())throw Error('invalid database CA');
   for(const cert of certs)new X509Certificate(cert);
   ssl={ca:pem,rejectUnauthorized:true,servername:host,minVersion:'TLSv1.2'};
  }finally{ca.fill(0);}
 }
 const data=await readPrivate(env.VV_DB_PASSWORD_FILE,1024);
 let password;
 try{
  password=data.toString('utf8').replace(/\r?\n$/,'');
  if(password.length<32||password.length>256||!/^[\x21-\x7e]+$/.test(password))throw Error('invalid service password');
 }finally{data.fill(0);}
 return {host,port,user,database,password,ssl,max,connectionTimeoutMillis:3000,idleTimeoutMillis:5000,statement_timeout:5000,query_timeout:6000,application_name:'vv-'+role};
}
