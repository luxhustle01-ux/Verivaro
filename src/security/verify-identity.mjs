import { createPublicKey, verify as verifySignature } from 'node:crypto';
import { decodeStrictJson } from './provider-identity.mjs';

// The provider and locally issued identities must reject duplicate JSON member
// names (including escaped aliases) before interpreting any signed claims.
const decode = decodeStrictJson;

export function verifyIdentityToken(token, { publicKey, issuer, audience, now = Math.floor(Date.now()/1000) }) {
  if (typeof token !== 'string' || token.length > 32768) throw new Error('invalid token');
  if (!publicKey || !issuer || !audience) throw new Error('missing verifier configuration');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('invalid compact token');
  const [h,p,s] = parts;
  const header = decode(h);
  const claims = decode(p);
  if (header.alg !== 'RS256' || header.typ !== 'JWT' || Object.keys(header).some(k => !['alg','typ'].includes(k))) throw new Error('unsupported token header');
  const signature = Buffer.from(s, 'base64url');
  if (!s || signature.toString('base64url') !== s) throw new Error('invalid signature encoding');
  const key = publicKey?.type === 'public' ? publicKey : createPublicKey(publicKey);
  if (key.asymmetricKeyType !== 'rsa' || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048 || !verifySignature('RSA-SHA256',Buffer.from(h+'.'+p),key,signature)) {
    throw new Error('invalid token signature');
  }
  if (Object.keys(claims).some(k => !['iss','aud','sub','sid','iat','nbf','exp'].includes(k))) throw new Error('unsupported identity claim');
  if (claims.iss !== issuer || claims.aud !== audience || typeof claims.sub !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(claims.sub)) {
    throw new Error('invalid identity claims');
  }
  if (typeof claims.sid !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(claims.sid)) throw new Error('invalid session claim');
  if (!Number.isSafeInteger(now) || !Number.isSafeInteger(claims.exp) || claims.exp <= now ||
      !Number.isSafeInteger(claims.iat) || claims.iat > now ||
      !Number.isSafeInteger(claims.nbf) || claims.nbf > now) throw new Error('token outside validity window');
  if (claims.exp - claims.iat > 3600 || claims.exp <= claims.iat) throw new Error('token lifetime exceeds policy');
  return Object.freeze({ actorId: claims.sub.toLowerCase(), sessionId: claims.sid.toLowerCase(), issuer: claims.iss, audience: claims.aud, expiresAt: claims.exp });
}
