import {generateKeyPairSync, createPublicKey, sign, verify, createHash} from 'node:crypto';
import {didKey,issueCredential,verifyCredential} from './credentials.js';

export const canonical = value => {
  if (value === null || ['string', 'boolean'].includes(typeof value)) return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype)
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  throw new Error('Unsupported signed value');
};
export const digest = value => createHash('sha256').update(canonical(value)).digest('hex');
const bytes = (domain, payload) => Buffer.from(`relay-trust/v1/${domain}\n${canonical(payload)}`);
export function newIdentity(name, role) {
  const {publicKey, privateKey} = generateKeyPairSync('ed25519');
  const publicPem = publicKey.export({type:'spki', format:'pem'});
  const id = `urn:relay:${createHash('sha256').update(publicKey.export({type:'spki',format:'der'})).digest('hex')}`;
  return {id,did:didKey(publicPem),name,role,publicKey:publicPem,privateKey:privateKey.export({type:'pkcs8',format:'pem'})};
}
export function signed(domain, payload, key) {
  if(domain==='credential')payload={...payload,credentialProfile:'vc-data-integrity/v2'};
  const envelope={payload, signature:sign(null,bytes(domain,payload),key).toString('base64url')};
  if(domain==='credential')envelope.verifiableCredential=issueCredential(payload,key);
  return envelope;
}
export function authentic(domain, envelope, key) {
  try {
    if (!envelope || !['payload,signature','payload,signature,verifiableCredential'].includes(Object.keys(envelope).sort().join(',')) ||
        typeof envelope.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature)) return false;
    const publicKey = createPublicKey(key);
    return publicKey.asymmetricKeyType === 'ed25519' && verify(null,bytes(domain,envelope.payload),publicKey,Buffer.from(envelope.signature,'base64url')) && (envelope.payload.credentialProfile!=='vc-data-integrity/v2'||!!envelope.verifiableCredential) && (!envelope.verifiableCredential || domain==='credential'&&verifyCredential(envelope.verifiableCredential,envelope.payload,key));
  } catch { return false; }
}
export const publicIdentity = ({privateKey,...identity}) => identity;
