import {readFileSync} from 'node:fs';
import {createHash,createPublicKey} from 'node:crypto';
import {authentic,digest} from '../src/crypto.js';

export function verifySnapshot(snapshot) {
  const checks=[];const check=(name,pass)=>checks.push({name,pass:!!pass});
  check('public snapshot format',snapshot.format==='relay-public-snapshot/v1');
  const roots=snapshot.identities;
  check('no signing keys',!JSON.stringify(snapshot).includes('-----BEGIN PRIVATE KEY-----')&&!Object.values(roots).some(i=>'privateKey' in i));
  for(const [role,id] of Object.entries(roots)) {
    try{const publicKey=createPublicKey(id.publicKey);check(`${role} key fingerprint`,publicKey.asymmetricKeyType==='ed25519'&&id.id===`urn:relay:${createHash('sha256').update(publicKey.export({type:'spki',format:'der'})).digest('hex')}`);}catch{check(`${role} key fingerprint`,false);}
  }
  for(const [name,env,root] of [['delegation',snapshot.delegation,roots.owner],['attestation',snapshot.attestation,roots.lab]]) {
    check(`${name} signature`,authentic('credential',env,root.publicKey));check(`${name} issuer binding`,env.payload.issuer===root.id);check(`${name} subject binding`,env.payload.subject===roots.scout.id);check(`${name} audience binding`,env.payload.audience===roots.steward.id);
  }
  for(const env of snapshot.receipts) {
    const root=Object.values(roots).find(i=>i.id===env.payload.issuer);check(`receipt ${env.payload.id}`,!!root&&authentic('receipt',env,root.publicKey));
  }
  const hashes=snapshot.attestation.payload.claim.receiptHashes;
  check('attested receipt hashes',new Set(hashes).size===hashes.length && hashes.every(hash=>snapshot.receipts.some(r=>digest(r)===hash && r.payload.issuer===roots.lab.id && r.payload.actor===roots.scout.id)));
  return {valid:checks.every(c=>c.pass),checks};
}
if(process.argv[2]) {
  try{const result=verifySnapshot(JSON.parse(readFileSync(process.argv[2],'utf8')));for(const c of result.checks)console.log(`${c.pass?'PASS':'FAIL'} ${c.name}`);
    console.log('Integrity only: snapshot roots require separate operator authentication; offline data cannot establish current revocation.');
    process.exitCode=result.valid?0:1;
  }catch{console.error('Invalid public snapshot.');process.exitCode=1;}
}
