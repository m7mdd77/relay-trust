import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {didKey,didPublicKey,resolveDid,jcs,verifyDocument,issueCredential,verifyCredential} from '../src/credentials.js';
import {newIdentity,signed,authentic} from '../src/crypto.js';
test('W3C eddsa-jcs-2022 published B.3 vector verifies and hashes match',()=>{
 const context=['https://www.w3.org/ns/credentials/v2','https://www.w3.org/ns/credentials/examples/v2'];
 const doc={'@context':context,id:'urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33',type:['VerifiableCredential','AlumniCredential'],name:'Alumni Credential',description:'A minimum viable example of an Alumni Credential.',issuer:'https://vc.example/issuers/5678',validFrom:'2023-01-01T00:00:00Z',credentialSubject:{id:'did:example:abcdefgh',alumniOf:'The School of Examples'}};
 const did='did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2';
 const options={'@context':context,type:'DataIntegrityProof',cryptosuite:'eddsa-jcs-2022',created:'2023-02-24T23:36:38Z',verificationMethod:did+'#'+did.slice(8),proofPurpose:'assertionMethod'};
 assert.equal(createHash('sha256').update(jcs(doc)).digest('hex'),'59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19');
 assert.equal(createHash('sha256').update(jcs(options)).digest('hex'),'66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a097cabe539a1db');
 const secured={...doc,proof:{...options,proofValue:'z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX'}};
 assert.equal(verifyDocument(secured,didPublicKey(did)),true);secured.credentialSubject.alumniOf='Forged';assert.equal(verifyDocument(secured,didPublicKey(did)),false);
});
test('did:key resolves Ed25519 Multikey and rejects other codecs and malformed data',()=>{const i=newIdentity('Issuer','owner');assert.equal(didKey(didPublicKey(i.did)),i.did);const d=resolveDid(i.did);assert.deepEqual(d.assertionMethod,[d.verificationMethod[0].id]);assert.throws(()=>resolveDid('did:key:z1'));assert.throws(()=>resolveDid('did:web:example.org'));});
test('VC proof, claims binding, key, purpose and context tampering fail closed',()=>{const i=newIdentity('Issuer','owner'),other=newIdentity('Other','outsider'),now=Date.now();const p={id:'123',kind:'delegation',subject:'urn:agent:scout',issuer:i.id,notBefore:now-1000,expiresAt:now+10000,maxItems:1};const vc=issueCredential(p,i.privateKey);assert.equal(verifyCredential(vc,p,i.publicKey),true);for(const mutate of [v=>v.credentialSubject.claims.maxItems=99,v=>v.proof.proofPurpose='authentication',v=>v.proof.cryptosuite='made-up',v=>v.proof.created='invalid',v=>v['@context'].reverse()]){const v=structuredClone(vc);mutate(v);assert.equal(verifyCredential(v,p,i.publicKey),false);}assert.equal(verifyCredential(vc,p,other.publicKey),false);const envelope=signed('credential',p,i.privateKey);envelope.verifiableCredential.credentialSubject.claims.maxItems=99;assert.equal(authentic('credential',envelope,i.publicKey),false);});
test('JCS rejects invalid Unicode/nonfinite values and preserves RFC 8785 number rendering',()=>{assert.throws(()=>jcs('\ud800'));assert.throws(()=>jcs(NaN));assert.equal(jcs({z:-0,a:1e30}),'{'+'"a":1e+30,"z":0}');});
test('new credential profile cannot be downgraded by stripping the VC',()=>{const i=newIdentity('Issuer','owner'),now=Date.now();const e=signed('credential',{id:'123',kind:'delegation',subject:'urn:agent:scout',notBefore:now,expiresAt:now+1000},i.privateKey);assert.equal(authentic('credential',e,i.publicKey),true);delete e.verifiableCredential;assert.equal(authentic('credential',e,i.publicKey),false);});
