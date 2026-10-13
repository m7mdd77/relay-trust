import test from 'node:test';
import assert from 'node:assert/strict';
import {TrustStore} from '../src/store.js';
import {verifySnapshot} from '../tools/verify-public.js';
test('offline public verifier accepts real snapshot and catches tampered receipt and fingerprint',t=>{
  const s=new TrustStore(':memory:');t.after(()=>s.close());s.execute(s.prepare('allowed').id);
  const snap={format:'relay-public-snapshot/v1',...s.state()};assert.ok(verifySnapshot(snap).valid);
  const changed=structuredClone(snap);changed.receipts[0].payload.resource='SITE-99';assert.equal(verifySnapshot(changed).valid,false);
  const changedKey=structuredClone(snap);changedKey.identities.owner.id=changedKey.identities.lab.id;assert.equal(verifySnapshot(changedKey).valid,false);
});
