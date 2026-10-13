import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {TrustStore} from '../src/store.js';
import {canonical,signed,authentic,digest} from '../src/crypto.js';
import {evaluate} from '../src/policy.js';

function fixture(t){let now=1800000000000;const store=new TrustStore(':memory:',()=>now);t.after(()=>store.close());return {store,advance:ms=>now+=ms};}
function context(t){const {store,advance}=fixture(t);const d=store.prepare('allowed');return {store,advance,d,ctx:store.context(d)};}
function resign(ctx,kind,role,patch){const prop={request:'request',delegation:'delegation',attestation:'attestation'}[kind];const payload={...ctx[prop].payload,...patch};ctx[prop]=signed(kind==='request'?'request':'credential',payload,ctx.identities[role].privateKey);if(kind!=='request'){ctx.request.payload[kind+'Hash']=digest(ctx[prop]);ctx.request=signed('request',ctx.request.payload,ctx.identities.scout.privateKey);}}

test('canonical signing is order independent, domain separated, and fails on byte tampering',t=>{
  const {store}=fixture(t),key=store.identities.scout;
  assert.equal(canonical({z:1,a:[true,null]}),canonical({a:[true,null],z:1}));
  const env=signed('request',{a:1,b:2},key.privateKey);
  assert.ok(authentic('request',{...env,payload:{b:2,a:1}},key.publicKey));
  assert.equal(authentic('credential',env,key.publicKey),false);
  assert.equal(authentic('request',{...env,payload:{a:9,b:2}},key.publicKey),false);
  assert.equal(authentic('request',{...env,signature:env.signature.slice(1)},key.publicKey),false);
  assert.equal(authentic('request',{...env,algorithm:'none'},key.publicKey),false);
});
test('valid cross-agent task creates a Steward-signed synthetic receipt',t=>{
  const {store}=fixture(t),d=store.prepare('allowed');assert.ok(d.preflight.allowed);
  assert.equal(new Set(Object.values(store.identities).map(i=>i.id)).size,5);
  const result=store.execute(d.id);assert.equal(result.status,'executed');assert.equal(store.state().tickets,1);
  assert.ok(authentic('receipt',result.receipt,store.identities.steward.publicKey));
  assert.equal(result.receipt.payload.requestHash,digest(d.request));
});
for(const [scenario,code] of [['scope','capability'],['spoof','request_signature'],['tampered','delegation_signature'],['expired','validity'],['audience','audience']])test(`${scenario} fails ${code} with no effect`,t=>{
  const {store}=fixture(t),d=store.prepare(scenario);assert.equal(d.preflight.allowed,false);assert.ok(d.preflight.failed.includes(code));assert.equal(store.execute(d.id).status,'blocked');assert.equal(store.state().tickets,0);
});
test('revocation between approval and execution blocks a valid task',t=>{
  const {store}=fixture(t),d=store.prepare('allowed');assert.ok(d.preflight.allowed);store.manage('revoke');const result=store.execute(d.id);assert.equal(result.status,'blocked');assert.ok(result.evaluation.failed.includes('revocation'));assert.equal(store.state().tickets,0);
});
test('narrowing revokes old grant and new grant has quota one',t=>{
  const {store}=fixture(t),old=store.prepare('allowed');store.manage('narrow');assert.equal(store.execute(old.id).status,'blocked');
  const first=store.prepare('allowed'),second=store.prepare('allowed');assert.ok(second.preflight.allowed);
  assert.equal(store.execute(first.id).status,'executed');const rejected=store.execute(second.id);assert.equal(rejected.status,'blocked');assert.ok(rejected.evaluation.failed.includes('quota'));assert.equal(store.state().tickets,1);
});
test('renewing does not revive a previously prepared request',t=>{
  const {store}=fixture(t),d=store.prepare('allowed');store.manage('grant');assert.equal(store.execute(d.id).status,'blocked');assert.ok(store.prepare('allowed').preflight.allowed);
});
test('replay of completed task returns exact receipt after revocation without new effect',t=>{
  const {store}=fixture(t),d=store.prepare('allowed'),first=store.execute(d.id);store.manage('revoke');const replay=store.execute(d.id);assert.equal(replay.status,'already_executed');assert.deepEqual(first.receipt,replay.receipt);assert.equal(store.state().tickets,1);
});
test('request expiration after preflight is enforced at execution',t=>{
  const {store,advance}=fixture(t),d=store.prepare('allowed');advance(300000);const result=store.execute(d.id);assert.equal(result.status,'blocked');assert.ok(result.evaluation.failed.includes('validity'));
});
test('delegation expiration and future validity fail even when correctly signed',t=>{
  const {ctx}=context(t);resign(ctx,'delegation','owner',{expiresAt:ctx.now});assert.ok(evaluate(ctx).failed.includes('validity'));
  resign(ctx,'delegation','owner',{notBefore:ctx.now+1,expiresAt:ctx.now+5000});assert.ok(evaluate(ctx).failed.includes('validity'));
});
test('expired evidence attestation blocks otherwise fresh trusted task',t=>{
  const {ctx}=context(t);resign(ctx,'attestation','lab',{expiresAt:ctx.now});assert.ok(evaluate(ctx).failed.includes('validity'));
});
test('signed credential with wrong issuer identifier fails issuer binding',t=>{
  const {ctx}=context(t);resign(ctx,'delegation','owner',{issuer:ctx.identities.lab.id});assert.ok(evaluate(ctx).failed.includes('issuer_binding'));
});
test('untrusted issuer key is refused even if payload names the pinned owner',t=>{
  const {ctx}=context(t);resign(ctx,'delegation','outsider',{});assert.ok(evaluate(ctx).failed.includes('delegation_signature'));
});
test('signed credentials cannot be lent to a different subject',t=>{
  const {ctx}=context(t);resign(ctx,'attestation','lab',{subject:ctx.identities.outsider.id});assert.ok(evaluate(ctx).failed.includes('subject_binding'));
});
test('wrong credential audience is refused independent of request audience',t=>{
  const {ctx}=context(t);resign(ctx,'delegation','owner',{audience:ctx.identities.outsider.id});assert.ok(evaluate(ctx).failed.includes('audience'));
});
test('resource boundary rejects another site even with Scout signature',t=>{
  const {ctx}=context(t);resign(ctx,'request','scout',{resource:'SITE-99'});assert.ok(evaluate(ctx).failed.includes('resource'));
});
test('credential substitution fails exact envelope binding',t=>{
  const {ctx}=context(t);const p={...ctx.delegation.payload,id:'another-credential'};ctx.delegation=signed('credential',p,ctx.identities.owner.privateKey);assert.ok(evaluate(ctx).failed.includes('credential_binding'));
});
test('attestation revocation independently blocks execution',t=>{
  const {store,d}=context(t);store.db.prepare('UPDATE credentials SET revoked=1 WHERE id=?').run(d.attestation.payload.id);assert.ok(store.execute(d.id).evaluation.failed.includes('revocation'));
});
test('self-reported 999 jobs cannot replace insufficient trusted evidence',t=>{
  const {ctx}=context(t);resign(ctx,'attestation','lab',{claim:{...ctx.attestation.payload.claim,successfulInspections:0}});assert.ok(evaluate(ctx).failed.includes('evidence'));
});
test('history requires real signed receipts, unique hashes, and matching Scout',t=>{
  const {ctx}=context(t);ctx.history[0].payload.actor=ctx.identities.outsider.id;assert.ok(evaluate(ctx).failed.includes('history_signatures'));
  const repeated=Array(3).fill(ctx.attestation.payload.claim.receiptHashes[1]);resign(ctx,'attestation','lab',{claim:{...ctx.attestation.payload.claim,receiptHashes:repeated}});assert.ok(evaluate(ctx).failed.includes('history_signatures'));
});
test('bad format and malformed envelopes fail closed',t=>{
  const {ctx}=context(t);resign(ctx,'request','scout',{format:'other'});assert.ok(evaluate(ctx).failed.includes('format'));
  ctx.request={payload:null,signature:'nonsense'};assert.equal(evaluate(ctx).allowed,false);
});
test('persistent state retains identities, revocations, decisions, receipts, and replay across restart',()=>{
  const dir=mkdtempSync(join(tmpdir(),'relay-test-')),path=join(dir,'store.sqlite');
  try {let s=new TrustStore(path);const identity=s.state().identities.scout.id,d=s.prepare('allowed'),r=s.execute(d.id);s.manage('revoke');s.close();s=new TrustStore(path);
    assert.equal(s.state().identities.scout.id,identity);assert.ok(s.state().revoked);assert.equal(s.state().tickets,1);assert.deepEqual(s.execute(d.id).receipt,r.receipt);assert.equal(s.prepare('allowed').preflight.allowed,false);s.close();
  }finally{rmSync(dir,{recursive:true,force:true});}
});
test('public profile exports no signing keys',t=>{
  const {store}=fixture(t);const json=JSON.stringify(store.state());assert.equal(json.includes('PRIVATE KEY'),false);assert.equal(json.includes('privateKey'),false);assert.ok(json.includes('PUBLIC KEY'));
});
