import {authentic, digest} from './crypto.js';

// Trusted roots and agent keys come from the local registry, never from a claim.
export function evaluate({request, delegation, attestation, identities, revoked, history = [], used = 0, now = Date.now()}) {
  const checks=[];
  const check=(code,pass,detail)=>checks.push({code,pass:!!pass,detail});
  const r=request?.payload, d=delegation?.payload, a=attestation?.payload;
  const scout=identities.scout, steward=identities.steward;
  check('request_signature',authentic('request',request,scout.publicKey),'Requester must prove possession of Scout’s registered Ed25519 key.');
  check('delegation_signature',authentic('credential',delegation,identities.owner.publicKey),'Authority must be signed by the pinned Workshop Owner.');
  check('attestation_signature',authentic('credential',attestation,identities.lab.publicKey),'Evidence must be signed by the pinned Evidence Lab.');
  check('format',d?.format==='relay-credential/v1' && a?.format==='relay-credential/v1' && r?.format==='relay-request/v1' && d?.kind==='delegation' && a?.kind==='attestation','Only the versioned local credential and request formats are accepted.');
  check('issuer_binding',d?.issuer===identities.owner.id && a?.issuer===identities.lab.id,'Both issuer identifiers must match their pinned signing keys.');
  check('subject_binding',r?.from===scout.id && d?.subject===r?.from && a?.subject===r?.from,'Request and both credentials must bind the same registered Scout.');
  check('audience',r?.to===steward.id && d?.audience===steward.id && a?.audience===steward.id,'Authority and evidence are usable only by Patch Steward.');
  check('credential_binding',r?.delegationId===d?.id && r?.attestationId===a?.id && r?.delegationHash===digest(delegation ?? null) && r?.attestationHash===digest(attestation ?? null),'The signed request commits to these exact credential envelopes.');
  check('validity',[r,d,a].every(p=>Number.isSafeInteger(p?.notBefore) && Number.isSafeInteger(p?.expiresAt) && p.notBefore<=now && now<p.expiresAt && p.notBefore<p.expiresAt),'Request, authority, and evidence must be active and unexpired.');
  check('revocation',!revoked.has(d?.id) && !revoked.has(a?.id),'Live revocation state is checked again at execution.');
  check('capability',r?.action==='ticket.create' && d?.capabilities?.length===1 && d.capabilities[0]==='ticket.create','Only creating a synthetic repair ticket is delegated.');
  check('resource',r?.resource==='SITE-17' && d?.resources?.length===1 && d.resources[0]==='SITE-17','The request must stay inside the delegated SITE-17 resource.');
  check('evidence',a?.claim?.type==='sandbox.inspection' && Number.isSafeInteger(a.claim.successfulInspections) && a.claim.successfulInspections>=3 && a.claim.environment==='synthetic' && Array.isArray(a.claim.receiptHashes) && a.claim.receiptHashes.length>=3,'At least three issuer-attested synthetic inspections are required; self-reported reputation is ignored.');
  const hashes=a?.claim?.receiptHashes;
  check('history_signatures',Array.isArray(hashes) && new Set(hashes).size===hashes.length && hashes.length===a?.claim?.successfulInspections && hashes.every(hash=>history.some(env=>digest(env)===hash && env.payload.issuer===identities.lab.id && env.payload.actor===scout.id && env.payload.action==='sandbox.inspect' && env.payload.resource==='SITE-17' && env.payload.synthetic===true && authentic('receipt',env,identities.lab.publicKey))),'Each distinct attested inspection hash must resolve to an authentic lab-signed receipt for this Scout.');
  check('quota',Number.isSafeInteger(d?.maxItems) && d.maxItems>0 && d.maxItems<=3 && used<d.maxItems,'Successful executions cannot exceed this grant’s ticket quota.');
  return {allowed:checks.every(c=>c.pass),checks,failed:checks.filter(c=>!c.pass).map(c=>c.code),evaluatedAt:now};
}
