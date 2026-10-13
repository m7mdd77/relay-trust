import {randomUUID,randomBytes} from 'node:crypto';
import {newIdentity,signed,digest,publicIdentity} from './crypto.js';
import {evaluate} from './policy.js';
export class Sandbox {
  constructor(data,clock=()=>Date.now()){this.data=data;this.clock=clock;}
  static create(clock=()=>Date.now()) {
    const s=new Sandbox({identities:{},credentials:{},delegationId:null,attestationId:null,revoked:[],decisions:{},receipts:[],events:[],token:randomBytes(32).toString('hex'),rate:{window:0,count:0}},clock);
    for(const [role,name] of Object.entries({owner:'Workshop Owner',lab:'Evidence Lab',scout:'Scout / inspection agent',steward:'Patch Steward / receiving agent',outsider:'Mirror / spoofing actor'}))s.data.identities[role]=newIdentity(name,role);
    const now=clock(),hashes=[];
    for(let i=0;i<3;i++){
      const payload={id:randomUUID(),actor:s.data.identities.scout.id,issuer:s.data.identities.lab.id,action:'sandbox.inspect',resource:'SITE-17',synthetic:true,result:'Broken destination reproduced',at:now-(3-i)*60000};
      const r=signed('receipt',payload,s.data.identities.lab.privateKey);s.data.receipts.push(r);hashes.push(digest(r));
    }
    const a=s.add({format:'relay-credential/v1',id:randomUUID(),kind:'attestation',issuer:s.data.identities.lab.id,subject:s.data.identities.scout.id,audience:s.data.identities.steward.id,notBefore:now-1000,expiresAt:now+86400000,claim:{type:'sandbox.inspection',successfulInspections:3,environment:'synthetic',receiptHashes:hashes}},'lab');
    s.data.attestationId=a.payload.id;s.issueGrant(3);s.event('identity.created','Fresh isolated sandbox; five distinct keys and three synthetic inspection receipts.');return s;
  }
  event(type,detail){this.data.events.push({seq:(this.data.events.at(-1)?.seq||0)+1,type,detail,at:this.clock()});this.data.events=this.data.events.slice(-40);}
  add(payload,role){const e=signed('credential',payload,this.data.identities[role].privateKey);this.data.credentials[payload.id]=e;return e;}
  issueGrant(maxItems){const now=this.clock(),i=this.data.identities;const d=this.add({format:'relay-credential/v1',id:randomUUID(),kind:'delegation',issuer:i.owner.id,subject:i.scout.id,audience:i.steward.id,notBefore:now-1000,expiresAt:now+86400000,capabilities:['ticket.create'],resources:['SITE-17'],maxItems},'owner');this.data.delegationId=d.payload.id;return d;}
  manage(mode){
    const old=this.data.credentials[this.data.delegationId];
    if(mode==='narrow'&&old.payload.maxItems<=1)throw Object.assign(new Error('Grant is already limited to one ticket.'),{status:409});
    if(Object.keys(this.data.credentials).length>=40)throw Object.assign(new Error('Sandbox limit reached. Start a fresh sandbox.'),{status:409});
    if(!this.data.revoked.includes(old.payload.id))this.data.revoked.push(old.payload.id);
    if(mode==='grant')this.issueGrant(3);if(mode==='narrow')this.issueGrant(1);
    this.event(`trust.${mode}`,mode==='revoke'?'Current grant revoked.':`Previous grant revoked; replacement quota ${mode==='narrow'?1:3}.`);return this.state();
  }
  context(decision){const d=this.data;return {request:decision.request,delegation:decision.attack==='tampered'?decision.delegation:d.credentials[decision.request.payload.delegationId],attestation:d.credentials[decision.request.payload.attestationId],identities:d.identities,revoked:new Set(d.revoked),history:d.receipts.filter(r=>r.payload.action==='sandbox.inspect'),used:d.receipts.filter(r=>r.payload.delegationId===decision.request.payload.delegationId).length,now:this.clock()};}
  prepare(scenario){
    if(Object.keys(this.data.decisions).length>=40)throw Object.assign(new Error('40-task sandbox limit reached. Start a fresh sandbox.'),{status:409});
    const now=this.clock(),d=this.data,i=d.identities,delegation=structuredClone(d.credentials[d.delegationId]),attestation=d.credentials[d.attestationId];
    if(scenario==='tampered')delegation.payload.maxItems=99;
    const payload={format:'relay-request/v1',id:randomUUID(),from:i.scout.id,to:scenario==='audience'?i.outsider.id:i.steward.id,action:scenario==='scope'?'site.delete':'ticket.create',resource:'SITE-17',notBefore:now-1000,expiresAt:scenario==='expired'?now-1:now+300000,delegationId:delegation.payload.id,attestationId:attestation.payload.id,delegationHash:digest(delegation),attestationHash:digest(attestation)};
    const request=signed('request',payload,i[scenario==='spoof'?'outsider':'scout'].privateKey),decision={id:payload.id,scenario,attack:scenario,request,delegation,attestation};decision.preflight=evaluate(this.context(decision));d.decisions[decision.id]=decision;
    this.event('task.checked',`${scenario}: ${decision.preflight.allowed?'accepted provisionally':'refused'}${decision.preflight.failed.length?' · '+decision.preflight.failed.join(', '):''}`);return decision;
  }
  execute(id){
    const d=this.data,decision=d.decisions[id];if(!decision)throw Object.assign(new Error('Task not found in your sandbox.'),{status:404});
    const existing=d.receipts.find(r=>r.payload.requestId===id);if(existing)return {status:'already_executed',receipt:existing,decision,synthetic:true};
    const evaluation=evaluate(this.context(decision));if(!evaluation.allowed){this.event('task.blocked',`No effect created: ${evaluation.failed.join(', ')}`);return {status:'blocked',evaluation,decision,synthetic:true};}
    const payload={id:randomUUID(),requestId:id,delegationId:decision.request.payload.delegationId,requestHash:digest(decision.request),issuer:d.identities.steward.id,actor:d.identities.scout.id,action:'ticket.create',resource:'SITE-17',synthetic:true,result:'Draft repair ticket created in your isolated sandbox',at:this.clock()};
    const receipt=signed('receipt',payload,d.identities.steward.privateKey);d.receipts.push(receipt);this.event('task.executed',`Steward created one synthetic draft. Receipt ${payload.id.slice(0,8)}.`);return {status:'executed',receipt,evaluation,decision,synthetic:true};
  }
  rate(){const window=Math.floor(this.clock()/60000),r=this.data.rate;if(r.window!==window){r.window=window;r.count=0;}if(r.count>=60)throw Object.assign(new Error('Sandbox request limit reached. Try next minute.'),{status:429});r.count++;}
  state(){const d=this.data,delegation=d.credentials[d.delegationId];return {identities:Object.fromEntries(Object.entries(d.identities).map(([k,v])=>[k,publicIdentity(v)])),delegation,attestation:d.credentials[d.attestationId],revoked:d.revoked.includes(d.delegationId),grantUsed:d.receipts.filter(r=>r.payload.delegationId===d.delegationId).length,selfClaim:{successfulJobs:999,label:'Self-reported · never used by policy'},receipts:[...d.receipts].reverse(),events:[...d.events].reverse(),tickets:d.receipts.filter(r=>r.payload.action==='ticket.create').length};}
}
