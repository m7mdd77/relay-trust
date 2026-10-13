import {DatabaseSync} from 'node:sqlite';
import {mkdirSync} from 'node:fs';
import {dirname} from 'node:path';
import {randomUUID} from 'node:crypto';
import {newIdentity, signed, digest, publicIdentity} from './crypto.js';
import {evaluate} from './policy.js';

export class TrustStore {
  constructor(path, clock=()=>Date.now()) {
    if (path!==':memory:') mkdirSync(dirname(path),{recursive:true});
    this.clock=clock; this.db=new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS identities (role TEXT PRIMARY KEY, data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS credentials (id TEXT PRIMARY KEY, kind TEXT, envelope TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS decisions (id TEXT PRIMARY KEY, data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS receipts (id TEXT PRIMARY KEY, decision_id TEXT UNIQUE, grant_id TEXT, envelope TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL);`);
    this.identities=Object.fromEntries(this.db.prepare('SELECT * FROM identities').all().map(r=>[r.role,JSON.parse(r.data)]));
    if (!this.identities.owner) this.seed();
  }
  transaction(fn) {this.db.exec('BEGIN IMMEDIATE');try {const result=fn();this.db.exec('COMMIT');return result;}catch(e){this.db.exec('ROLLBACK');throw e;}}
  setting(k) {return this.db.prepare('SELECT value FROM settings WHERE key=?').get(k)?.value;}
  set(k,v) {this.db.prepare('INSERT OR REPLACE INTO settings VALUES (?,?)').run(k,v);}
  event(type,detail) {this.db.prepare('INSERT INTO events(data) VALUES (?)').run(JSON.stringify({type,detail,at:this.clock()}));}
  credential(id) {const r=this.db.prepare('SELECT * FROM credentials WHERE id=?').get(id);return r?JSON.parse(r.envelope):null;}
  addCredential(payload,role) {const env=signed('credential',payload,this.identities[role].privateKey);this.db.prepare('INSERT INTO credentials(id,kind,envelope) VALUES (?,?,?)').run(payload.id,payload.kind,JSON.stringify(env));return env;}
  seed() {
    this.transaction(()=>{
      for(const [role,name] of Object.entries({owner:'Workshop Owner',lab:'Evidence Lab',scout:'Scout / inspection agent',steward:'Patch Steward / receiving agent',outsider:'Mirror / spoofing actor'})) {
        const identity=newIdentity(name,role);this.identities[role]=identity;this.db.prepare('INSERT INTO identities VALUES (?,?)').run(role,JSON.stringify(identity));
      }
      const now=this.clock(), receiptHashes=[];
      for(let i=0;i<3;i++) {
        const payload={id:randomUUID(),actor:this.identities.scout.id,issuer:this.identities.lab.id,action:'sandbox.inspect',resource:'SITE-17',synthetic:true,result:'Broken destination reproduced',at:now-(3-i)*60000};
        const env=signed('receipt',payload,this.identities.lab.privateKey);receiptHashes.push(digest(env));
        this.db.prepare('INSERT INTO receipts VALUES (?,NULL,NULL,?)').run(payload.id,JSON.stringify(env));
      }
      const a=this.addCredential({format:'relay-credential/v1',id:randomUUID(),kind:'attestation',issuer:this.identities.lab.id,subject:this.identities.scout.id,audience:this.identities.steward.id,notBefore:now-1000,expiresAt:now+30*86400000,claim:{type:'sandbox.inspection',successfulInspections:3,environment:'synthetic',receiptHashes}},'lab');
      this.set('attestation',a.payload.id);this.issueGrant(3);this.event('identity.created','Five local key-bound identities; three synthetic inspection receipts.');
    });
  }
  issueGrant(maxItems) {
    const now=this.clock();const d=this.addCredential({format:'relay-credential/v1',id:randomUUID(),kind:'delegation',issuer:this.identities.owner.id,subject:this.identities.scout.id,audience:this.identities.steward.id,notBefore:now-1000,expiresAt:now+86400000,capabilities:['ticket.create'],resources:['SITE-17'],maxItems},'owner');
    this.set('delegation',d.payload.id);return d;
  }
  manage(mode) {
    return this.transaction(()=>{
      const old=this.credential(this.setting('delegation'));
      if(mode==='narrow' && old.payload.maxItems<=1) throw Object.assign(new Error('Grant is already limited to one ticket.'),{status:409});
      this.db.prepare('UPDATE credentials SET revoked=1 WHERE id=?').run(old.payload.id);
      if(mode==='grant') this.issueGrant(3);
      if(mode==='narrow') this.issueGrant(1);
      this.event(`trust.${mode}`,mode==='revoke'?'Current grant revoked.':`Previous grant revoked; new grant limited to ${mode==='narrow'?1:3} tickets.`);
      return this.state();
    });
  }
  context(decision) {
    const revoked=new Set(this.db.prepare('SELECT id FROM credentials WHERE revoked=1').all().map(r=>r.id));
    // Re-fetch current stored envelopes by committed IDs, but preserve deliberately tampered test evidence.
    const delegation=decision.attack==='tampered'?decision.delegation:this.credential(decision.request.payload.delegationId);
    const attestation=this.credential(decision.request.payload.attestationId);
    const used=this.db.prepare('SELECT COUNT(*) AS n FROM receipts WHERE grant_id=?').get(decision.request.payload.delegationId).n;
    const history=this.db.prepare('SELECT envelope FROM receipts WHERE decision_id IS NULL').all().map(r=>JSON.parse(r.envelope));
    return {request:decision.request,delegation,attestation,identities:this.identities,revoked,history,used,now:this.clock()};
  }
  prepare(scenario) {
    return this.transaction(()=>{
      const now=this.clock(),delegation=structuredClone(this.credential(this.setting('delegation'))),attestation=this.credential(this.setting('attestation'));
      if(scenario==='tampered') delegation.payload.maxItems=99;
      const payload={format:'relay-request/v1',id:randomUUID(),from:this.identities.scout.id,to:this.identities.steward.id,action:scenario==='scope'?'site.delete':'ticket.create',resource:'SITE-17',notBefore:now-1000,expiresAt:scenario==='expired'?now-1:now+300000,delegationId:delegation.payload.id,attestationId:attestation.payload.id,delegationHash:digest(delegation),attestationHash:digest(attestation)};
      if(scenario==='audience') payload.to=this.identities.outsider.id;
      const request=signed('request',payload,this.identities[scenario==='spoof'?'outsider':'scout'].privateKey);
      const decision={id:payload.id,scenario,attack:scenario,request,delegation,attestation};
      decision.preflight=evaluate(this.context(decision));
      this.db.prepare('INSERT INTO decisions VALUES (?,?)').run(decision.id,JSON.stringify(decision));
      this.event('task.checked',`${scenario}: ${decision.preflight.allowed?'accepted provisionally':'refused'}${decision.preflight.failed.length?' · '+decision.preflight.failed.join(', '):''}`);
      return decision;
    });
  }
  execute(id) {
    return this.transaction(()=>{
      const row=this.db.prepare('SELECT data FROM decisions WHERE id=?').get(id);
      if(!row) throw Object.assign(new Error('Task not found.'),{status:404});
      const decision=JSON.parse(row.data);
      const existing=this.db.prepare('SELECT envelope FROM receipts WHERE decision_id=?').get(id);
      if(existing) return {status:'already_executed',receipt:JSON.parse(existing.envelope),decision,synthetic:true};
      const evaluation=evaluate(this.context(decision));
      if(!evaluation.allowed) {this.event('task.blocked',`No effect created: ${evaluation.failed.join(', ')}`);return {status:'blocked',evaluation,decision,synthetic:true};}
      const payload={id:randomUUID(),requestId:id,delegationId:decision.request.payload.delegationId,requestHash:digest(decision.request),issuer:this.identities.steward.id,actor:this.identities.scout.id,action:'ticket.create',resource:'SITE-17',synthetic:true,result:'Draft repair ticket created locally',at:this.clock()};
      const receipt=signed('receipt',payload,this.identities.steward.privateKey);
      this.db.prepare('INSERT INTO receipts VALUES (?,?,?,?)').run(payload.id,id,decision.request.payload.delegationId,JSON.stringify(receipt));
      this.event('task.executed',`Patch Steward created one synthetic SITE-17 draft. Receipt ${payload.id.slice(0,8)}.`);
      return {status:'executed',receipt,evaluation,decision,synthetic:true};
    });
  }
  state() {
    const delegation=this.credential(this.setting('delegation')),attestation=this.credential(this.setting('attestation'));
    const revoked=!!this.db.prepare('SELECT revoked FROM credentials WHERE id=?').get(delegation.payload.id).revoked;
    const grantUsed=this.db.prepare('SELECT COUNT(*) AS n FROM receipts WHERE grant_id=?').get(delegation.payload.id).n;
    return {identities:Object.fromEntries(Object.entries(this.identities).map(([k,v])=>[k,publicIdentity(v)])),delegation,attestation,revoked,grantUsed,
      selfClaim:{successfulJobs:999,label:'Self-reported · never used by policy'},
      receipts:this.db.prepare('SELECT envelope FROM receipts ORDER BY rowid DESC').all().map(r=>JSON.parse(r.envelope)),
      events:this.db.prepare('SELECT seq,data FROM events ORDER BY seq DESC LIMIT 40').all().map(r=>({seq:r.seq,...JSON.parse(r.data)})),
      tickets:this.db.prepare('SELECT COUNT(*) AS n FROM receipts WHERE decision_id IS NOT NULL').get().n};
  }
  close(){this.db.close();}
}
