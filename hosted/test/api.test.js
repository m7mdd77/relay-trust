import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import {handleApi} from '../src/api.js';
import {authentic} from '../src/crypto.js';
class LocalD1 {
  constructor(){this.db=new DatabaseSync(':memory:');this.db.exec(readFileSync(new URL('../drizzle/0000_faithful_the_professor.sql',import.meta.url),'utf8').replaceAll('--> statement-breakpoint',''));}
  prepare(sql){let args=[];const stmt=this.db.prepare(sql);return {bind(...values){args=values;return this;},async first(){await Promise.resolve();return stmt.get(...args)||null;},async run(){await Promise.resolve();return {meta:stmt.run(...args)};}};}
  async batch(statements){this.db.exec('BEGIN');try{const result=[];for(const s of statements)result.push(await s.run());this.db.exec('COMMIT');return result;}catch(e){this.db.exec('ROLLBACK');throw e;}}
}
async function fixture(t){const db=new LocalD1();t.after(()=>db.db.close());const origin='https://relay.example';let now=Date.now();const clock=()=>now;
  async function visitor(){const r=await handleApi(new Request(origin+'/api/state'),db,{clock});assert.equal(r.status,200);const cookie=r.headers.get('set-cookie').split(';')[0],state=await r.json();return {cookie,token:state.token,state,request:async(path,body,extra={})=>handleApi(new Request(origin+path,{method:body===undefined?'GET':'POST',headers:{Cookie:cookie,Origin:origin,'Content-Type':'application/json','X-Demo-Token':state.token,...extra},...(body===undefined?{}:{body:JSON.stringify(body)})}),db,{clock})};}
  return {db,visitor,advance:ms=>now+=ms,clock,origin};
}
test('isolated cookie scopes prevent another visitor executing or revoking a task',async t=>{
  const {visitor}=await fixture(t),a=await visitor(),b=await visitor();assert.notEqual(a.state.identities.scout.id,b.state.identities.scout.id);
  const task=await(await a.request('/api/prepare',{scenario:'allowed'})).json();assert.equal((await b.request('/api/execute',{id:task.id})).status,404);
  await b.request('/api/trust',{mode:'revoke'});assert.equal((await(await a.request('/api/state')).json()).revoked,false);assert.equal((await(await a.request('/api/execute',{id:task.id})).json()).status,'executed');
});
test('cookie is HttpOnly, Secure, SameSite Strict and exports exclude keys/token',async t=>{
  const {db,origin,clock,visitor}=await fixture(t);const response=await handleApi(new Request(origin+'/api/state'),db,{clock}),cookie=response.headers.get('set-cookie');assert.ok(cookie.includes('HttpOnly'));assert.ok(cookie.includes('Secure'));assert.ok(cookie.includes('SameSite=Strict'));assert.ok(cookie.startsWith('__Host-'));
  const v=await visitor(),snap=await(await v.request('/api/export')).json();assert.equal(snap.token,undefined);assert.equal(JSON.stringify(snap).includes('PRIVATE KEY'),false);assert.equal(JSON.stringify(snap).includes('privateKey'),false);
});
test('atomic active-session capacity bounds anonymous storage growth',async t=>{
  const {db,origin,clock}=await fixture(t);const statement=db.db.prepare('INSERT INTO relay_sandboxes VALUES (?,0,?,?)');for(let n=0;n<256;n++)statement.run('capacity-'+n,clock()+86400000,'{}');
  const r=await handleApi(new Request(origin+'/api/state'),db,{clock});assert.equal(r.status,503);assert.equal(db.db.prepare('SELECT COUNT(*) AS n FROM relay_sandboxes').get().n,256);
});
test('mutation requires matching cookie, token, origin and correct input',async t=>{
  const {visitor}=await fixture(t),v=await visitor();for(const headers of [{Origin:'https://evil.example'},{'X-Demo-Token':'bad'},{Cookie:''},{'Content-Type':'text/plain'},{'Sec-Fetch-Site':'cross-site'}])assert.equal((await v.request('/api/prepare',{scenario:'allowed'},headers)).status,headers['Content-Type']?415:403);
  assert.equal((await v.request('/api/prepare',{scenario:'allowed',privateKey:'fake'})).status,400);assert.equal((await v.request('/api/prepare',{scenario:'spoof',padding:'x'.repeat(5000)})).status,413);
});
test('all adversarial scenarios fail; signed effects remain real',async t=>{
  const {visitor}=await fixture(t),v=await visitor();for(const scenario of ['scope','spoof','tampered','expired','audience']){const d=await(await v.request('/api/prepare',{scenario})).json();assert.equal(d.preflight.allowed,false);assert.equal((await v.request('/api/execute',{id:d.id})).status,409);}
  const d=await(await v.request('/api/prepare',{scenario:'allowed'})).json(),r=await(await v.request('/api/execute',{id:d.id})).json();assert.equal(r.status,'executed');assert.ok(authentic('receipt',r.receipt,v.state.identities.steward.publicKey));
});
test('concurrent replay commits one effect with revision guarded atomic writes',async t=>{
  const {visitor}=await fixture(t),v=await visitor(),d=await(await v.request('/api/prepare',{scenario:'allowed'})).json();
  const outcomes=await Promise.all(Array.from({length:5},async()=>await(await v.request('/api/execute',{id:d.id})).json()));assert.equal(outcomes.filter(r=>r.status==='executed').length,1);assert.equal(outcomes.filter(r=>r.status==='already_executed').length,4);assert.equal(new Set(outcomes.map(r=>r.receipt.payload.id)).size,1);assert.equal((await(await v.request('/api/state')).json()).tickets,1);
});
test('revocation after preflight and narrowed quota block later effects',async t=>{
  const {visitor}=await fixture(t),v=await visitor(),d=await(await v.request('/api/prepare',{scenario:'allowed'})).json();await v.request('/api/trust',{mode:'revoke'});assert.equal((await v.request('/api/execute',{id:d.id})).status,409);
  await v.request('/api/trust',{mode:'grant'});await v.request('/api/trust',{mode:'narrow'});const a=await(await v.request('/api/prepare',{scenario:'allowed'})).json(),b=await(await v.request('/api/prepare',{scenario:'allowed'})).json();const results=await Promise.all([a,b].map(async d=>await(await v.request('/api/execute',{id:d.id})).json()));assert.equal(results.filter(r=>r.status==='executed').length,1);assert.equal(results.filter(r=>r.status==='blocked').length,1);
});
test('session data persists through handler calls; expiry fails closed and reset rotates keys',async t=>{
  const {visitor,advance}=await fixture(t),v=await visitor();const state=await(await v.request('/api/state')).json();assert.equal(state.identities.scout.id,v.state.identities.scout.id);
  const d=await(await v.request('/api/prepare',{scenario:'allowed'})).json();advance(300000);assert.equal((await v.request('/api/execute',{id:d.id})).status,409);
  const reset=await v.request('/api/reset',{}),newState=await reset.json();assert.notEqual(newState.identities.scout.id,state.identities.scout.id);assert.notEqual(newState.token,state.token);assert.ok(reset.headers.get('set-cookie'));
  advance(86400000);assert.equal((await v.request('/api/execute',{id:d.id})).status,403);
});
