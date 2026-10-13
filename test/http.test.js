import test from 'node:test';
import assert from 'node:assert/strict';
import {request as httpRequest} from 'node:http';
import {createApp} from '../server.js';

async function setup(t){const app=createApp({dbPath:':memory:'});await new Promise(r=>app.server.listen(0,'127.0.0.1',r));t.after(async()=>{await new Promise(r=>app.server.close(r));app.store.close();});const url=`http://127.0.0.1:${app.server.address().port}`;const state=await (await fetch(url+'/api/state')).json();const headers={'Origin':url,'Content-Type':'application/json','X-Demo-Token':state.token};return {...app,url,headers};}
const post=(url,path,headers,body)=>fetch(url+path,{method:'POST',headers,body:JSON.stringify(body)});

test('HTTP valid flow, idempotency, and revocation race exercise actual routes',async t=>{
  const {url,headers}=await setup(t);const d=await(await post(url,'/api/prepare',headers,{scenario:'allowed'})).json();assert.ok(d.preflight.allowed);
  const first=await(await post(url,'/api/execute',headers,{id:d.id})).json();assert.equal(first.status,'executed');
  const repeated=await(await post(url,'/api/execute',headers,{id:d.id})).json();assert.equal(repeated.status,'already_executed');assert.deepEqual(first.receipt,repeated.receipt);
  const pending=await(await post(url,'/api/prepare',headers,{scenario:'allowed'})).json();await post(url,'/api/trust',headers,{mode:'revoke'});
  const blocked=await post(url,'/api/execute',headers,{id:pending.id});assert.equal(blocked.status,409);assert.ok((await blocked.json()).evaluation.failed.includes('revocation'));
});
test('HTTP requires exact same origin, session token, JSON content type',async t=>{
  const {url,headers}=await setup(t);
  for(const override of [{Origin:'https://evil.example'},{Origin:''},{'X-Demo-Token':'x'},{'Content-Type':'text/plain'},{'Sec-Fetch-Site':'cross-site'}]){
    const r=await post(url,'/api/prepare',{...headers,...override},{scenario:'allowed'});assert.equal(r.status,override['Content-Type']?415:403);
  }
});
test('concurrent HTTP replay commits one effect and returns one identical receipt',async t=>{
  const {url,headers,store}=await setup(t);const d=await(await post(url,'/api/prepare',headers,{scenario:'allowed'})).json();
  const results=await Promise.all(Array.from({length:5},async()=>await(await post(url,'/api/execute',headers,{id:d.id})).json()));
  assert.equal(results.filter(r=>r.status==='executed').length,1);assert.equal(results.filter(r=>r.status==='already_executed').length,4);
  assert.equal(new Set(results.map(r=>r.receipt.payload.id)).size,1);assert.equal(store.state().tickets,1);
});
test('HTTP validates scenarios, body shape, unknown fields, IDs and methods',async t=>{
  const {url,headers}=await setup(t);
  for(const body of [null,[],{}, {scenario:'untrusted'}, {scenario:'allowed',privateKey:'injected'}])assert.equal((await post(url,'/api/prepare',headers,body)).status,400);
  assert.equal((await post(url,'/api/execute',headers,{id:'../../secret'})).status,400);
  assert.equal((await post(url,'/api/execute',headers,{id:'00000000-0000-0000-0000-000000000000'})).status,404);
  assert.equal((await fetch(url+'/api/state',{method:'DELETE'})).status,405);
  assert.equal((await fetch(url+'/api/prepare',{method:'POST',headers,body:'{invalid'})).status,400);
});
test('Host rebinding defenses, cross-origin reads, and private paths',async t=>{
  const {url,headers,server}=await setup(t);
  const status=await new Promise((resolve,reject)=>{const req=httpRequest({host:'127.0.0.1',port:server.address().port,path:'/api/state',headers:{Host:'evil.example'}},res=>{res.resume();resolve(res.statusCode);});req.on('error',reject);req.end();});assert.equal(status,403);
  assert.equal((await fetch(url+'/api/state',{headers:{Origin:'https://evil.example'}})).status,403);
  for(const route of ['/.local/trust.sqlite','/src/store.js','/server.js','/api/state?dump=true','/%2e%2e/.local/trust.sqlite'])assert.equal((await fetch(url+route)).status,404);
});
test('CSP, no-store, no CORS, and public export omit keys and token',async t=>{
  const {url}=await setup(t);const page=await fetch(url);assert.ok(page.headers.get('content-security-policy').includes("frame-ancestors 'none'"));assert.ok(page.headers.get('content-security-policy').includes("script-src 'self'"));assert.equal(page.headers.get('cache-control'),'no-store');assert.equal(page.headers.get('access-control-allow-origin'),null);
  const snapshot=await(await fetch(url+'/api/export')).json();const text=JSON.stringify(snapshot);assert.equal(snapshot.token,undefined);assert.equal(text.includes('PRIVATE KEY'),false);assert.equal(text.includes('privateKey'),false);
});
test('request body size and mutation rate limits bound local abuse',async t=>{
  const {url,headers}=await setup(t);const large=await post(url,'/api/prepare',headers,{scenario:'allowed',padding:'a'.repeat(5000)});assert.equal(large.status,413);
  for(let i=0;i<119;i++)await post(url,'/api/prepare',headers,{scenario:'spoof'});
  assert.equal((await post(url,'/api/prepare',headers,{scenario:'allowed'})).status,429);
});
