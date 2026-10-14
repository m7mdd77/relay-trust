import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtempSync,readdirSync,readFileSync,rmSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';
import {createApp} from '../server.js';
test('recording is saved only by an authenticated same-origin local request and cannot name a path',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'relay-recording-')),app=createApp({dbPath:':memory:',recordingDirectory:dir});await new Promise(r=>app.server.listen(0,'127.0.0.1',r));const base=`http://127.0.0.1:${app.server.address().port}`;
 try{const state=await(await fetch(base+'/api/state')).json(),video=Buffer.from('1a45dfa3000000000000000000000000','hex');const submit=extra=>fetch(base+'/api/recording',{method:'POST',headers:{Origin:base,'Content-Type':'video/webm','X-Demo-Token':state.token,...extra},body:video});
  assert.equal((await submit({Origin:'https://attacker.example'})).status,403);assert.equal((await submit({'X-Demo-Token':'bad'})).status,403);assert.equal((await submit({'Content-Type':'text/plain'})).status,415);assert.deepEqual(readdirSync(dir),[]);
  assert.equal((await fetch(base+'/api/recording',{method:'POST',headers:{Origin:base,'Content-Type':'video/webm','X-Demo-Token':state.token},body:'not a video'})).status,400);
  const r=await submit({});assert.equal(r.status,201);const saved=await r.json();assert.match(saved.filename,/^relay-trust-live-\d+\.webm$/);assert.deepEqual(readFileSync(join(dir,saved.filename)),video);assert.deepEqual(readdirSync(dir),[saved.filename]);
 }finally{await new Promise(r=>app.server.close(r));app.store.close();rmSync(dir,{recursive:true,force:true});}
});
