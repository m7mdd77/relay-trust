const $=id=>document.getElementById(id);
let state,decision,token,busy=false;
const labels={request_signature:'Requester signature',delegation_signature:'Owner signature',attestation_signature:'Evidence signature',format:'Credential format',issuer_binding:'Pinned issuers',subject_binding:'Subject binding',audience:'Receiving agent',credential_binding:'Exact credential binding',validity:'Validity windows',revocation:'Live revocation',capability:'Delegated capability',resource:'Resource boundary',evidence:'Attested history',history_signatures:'Inspection receipts',quota:'Remaining quota'};
const copies={allowed:'Scout asks Patch Steward to create one synthetic repair ticket for SITE-17. The owner allows up to three tickets and the lab attests three inspections.',scope:'A valid Scout asks to delete SITE-17. Its authentic key cannot expand the owner’s ticket.create capability.',spoof:'Mirror copies Scout’s public identity and credentials, but signs the request with Mirror’s key. A familiar name cannot prove key possession.',tampered:'The attacker changes the signed grant from 3 to 99 tickets. Verification must detect the altered payload before any effect.',expired:'Scout signs a request whose validity window has already ended. Authentic signatures do not make expired authority usable.',audience:'Scout addresses the task to Mirror. This grant is only usable by Patch Steward, so audience binding must refuse it.'};
const short=id=>id.slice(0,18)+'…'+id.slice(-12);
const time=ms=>new Date(ms).toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
function element(tag,text,className){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(className)e.className=className;return e;}
function error(message){$('message').textContent=message;$('message').hidden=false;setTimeout(()=>$('message').hidden=true,6500);}
async function api(path,body){const res=await fetch(path,body?{method:'POST',headers:{'Content-Type':'application/json','X-Demo-Token':token},body:JSON.stringify(body)}:{});const data=await res.json();if(!res.ok && data.status!=='blocked')throw new Error(data.error||'Request failed.');return data;}
async function refresh(){const data=await api('/api/state');token=data.token;delete data.token;state=data;renderState();}
function renderState(){
  for(const id of ['prepare','grant','verify','export','reset'])$(id).disabled=busy;
  $('scout-id').textContent=short(state.identities.scout.id);$('scout-id').title=state.identities.scout.id;
  $('steward-id').textContent=short(state.identities.steward.id);$('steward-id').title=state.identities.steward.id;
  $('ticket-count').textContent=`${state.tickets} sandbox ticket${state.tickets===1?'':'s'}`;
  $('grant-status').textContent=state.revoked?'REVOKED':'ACTIVE';$('grant-status').className=`pill ${state.revoked?'revoked-grant':'active-grant'}`;
  const d=state.delegation.payload;
  copies.allowed=`Scout asks Patch Steward to create one synthetic repair ticket for SITE-17. This owner grant allows ${d.maxItems} ticket${d.maxItems===1?'':'s'}; the lab attests three inspections.`;
  $('scenario-copy').textContent=copies[$('scenario').value];
  $('grant-meta').replaceChildren(...[`ticket.create`,'SITE-17',`${state.grantUsed} / ${d.maxItems} tickets used`,`Expires ${time(d.expiresAt)}`,`Grant ${d.id.slice(0,8)}`].map(t=>element('span',t)));
  $('narrow').disabled=busy||d.maxItems<=1||state.revoked;$('revoke').disabled=busy||state.revoked;
  $('credential-view').replaceChildren();
  for(const [title,env] of [['Owner → Scout / authority',state.delegation],['Evidence Lab → Scout / attestation',state.attestation]]){$('credential-view').append(element('h3',title),element('pre',JSON.stringify(env,null,2)));}
  $('receipts').replaceChildren(...state.receipts.slice(0,8).map(env=>{
    const r=env.payload,e=element('article',undefined,'receipt'),left=element('div');left.append(element('b',r.action==='ticket.create'?'Repair draft created':'Inspection evidence seeded'),element('p',`${r.resource} · ${time(r.at)} · ${r.id.slice(0,8)}`));e.append(left,element('span','SIGNED / SYNTHETIC','receipt-tag'));return e;
  }));
  $('events').replaceChildren(...state.events.slice(0,14).map(ev=>{const li=element('li');li.append(element('b',`${time(ev.at)} · ${ev.type}`),element('span',ev.detail));return li;}));
}
function showDecision(evaluation,result){
  const panel=$('decision-panel'),content=$('decision-content');panel.classList.toggle('denied',!evaluation.allowed);content.replaceChildren();
  const top=element('div',undefined,'decision-top');top.append(element('span',evaluation.allowed?'ACCEPTED PROVISIONALLY':'REFUSED','pill'),element('code',`TASK ${decision.id.slice(0,8)}`));content.append(top);
  const headings={executed:'A repair draft, with a signed receipt.',already_executed:'Same task. Same signed receipt.',blocked:'The live trust check blocked execution.'};
  content.append(element('h2',headings[result?.status]||(evaluation.allowed?'The handoff is within trust.':'This task crosses a trust boundary.')));
  const explanations={executed:'Patch Steward rechecked the grant and evidence at execution, then created one synthetic ticket.',already_executed:'This task already completed. The original receipt is returned; replay creates no new effect.'};
  content.append(element('p',explanations[result?.status]||(evaluation.allowed?'Patch Steward accepts Scout’s signed authority and evidence. Execution still requires a live recheck.':`No effect authorized. Failed checks: ${evaluation.failed.map(k=>labels[k]).join(', ')}.`)));
  const list=element('ul',undefined,'check-list');for(const c of evaluation.checks){const li=element('li',undefined,c.pass?'pass':'fail');li.append(element('span',c.pass?'✓':'×','check-symbol'),element('span',labels[c.code]));list.append(li);}content.append(list);
  const details=element('details');details.append(element('summary','Why each check passed or failed'));for(const c of evaluation.checks)details.append(element('p',`${c.pass?'✓':'×'} ${labels[c.code]}: ${c.detail}`,'check-detail'));content.append(details);
  const proof=element('details');proof.append(element('summary','Inspect submitted request and grant'),element('pre',JSON.stringify({request:decision.request,delegation:decision.delegation},null,2)));content.append(proof);
  if(result){
    const texts={executed:'EXECUTED · One sandbox repair draft created. Patch Steward signed the receipt.',already_executed:'ALREADY EXECUTED · Returning the original receipt. No duplicate ticket created.',blocked:'BLOCKED AT EXECUTION · Trust changed or was invalid. No new ticket created.'};
    const note=element('div',texts[result.status],'result-note');if(result.receipt)note.append(element('p',`Receipt ${result.receipt.payload.id} · signed by Patch Steward`));content.append(note);
    if(result.status==='executed'||result.status==='already_executed')top.firstChild.textContent=result.status==='executed'?'EXECUTED / SIGNED':'IDEMPOTENT REPLAY';
  }
  $('execution').hidden=!evaluation.allowed && result?.status!=='already_executed';
  $('execute').textContent=result?.receipt?'Repeat execution / prove idempotency →':'Execute with live trust check →';
  if(matchMedia('(max-width:650px)').matches)panel.scrollIntoView({behavior:matchMedia('(prefers-reduced-motion:reduce)').matches?'instant':'smooth',block:'start'});
}
async function run(fn){if(busy)return;busy=true;for(const id of ['prepare','execute','grant','narrow','revoke','verify','export','reset'])$(id).disabled=true;try{await fn();}catch(e){error(e.message);}finally{busy=false;for(const id of ['prepare','execute','grant','verify','export','reset'])$(id).disabled=false;if(state)renderState();}}
$('scenario').addEventListener('change',()=>{$('scenario-copy').textContent=copies[$('scenario').value];});
$('prepare').addEventListener('click',()=>run(async()=>{decision=await api('/api/prepare',{scenario:$('scenario').value});showDecision(decision.preflight);await refresh();}));
$('execute').addEventListener('click',()=>run(async()=>{if(!decision)return;const result=await api('/api/execute',{id:decision.id});showDecision(result.evaluation||decision.preflight,result);await refresh();}));
for(const mode of ['grant','narrow','revoke'])$(mode).addEventListener('click',()=>run(async()=>{await api('/api/trust',{mode});await refresh();if(decision){const note=element('div','Trust changed. This prepared task retains its original grant; execution will recheck it.','result-note');$('decision-content').append(note);}}));
const stable=value=>value===null||typeof value!=='object'?JSON.stringify(value):Array.isArray(value)?`[${value.map(stable).join(',')}]`:`{${Object.keys(value).sort().map(k=>`${JSON.stringify(k)}:${stable(value[k])}`).join(',')}}`;
const decode=value=>Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));
async function verifyEnvelope(domain,env,publicPem){const der=decode(publicPem.replace(/-----[^-]+-----/g,'').replace(/\s/g,''));const key=await crypto.subtle.importKey('spki',der,'Ed25519',false,['verify']);return crypto.subtle.verify('Ed25519',key,decode(env.signature),new TextEncoder().encode(`relay-trust/v1/${domain}\n${stable(env.payload)}`));}
$('verify').addEventListener('click',()=>run(async()=>{
  await refresh();const checks=[['credential',state.delegation,state.identities.owner.publicKey],['credential',state.attestation,state.identities.lab.publicKey],...state.receipts.map(r=>['receipt',r,Object.values(state.identities).find(i=>i.id===r.payload.issuer).publicKey])];
  const outcomes=await Promise.all(checks.map(c=>verifyEnvelope(...c)));
  $('verify-result').textContent=outcomes.every(Boolean)?`${outcomes.length}/${outcomes.length} public signatures verified independently in this browser. Signatures attest origin and integrity; current authority still requires policy.`:'A public signature failed verification.';
}));
$('export').addEventListener('click',()=>run(async()=>{const snapshot=await api('/api/export');const url=URL.createObjectURL(new Blob([JSON.stringify(snapshot,null,2)],{type:'application/json'}));const a=element('a');a.href=url;a.download='relay-public-evidence.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}));
$('scenario-copy').textContent=copies.allowed;
refresh().catch(e=>error(e.message));

$('reset').addEventListener('click',()=>run(async()=>{await api('/api/reset',{});decision=null;$('execution').hidden=true;$('decision-panel').classList.remove('denied');$('decision-content').replaceChildren(element('h2','A fresh sandbox is ready.'),element('p','Fresh identities, evidence, and authority. Check a handoff to start.'));$('verify-result').textContent='';await refresh();}));
