const output=document.getElementById('agent-output'),status=document.getElementById('agent-status'),controls=document.getElementById('agent-controls');
const buttons=[...controls.querySelectorAll('button')];let busy=false,started=false,recording=false,lastState;
const summary=document.createElement('div');summary.setAttribute('role','status');summary.className='agent-summary';controls.after(summary);
function render(s){lastState=s;started=!!s.trace?.length;output.textContent=JSON.stringify(s,null,2);const event=s.trace?.at(-1);summary.textContent=event?`${event.type} · ${event.status||'verified'}${event.evaluation?.failed?.length?' · '+event.evaluation.failed.join(', '):''}`:'Run the two AI agents to propose and verify a handoff.';if(!recording)status.textContent=s.configured?'Separate Scout and Steward processes · DeepSeek V4 Flash':'Configure RELAY_AGENT_ENV, then restart the local server.';for(const b of buttons)b.disabled=busy||!s.configured||b.dataset.mode==='run'&&started;}
async function action(mode){if(busy)throw Error('An operation is already in progress');busy=true;buttons.forEach(b=>b.disabled=true);summary.textContent='Working in the independent agent processes…';try{const state=await(await fetch('/api/state',{cache:'no-store'})).json();const response=await fetch('/api/agents',{method:'POST',headers:{'Content-Type':'application/json','X-Demo-Token':state.token},body:JSON.stringify({mode})});const result=await response.json();if(!response.ok)throw Error(result.error);render(result);return result;}catch(e){summary.textContent=e.message;throw e;}finally{busy=false;const s=await(await fetch('/api/agent-state',{cache:'no-store'})).json();render(s);}}
for(const b of buttons)b.addEventListener('click',()=>action(b.dataset.mode).catch(()=>{}));
fetch('/api/agent-state',{cache:'no-store'}).then(r=>r.json()).then(render);
const recorderButton=document.getElementById('record-live');
recorderButton.addEventListener('click',async()=>{
 let stream;try{
  if(!started||busy)throw Error('Run the AI handoff before starting the recording.');
  stream=await navigator.mediaDevices.getDisplayMedia({video:{displaySurface:'browser'},audio:false,preferCurrentTab:true,selfBrowserSurface:'include'});
  const chunks=[],recorder=new MediaRecorder(stream,{mimeType:MediaRecorder.isTypeSupported('video/webm;codecs=vp9')?'video/webm;codecs=vp9':'video/webm',videoBitsPerSecond:1500000});
  let stopped=false;recorder.ondataavailable=e=>{if(e.data.size)chunks.push(e.data);};
  recorder.onstop=async()=>{stopped=true;recording=false;stream.getTracks().forEach(t=>t.stop());try{const video=new Blob(chunks,{type:'video/webm'}),state=await(await fetch('/api/state',{cache:'no-store'})).json();const response=await fetch('/api/recording',{method:'POST',headers:{'Content-Type':'video/webm','X-Demo-Token':state.token},body:video});const saved=await response.json();if(!response.ok)throw Error(saved.error);status.textContent=`Continuous recording saved locally: ${saved.filename} (${saved.bytes} bytes). Review before publication.`;}catch(e){status.textContent=`Recording save failed: ${e.message}`;const a=document.createElement('a');a.href=URL.createObjectURL(new Blob(chunks,{type:'video/webm'}));a.download='relay-trust-live-walkthrough.webm';a.click();}finally{recorderButton.disabled=false;}};
  recorder.start(1000);recording=true;recorderButton.disabled=true;status.textContent='Recording only this tab continuously for 90 seconds. No microphone audio.';
  const delays=[[2,'prepare'],[12,'execute'],[25,'replay'],[38,'spoof'],[51,'prepare'],[64,'revoke'],[76,'execute']];
  for(const [seconds,mode] of delays)setTimeout(()=>{if(!stopped)action(mode).catch(e=>{summary.textContent=`Demonstration stopped: ${e.message}`;});},seconds*1000);
  setTimeout(()=>{if(recorder.state==='recording')recorder.stop();},90000);
  stream.getVideoTracks()[0].addEventListener('ended',()=>{if(recorder.state==='recording')recorder.stop();});
 }catch(e){stream?.getTracks().forEach(t=>t.stop());status.textContent=e.message;}
});
