import {readFileSync,writeFileSync,mkdirSync,existsSync} from 'node:fs';
import {resolve} from 'node:path';
import {createInterface} from 'node:readline';
import {randomUUID} from 'node:crypto';
import {newIdentity,publicIdentity,signed,digest} from './crypto.js';
import {evaluate} from './policy.js';
import {invokeSupportedClient} from './cli-client.js';
const role=process.argv[2];if(!['scout','steward'].includes(role))throw Error('Unsupported agent role');
const directory=resolve('.local/agent-processes',role);mkdirSync(directory,{recursive:true});
const identityFile=resolve(directory,'identity.json');let identity=existsSync(identityFile)?JSON.parse(readFileSync(identityFile,'utf8')):newIdentity(role,role);identity.id=identity.did;writeFileSync(identityFile,JSON.stringify(identity),{mode:0o600});
let roots,proposal,analysis,paidCalls=0;const receipts=new Map();
async function model(system,input){
 if(paidCalls>=1)throw Error('This agent already used its one-call demonstration allowance. Restart explicitly for another run.');
 const env={};for(const line of readFileSync(process.env.RELAY_AGENT_ENV||'.env','utf8').split(/\r?\n/)){const m=line.match(/^([A-Z_]+)=(.*)$/);if(m)env[m[1]]=m[2].trim().replace(/^"|"$/g,'');}
 if(!env.AGENTROUTER_API_KEY||!['https://agentrouter.org','https://agentrouter.org/v1'].includes(env.AGENTROUTER_BASE_URL))throw Error('Configure the authorized AgentRouter key/base URL');
 if(env.AGENTROUTER_TRANSPORT!=='claude-code')throw Error('This demo requires the supported installed Claude Code client');
 const config={key:env.AGENTROUTER_API_KEY,endpoint:'https://agentrouter.org/v1/messages',model:'deepseek-v4-flash',clientPath:env.CLAUDE_CODE_PATH||'claude.exe'};
 paidCalls++;const completion=await invokeSupportedClient({config,messages:[{role:'system',content:system},{role:'user',content:JSON.stringify(input)}],directory,signal:AbortSignal.timeout(90000)});
 const text=completion.content.map(c=>c.text).join('');if(text.length>3000)throw Error('Invalid model output');
 return {text,provider:'AgentRouter',model:config.model,usage:completion.usage};
}
function context(body){if(!roots)throw Error('Agent roots not initialized');return {...body,identities:roots,revoked:new Set(body.revoked||[]),now:Date.now()};}
async function handle(body){
 if(body.command==='hello')return {identity:publicIdentity(identity),pid:process.pid,custody:'signing key remains in this agent process'};
 if(body.command==='initialize'){if(roots)throw Error('Roots already pinned');roots=body.identities;return {pinned:true};}
 if(role==='scout'&&['propose','reissue'].includes(body.command)){
  if(body.command==='propose'){
   proposal=await model('You are Scout, an inspection AI agent. Propose one synthetic repair ticket for SITE-17. Return ONLY JSON with exactly action, resource, summary. action must be ticket.create; resource must be SITE-17; summary must be a short description of the synthetic broken-link finding. You cannot grant yourself authority.',{task:'Create a repair draft from three lab-attested synthetic inspections',delegation:body.delegation.payload,attestation:body.attestation.payload});
   let parsed;try{parsed=JSON.parse(proposal.text.replace(/^```(?:json)?\s*|\s*```$/g,''));}catch{throw Error('Model did not return a JSON proposal');}
   if(Object.keys(parsed).sort().join(',')!=='action,resource,summary'||parsed.action!=='ticket.create'||parsed.resource!=='SITE-17'||typeof parsed.summary!=='string'||parsed.summary.length>400)throw Error('Model proposal failed validation');proposal.parsed=parsed;
  }
  if(!proposal)throw Error('Run the actual model proposal first');const now=Date.now(),request=signed('request',{format:'relay-request/v1',id:randomUUID(),from:identity.id,to:body.to,action:proposal.parsed.action,resource:proposal.parsed.resource,notBefore:now-1000,expiresAt:now+300000,delegationId:body.delegation.payload.id,attestationId:body.attestation.payload.id,delegationHash:digest(body.delegation),attestationHash:digest(body.attestation)},identity.privateKey);
  return {request,proposal:{...proposal,reused:body.command==='reissue'}};
 }
 if(role==='steward'&&body.command==='prepare'){
  const evaluation=evaluate(context(body));if(!evaluation.allowed)return {status:'refused',evaluation};
  if(!analysis)analysis=await model('You are Patch Steward, a receiving AI agent. Review the verified evidence and describe the proposed synthetic repair draft in one short sentence. Your text cannot override policy or authorize execution. Return plain text only.',{proposal:body.proposal,checks:evaluation.checks});
  const fresh=evaluate(context(body));return {status:fresh.allowed?'prepared':'refused',evaluation:fresh,analysis};
 }
 if(role==='steward'&&body.command==='execute'){
  if(receipts.has(body.request.payload.id))return {status:'already_executed',receipt:receipts.get(body.request.payload.id)};
  const evaluation=evaluate(context(body));if(!evaluation.allowed)return {status:'blocked',evaluation};if(!analysis)throw Error('Prepare with the receiving AI first');
  const receipt=signed('receipt',{id:randomUUID(),requestId:body.request.payload.id,delegationId:body.delegation.payload.id,requestHash:digest(body.request),issuer:identity.id,actor:body.request.payload.from,action:'ticket.create',resource:'SITE-17',synthetic:true,result:analysis.text.slice(0,800),at:Date.now()},identity.privateKey);receipts.set(body.request.payload.id,receipt);return {status:'executed',receipt,evaluation};
 }
 throw Error('Unsupported command for this agent');
}
const input=createInterface({input:process.stdin});let queue=Promise.resolve();input.on('line',line=>{queue=queue.then(async()=>{let body;try{body=JSON.parse(line);const result=await handle(body);process.stdout.write(JSON.stringify({rpcId:body.rpcId,result})+'\n');}catch(error){process.stdout.write(JSON.stringify({rpcId:body?.rpcId,error:error.message})+'\n');}});});
