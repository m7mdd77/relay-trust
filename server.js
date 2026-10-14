import {createServer} from 'node:http';
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {randomBytes, timingSafeEqual} from 'node:crypto';
import {resolve} from 'node:path';
import {TrustStore} from './src/store.js';
import {AgentSession} from './src/agent-session.js';

export function createApp({dbPath=resolve('.local/trust.sqlite'),recordingDirectory=resolve('.local/recordings')}={}) {
  const store=new TrustStore(dbPath),token=randomBytes(32).toString('hex');
  const agents=new AgentSession();
  const assets=new Map([['/',['index.html','text/html; charset=utf-8']],['/app.js',['app.js','text/javascript; charset=utf-8']],['/agents.js',['agents.js','text/javascript; charset=utf-8']],['/style.css',['style.css','text/css; charset=utf-8']]].map(([route,[file,type]])=>[route,{data:readFileSync(new URL(`./public/${file}`,import.meta.url)),type}]));
  const rates=new Map();
  const server=createServer(async(req,res)=>{
    const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",'Permissions-Policy':'camera=(), microphone=(), geolocation=()','Cross-Origin-Resource-Policy':'same-origin'};
    const send=(status,data)=>{if(res.destroyed)return;res.writeHead(status,{...headers,'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(data));};
    try {
      const port=server.address().port;
      const validHosts=[`127.0.0.1:${port}`,`localhost:${port}`];
      if(!validHosts.includes(req.headers.host)) return send(403,{error:'Untrusted Host.'});
      if(req.headers.origin && req.headers.origin!==`http://${req.headers.host}`)return send(403,{error:'Cross-origin request denied.'});
      if(req.headers['sec-fetch-site']==='cross-site')return send(403,{error:'Cross-site request denied.'});
      if(req.url.includes('?') || req.url.includes('%') || req.url.includes('..'))return send(404,{error:'Route not found.'});
      if(req.method==='GET') {
        if(req.url==='/api/agent-state')return send(200,agents.state());
        if(req.url==='/api/state')return send(200,{...store.state(),token});
        if(req.url==='/api/export')return send(200,{format:'relay-public-snapshot/v1',...store.state()});
        const asset=assets.get(req.url);
        if(!asset)return send(404,{error:'Route not found.'});
        res.writeHead(200,{...headers,'Content-Type':asset.type});return res.end(asset.data);
      }
      if(req.method!=='POST')return send(405,{error:'Method not allowed.'});
      if(req.headers.origin!==`http://${req.headers.host}`)return send(403,{error:'Same-origin mutation required.'});
      const supplied=req.headers['x-demo-token'];
      if(typeof supplied!=='string'||supplied.length!==token.length || !timingSafeEqual(Buffer.from(supplied),Buffer.from(token)))return send(403,{error:'Demo session token required.'});
      if(req.url==='/api/recording'){
        if(req.headers['content-type']!=='video/webm')return send(415,{error:'WebM recording required.'});
        const chunks=[];let bytes=0;
        for await(const chunk of req){bytes+=chunk.length;if(bytes>64*1024*1024){send(413,{error:'Recording exceeds 64 MB.'});req.resume();return;}chunks.push(chunk);}
        const video=Buffer.concat(chunks);
        if(video.length<16||video.subarray(0,4).toString('hex')!=='1a45dfa3')return send(400,{error:'Invalid WebM recording.'});
        mkdirSync(recordingDirectory,{recursive:true});const filename=`relay-trust-live-${Date.now()}.webm`;writeFileSync(resolve(recordingDirectory,filename),video,{flag:'wx'});
        return send(201,{saved:true,filename,bytes:video.length});
      }
      if(req.headers['content-type']!=='application/json')return send(415,{error:'Use application/json.'});
      const window=Math.floor(Date.now()/60000),bucket=rates.get(window)||0;
      if(bucket>=120)return send(429,{error:'Demo request limit reached. Try next minute.'});
      rates.clear();rates.set(window,bucket+1);
      let data='',size=0;
      for await(const chunk of req){size+=chunk.length;if(size>4096){send(413,{error:'Request too large.'});req.resume();return;}data+=chunk;}
      let body;try{body=JSON.parse(data);}catch{return send(400,{error:'Invalid JSON.'});}
      if(!body || Array.isArray(body)||typeof body!=='object')return send(400,{error:'JSON object required.'});
      const keys=Object.keys(body);
      if(req.url==='/api/agents'){
        if(keys.join(',')!=='mode'||!['run','execute','replay','spoof','prepare','revoke'].includes(body.mode))return send(400,{error:'Choose an agent operation.'});
        if(!process.env.RELAY_AGENT_ENV)return send(503,{error:'Configure RELAY_AGENT_ENV for the local AI agent processes.'});
        try{return send(200,await agents.act(body.mode));}catch(e){return send(502,{error:e.message});}
      }
      if(req.url==='/api/prepare') {
        if(keys.join(',')!=='scenario'||!['allowed','scope','spoof','tampered','expired','audience'].includes(body.scenario))return send(400,{error:'Choose a supported scenario.'});
        return send(200,store.prepare(body.scenario));
      }
      if(req.url==='/api/execute') {
        if(keys.join(',')!=='id'||typeof body.id!=='string'||!/^[a-f0-9-]{36}$/.test(body.id))return send(400,{error:'Valid task ID required.'});
        const result=store.execute(body.id);return send(result.status==='blocked'?409:200,result);
      }
      if(req.url==='/api/trust') {
        if(keys.join(',')!=='mode'||!['grant','narrow','revoke'].includes(body.mode))return send(400,{error:'Choose grant, narrow, or revoke.'});
        return send(200,store.manage(body.mode));
      }
      return send(404,{error:'Route not found.'});
    }catch(e){send(e.status||500,{error:e.status?e.message:'Internal error.'});}
  });
  server.requestTimeout=10000;server.headersTimeout=10000;
  server.on('close',()=>agents.close());
  return {server,store};
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const port=Number(process.env.PORT||3250);
  if(!Number.isInteger(port)||port<1024||port>65535)throw new Error('Invalid PORT.');
  const {server,store}=createApp({dbPath:process.env.RELAY_DB||resolve('.local/trust.sqlite'),recordingDirectory:process.env.RELAY_RECORDING_DIRECTORY||resolve('.local/recordings')});
  server.listen(port,'127.0.0.1',()=>console.log(`Relay Trust · http://127.0.0.1:${port} · synthetic local demo`));
  const shutdown=()=>server.close(()=>{store.close();process.exit(0);});
  process.on('SIGINT',shutdown);process.on('SIGTERM',shutdown);
}
