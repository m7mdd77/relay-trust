import {randomBytes,createHash,timingSafeEqual} from 'node:crypto';
import {Sandbox} from './sandbox.js';
const hash=value=>createHash('sha256').update(value).digest('hex');
const equal=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Cross-Origin-Resource-Policy':'same-origin'};
export async function handleApi(request,db,{clock=()=>Date.now()}={}) {
  const url=new URL(request.url),path=url.pathname;
  const json=(status,data,extra={})=>new Response(JSON.stringify(data),{status,headers:{...headers,'Content-Type':'application/json; charset=utf-8',...extra}});
  try {
    if(!db)return json(503,{error:'Sandbox storage unavailable.'});
    const origin=request.headers.get('Origin'),site=request.headers.get('Sec-Fetch-Site');
    if((origin&&origin!==url.origin)||site==='cross-site')return json(403,{error:'Cross-origin request denied.'});
    if(!['GET','POST'].includes(request.method))return json(405,{error:'Method not allowed.'});
    if(!['/api/state','/api/export','/api/prepare','/api/execute','/api/trust','/api/reset'].includes(path)||url.search)return json(404,{error:'Route not found.'});
    const secure=url.protocol==='https:',name=secure?'__Host-relay-session':'relay-session';
    const cookie=(request.headers.get('Cookie')||'').split(';').map(v=>v.trim()).find(v=>v.startsWith(name+'='))?.slice(name.length+1);
    const cookieValue=typeof cookie==='string'&&/^[a-f0-9]{64}$/.test(cookie)?cookie:null;
    let id=cookieValue?hash(cookieValue):null,row=id?await db.prepare('SELECT revision,expires,data FROM relay_sandboxes WHERE id=? AND expires>?').bind(id,clock()).first():null,setCookie;
    const newSession=async()=>{
      const secret=randomBytes(32).toString('hex');id=hash(secret);const sandbox=Sandbox.create(clock),expires=clock()+86400000;
      const inserted=await db.batch([db.prepare('DELETE FROM relay_sandboxes WHERE id IN (SELECT id FROM relay_sandboxes WHERE expires<? LIMIT 50)').bind(clock()),db.prepare('INSERT INTO relay_sandboxes(id,revision,expires,data) SELECT ?,0,?,? WHERE (SELECT COUNT(*) FROM relay_sandboxes WHERE expires>?)<256').bind(id,expires,JSON.stringify(sandbox.data),clock())]);
      if(inserted[1].meta.changes!==1)throw Object.assign(new Error('The public lab is at sandbox capacity. Existing sessions still work; try again later.'),{status:503});
      row={revision:0,expires,data:JSON.stringify(sandbox.data)};setCookie=`${name}=${secret}; Path=/; Max-Age=86400; HttpOnly; SameSite=Strict${secure?'; Secure':''}`;return sandbox;
    };
    if(request.method==='GET') {
      if(!['/api/state','/api/export'].includes(path))return json(405,{error:'POST required.'});
      if(!row){if(path==='/api/export')return json(403,{error:'Open your sandbox first.'});await newSession();}
      const sandbox=new Sandbox(JSON.parse(row.data),clock),state=sandbox.state();return json(200,path==='/api/state'?{...state,token:sandbox.data.token}:{format:'relay-public-snapshot/v1',...state},setCookie?{'Set-Cookie':setCookie}:{});
    }
    if(origin!==url.origin)return json(403,{error:'Same-origin mutation required.'});if(!row)return json(403,{error:'Open your sandbox first.'});
    if(request.headers.get('Content-Type')!=='application/json')return json(415,{error:'Use application/json.'});
    if(Number(request.headers.get('Content-Length')||0)>4096)return json(413,{error:'Request too large.'});
    const reader=request.body?.getReader();let bytes=0,text='';if(!reader)return json(400,{error:'JSON body required.'});const decoder=new TextDecoder();
    while(true){const {done,value}=await reader.read();if(done)break;bytes+=value.length;if(bytes>4096){await reader.cancel();return json(413,{error:'Request too large.'});}text+=decoder.decode(value,{stream:true});}text+=decoder.decode();
    let body;try{body=JSON.parse(text);}catch{return json(400,{error:'Invalid JSON.'});}if(!body||typeof body!=='object'||Array.isArray(body))return json(400,{error:'JSON object required.'});
    const keys=Object.keys(body).join(',');
    if(path==='/api/prepare'&&(keys!=='scenario'||!['allowed','scope','spoof','tampered','expired','audience'].includes(body.scenario)))return json(400,{error:'Choose a supported scenario.'});
    if(path==='/api/execute'&&(keys!=='id'||typeof body.id!=='string'||!/^[a-f0-9-]{36}$/.test(body.id)))return json(400,{error:'Valid task ID required.'});
    if(path==='/api/trust'&&(keys!=='mode'||!['grant','narrow','revoke'].includes(body.mode)))return json(400,{error:'Choose grant, narrow, or revoke.'});
    if(path==='/api/reset'&&keys!=='')return json(400,{error:'Empty reset object required.'});if(['/api/state','/api/export'].includes(path))return json(405,{error:'GET required.'});
    // An atomic revision-guarded write commits decision + quota + effect together.
    // Conflicts reload state and repeat every trust check before attempting a write.
    for(let attempt=0;attempt<6;attempt++){
      if(attempt)row=await db.prepare('SELECT revision,expires,data FROM relay_sandboxes WHERE id=? AND expires>?').bind(id,clock()).first();
      if(!row)return json(403,{error:'Sandbox expired. Reload to create a new one.'});const sandbox=new Sandbox(JSON.parse(row.data),clock);
      if(!equal(request.headers.get('X-Demo-Token'),sandbox.data.token))return json(403,{error:'Sandbox token required.'});sandbox.rate();
      if(path==='/api/reset'){const fresh=await newSession();return json(200,{...fresh.state(),token:fresh.data.token},{'Set-Cookie':setCookie});}
      const result=path==='/api/prepare'?sandbox.prepare(body.scenario):path==='/api/trust'?sandbox.manage(body.mode):sandbox.execute(body.id);
      const deadline=result.status==='executed'?Math.min(result.decision.request.payload.expiresAt,result.decision.delegation.payload.expiresAt,result.decision.attestation.payload.expiresAt):row.expires;
      const changed=await db.prepare("UPDATE relay_sandboxes SET data=?,revision=revision+1 WHERE id=? AND revision=? AND expires>? AND ?>(julianday('now')-2440587.5)*86400000").bind(JSON.stringify(sandbox.data),id,row.revision,clock(),deadline).run();
      if(changed.meta.changes===1)return json(result.status==='blocked'?409:200,result);
    }
    return json(409,{error:'Sandbox changed concurrently. Retry the same task.'});
  }catch(error){return json(error.status||500,{error:error.status?error.message:'Sandbox temporarily unavailable. Reload or try again.'});}
}
