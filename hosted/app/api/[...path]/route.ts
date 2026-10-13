import {env} from 'cloudflare:workers';
import {handleApi} from '../../../src/api.js';
export const dynamic='force-dynamic';
export const GET=(request:Request)=>handleApi(request,env.DB);
export const POST=(request:Request)=>handleApi(request,env.DB);
export const DELETE=(request:Request)=>handleApi(request,env.DB);
