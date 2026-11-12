import http from 'node:http';
import {randomUUID} from 'node:crypto';
import {pathToFileURL} from 'node:url';

/** Photo boundary core. No credentials, Storage paths or signed URLs are exposed. */
const MAX_PHOTO_BYTES = 10 * 1024 * 1024;
const PHOTO_BUCKET = 'detaillane-photos-server-v1';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MIME = new Map([['image/jpeg', ['jpg','jpeg']], ['image/png',['png']], ['image/webp',['webp']]]);
const PHOTO_FIELDS = ['id','organization_id','job_id','stage','mime_type','byte_size','state','version','created_at','updated_at'];
const STATUS = {INVALID:400,UNAUTHENTICATED:401,FORBIDDEN:403,NOT_FOUND:404,CONFLICT:409,TOO_LARGE:413,UNSUPPORTED_MEDIA:415,NETWORK:502,BOUNDARY_INACTIVE:503,ORPHAN_RECONCILIATION:503,RESPONSE_INVALID:502};
class PhotoError extends Error {
 constructor(code, details = {}) { super(code); this.name='PhotoError'; this.code=code; this.details=details; }
}
const fail = (code, details) => { throw new PhotoError(code, details); };
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const validId = value => typeof value === 'string' && UUID.test(value);
function version(value) {
 if(typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value) || !Number.isSafeInteger(Number(value))) fail('INVALID');
 return Number(value);
}
async function limitedBytes(body, limit, declaredLength) {
 if(declaredLength !== null && declaredLength !== undefined && (!/^(0|[1-9][0-9]*)$/.test(String(declaredLength)) || Number(declaredLength)>limit)) fail('TOO_LARGE');
 if(!body) return new Uint8Array();
 const reader=body.getReader();const chunks=[];let size=0;
 try {
  while(true) { const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>limit)fail('TOO_LARGE');chunks.push(value); }
 } catch(error) { try{await reader.cancel();}catch{};throw error instanceof PhotoError?error:new PhotoError('NETWORK'); }
 finally { reader.releaseLock(); }
 const bytes=new Uint8Array(size);let at=0;for(const chunk of chunks){bytes.set(chunk,at);at+=chunk.byteLength;}return bytes;
}
function matchesMime(bytes, mime) {
 if(mime==='image/png')return bytes.length>=8&&[137,80,78,71,13,10,26,10].every((n,i)=>bytes[i]===n);
 if(mime==='image/jpeg')return bytes.length>=3&&bytes[0]===255&&bytes[1]===216&&bytes[2]===255;
 if(mime==='image/webp')return bytes.length>=12&&String.fromCharCode(...bytes.slice(0,4))==='RIFF'&&String.fromCharCode(...bytes.slice(8,12))==='WEBP';
 return false;
}
function checkedPhoto(envelope) {
 const p=envelope?.photo;
 if(envelope?.bucket_id!==PHOTO_BUCKET||!object(p)||!validId(p.id)||!validId(p.job_id)||!validId(p.organization_id)||!MIME.has(p.mime_type)||!Number.isSafeInteger(p.byte_size)||p.byte_size<1||p.byte_size>MAX_PHOTO_BYTES||!Number.isSafeInteger(p.version)||p.version<1||!['pending','ready','failed'].includes(p.state)||!['before','after'].includes(p.stage))fail('RESPONSE_INVALID');
 const expected=p.organization_id+'/'+p.job_id+'/'+p.id+'.';
 if(typeof p.object_path!=='string'||!MIME.get(p.mime_type).some(ext=>p.object_path===expected+ext))fail('RESPONSE_INVALID');
 return p;
}
const publicPhoto = p => Object.fromEntries(PHOTO_FIELDS.filter(k=>p[k]!==undefined).map(k=>[k,p[k]]));
function sameIdentity(a,b){return ['id','organization_id','job_id','object_path','mime_type','byte_size'].every(k=>a[k]===b[k]);}
function authorizedOrigin(origin) {
 try { const u=new URL(origin);return u.origin===origin&&!u.username&&!u.password&&(u.protocol==='https:'||u.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(u.hostname)); }catch{return false;}
}
function createPhotoGateway({backend, allowedOrigins=[], randomUUID=()=>crypto.randomUUID()}={}) {
   if(!backend||!Array.isArray(allowedOrigins)||allowedOrigins.some(o=>!authorizedOrigin(o)))throw new TypeError('Invalid photo gateway configuration');
 const origins=new Set(allowedOrigins);
 async function rpc(actor, action, args={}) {
  const photo=checkedPhoto(await backend.rpc(actor.id,action,args));
  if(args.p_photo_id&&photo.id!==args.p_photo_id)fail('RESPONSE_INVALID');
  if(action==='reserve'&&(photo.job_id!==args.p_job_id||photo.stage!==args.p_stage||photo.mime_type!==args.p_mime_type||photo.byte_size!==args.p_byte_size||photo.state!=='pending'||photo.uploaded_by!==actor.id))fail('RESPONSE_INVALID');
  if(['upload','begin_upload'].includes(action)&&(photo.state!=='pending'||photo.uploaded_by!==actor.id))fail('RESPONSE_INVALID');
  if(['read','finalize','reconcile_finalize'].includes(action)&&photo.state!=='ready')fail('RESPONSE_INVALID');
  if(['claim_delete','delete_metadata'].includes(action)&&photo.state!=='failed')fail('RESPONSE_INVALID');
  return photo;
 }
 function headers(origin) {
  const h=new Headers({'Cache-Control':'private, no-store, max-age=0','Pragma':'no-cache','Expires':'0','Vary':'Authorization, Origin','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none'",'Cross-Origin-Resource-Policy':'same-origin'});
  if(origin&&origins.has(origin)){h.set('Access-Control-Allow-Origin',origin);h.set('Access-Control-Expose-Headers','X-Photo-Version, Content-Length');}
  return h;
 }
 function json(body,status,origin){const h=headers(origin);h.set('Content-Type','application/json; charset=utf-8');return new Response(JSON.stringify(body),{status,headers:h});}
 async function compensate(actor, original) {
  // No service-credential authorization bypass: all reconciliation must reauthorize.
  let latest;
  try { latest=await rpc(actor,'inspect',{p_photo_id:original.id}); }
  catch { fail('ORPHAN_RECONCILIATION',{photoId:original.id}); }
  if(!sameIdentity(original,latest))fail('ORPHAN_RECONCILIATION',{photoId:original.id});
  if(latest.state==='ready')return latest; // A lost finalization response is success.
  // A second upload may still be in flight. Never claim/delete a pending row
  // merely because an HTTP response was lost; retain its identity for management.
  fail('ORPHAN_RECONCILIATION',{photoId:original.id,version:latest.version});
 }
 return async function handle(request) {
  const origin=request.headers.get('origin');
  try {
   if(origin&&!origins.has(origin))fail('FORBIDDEN');
   const url=new URL(request.url),method=request.method;
   if(method==='OPTIONS'){
    const desired=request.headers.get('access-control-request-method');
    const requested=(request.headers.get('access-control-request-headers')||'').toLowerCase().split(',').map(x=>x.trim()).filter(Boolean);
    if(!origin||!['GET','POST','PUT','DELETE'].includes(desired)||requested.some(x=>!['authorization','content-type'].includes(x)))fail('FORBIDDEN');
    const h=headers(origin);h.set('Access-Control-Allow-Methods','GET, POST, PUT, DELETE');h.set('Access-Control-Allow-Headers','Authorization, Content-Type');h.set('Access-Control-Max-Age','0');return new Response(null,{status:204,headers:h});
   }
   if(method==='GET'&&url.pathname==='/health'&&!url.search)return json({service:'detaillane-photo-boundary',status:'running'},200,origin);
   const reserve=method==='POST'&&url.pathname==='/photos/reservations';
   const match=/^\/photos\/([0-9a-f-]+)(\/content|\/reconcile)?$/.exec(url.pathname);
   const reconcile=match?.[2]==='/reconcile'&&method==='POST';
   if(!reserve&&(!match||!validId(match[1])||!((match[2]==='/content'&&['GET','PUT'].includes(method))||reconcile||(!match[2]&&method==='DELETE'))))fail('NOT_FOUND');
   const allowedQuery=method==='PUT'||method==='DELETE'||reconcile?['version']:[];
   for(const key of url.searchParams.keys())if(!allowedQuery.includes(key))fail('INVALID');
   if(allowedQuery.length&&url.searchParams.getAll('version').length!==1)fail('INVALID');
   const expected=allowedQuery.length?version(url.searchParams.get('version')):undefined;
   const auth=request.headers.get('authorization');
   if(!auth||!/^Bearer [A-Za-z0-9._~+\/-]+=*$/.test(auth)||auth.length>16384)fail('UNAUTHENTICATED');
       const actor=await backend.verifyToken(auth.slice(7));if(!validId(actor?.id))fail('UNAUTHENTICATED');
   if(reserve){
    if(!/^application\/json(?:;|$)/i.test(request.headers.get('content-type')||''))fail('UNSUPPORTED_MEDIA');
    const bytes=await limitedBytes(request.body,2048,request.headers.get('content-length'));let value;
    try{value=JSON.parse(new TextDecoder().decode(bytes));}catch{fail('INVALID');}
    if(!object(value)||Object.keys(value).some(k=>!['jobId','stage','mimeType','byteSize'].includes(k))||!validId(value.jobId)||!['before','after'].includes(value.stage)||!MIME.has(value.mimeType)||!Number.isSafeInteger(value.byteSize)||value.byteSize<1||value.byteSize>MAX_PHOTO_BYTES)fail('INVALID');
    const id=randomUUID();if(!validId(id))fail('RESPONSE_INVALID');
    let photo;
    try{photo=await rpc(actor,'reserve',{p_photo_id:id,p_job_id:value.jobId,p_stage:value.stage,p_mime_type:value.mimeType,p_byte_size:value.byteSize});}
    catch(error){
     if(error instanceof PhotoError&&['FORBIDDEN','INVALID','CONFLICT','BOUNDARY_INACTIVE','NOT_FOUND'].includes(error.code))throw error;
     try{photo=await rpc(actor,'inspect',{p_photo_id:id});}catch{fail('ORPHAN_RECONCILIATION',{photoId:id});}
     if(photo.id!==id||photo.job_id!==value.jobId||photo.stage!==value.stage||photo.mime_type!==value.mimeType||photo.byte_size!==value.byteSize||photo.state!=='pending'||photo.uploaded_by!==actor.id)fail('ORPHAN_RECONCILIATION',{photoId:id});
    }
    return json({photo:publicPhoto(photo)},201,origin);
   }
   const id=match[1];
   if(reconcile){
    const envelope=await backend.rpc(actor.id,'reconcile_inspect',{p_photo_id:id});const photo=checkedPhoto(envelope);
    if(photo.id!==id||photo.version!==expected)fail('CONFLICT');
    const operationId=envelope.upload_intent?.operation_id;
    if(photo.state!=='pending'||!validId(operationId))fail('CONFLICT');
    try{
     const file=await backend.download(PHOTO_BUCKET,photo.object_path);const bytes=await limitedBytes(file.body,MAX_PHOTO_BYTES,file.length);
     if(file.mimeType!==photo.mime_type||bytes.length!==photo.byte_size||!matchesMime(bytes,photo.mime_type))fail('RESPONSE_INVALID');
    }catch{fail('ORPHAN_RECONCILIATION',{photoId:id,version:photo.version});}
    const ready=await rpc(actor,'reconcile_finalize',{p_photo_id:id,p_expected_version:expected,p_operation_id:operationId});
    return json({photo:publicPhoto(ready)},200,origin);
   }
   if(method==='GET'){
    const photo=await rpc(actor,'read',{p_photo_id:id});
    const file=await backend.download(PHOTO_BUCKET,photo.object_path);
    const bytes=await limitedBytes(file.body,MAX_PHOTO_BYTES,file.length);
    if(file.mimeType!==photo.mime_type||bytes.byteLength!==photo.byte_size||!matchesMime(bytes,photo.mime_type))fail('RESPONSE_INVALID');
    const rechecked=await rpc(actor,'read',{p_photo_id:id});
    if(!sameIdentity(photo,rechecked)||rechecked.version!==photo.version||rechecked.state!=='ready')fail('CONFLICT');
    const h=headers(origin);h.set('Content-Type',photo.mime_type);h.set('Content-Length',String(bytes.byteLength));h.set('X-Photo-Version',String(photo.version));
    return new Response(bytes,{status:200,headers:h});
   }
   if(method==='PUT'){
    let photo=await rpc(actor,'upload',{p_photo_id:id,p_expected_version:expected});
    if((request.headers.get('content-type')||'').split(';')[0].trim().toLowerCase()!==photo.mime_type)fail('UNSUPPORTED_MEDIA');
    const bytes=await limitedBytes(request.body,MAX_PHOTO_BYTES,request.headers.get('content-length'));
    if(bytes.length!==photo.byte_size||!matchesMime(bytes,photo.mime_type))fail('INVALID');
    // Slow uploads cannot retain authorization across body reception.
    const checked=await rpc(actor,'upload',{p_photo_id:id,p_expected_version:expected});if(!sameIdentity(photo,checked))fail('CONFLICT');photo=checked;
    const operationId=randomUUID();if(!validId(operationId))fail('RESPONSE_INVALID');
    try{await rpc(actor,'begin_upload',{p_photo_id:id,p_expected_version:expected,p_operation_id:operationId});}
    catch(error){
     if(error instanceof PhotoError&&['FORBIDDEN','INVALID','CONFLICT','NOT_FOUND','BOUNDARY_INACTIVE'].includes(error.code))throw error;
           fail('ORPHAN_RECONCILIATION',{photoId:id,version:photo.version});
    }
    try {
     await backend.upload(PHOTO_BUCKET,photo.object_path,bytes,photo.mime_type);
     const ready=await rpc(actor,'finalize',{p_photo_id:id,p_expected_version:expected,p_operation_id:operationId});
     return json({photo:publicPhoto(ready)},200,origin);
    }catch(error){const ready=await compensate(actor,photo);return json({photo:publicPhoto(ready)},200,origin);}
   }
   const claimed=await rpc(actor,'claim_delete',{p_photo_id:id,p_expected_version:expected});
   try {
    await backend.remove(PHOTO_BUCKET,claimed.object_path);
    const removed=await rpc(actor,'delete_metadata',{p_photo_id:id,p_expected_version:claimed.version});
    return json({deleted:true,id:removed.id,organization_id:removed.organization_id,version:removed.version},200,origin);
   }catch{fail('ORPHAN_RECONCILIATION',{photoId:id,version:claimed.version});}
  }catch(error){
   const code=error instanceof PhotoError&&STATUS[error.code]?error.code:'NETWORK';
   const extra={};if(validId(error?.details?.photoId))extra.photoId=error.details.photoId;if(Number.isSafeInteger(error?.details?.version)&&error.details.version>0)extra.version=error.details.version;
   return json({error:{code,message:code,...extra}},STATUS[code]||502,origin);
  }
 };
}

/** Privileged transport, server-only. Every request uses the configured origin. */
const KNOWN_SQL = {'42501':'FORBIDDEN','40001':'CONFLICT','22023':'INVALID','23514':'INVALID','23503':'CONFLICT','55000':'BOUNDARY_INACTIVE','P0002':'NOT_FOUND','02000':'NOT_FOUND'};
function createSupabasePhotoBackend({url,expectedProjectRef,publishableKey,serverKey,fetchImpl=fetch,allowLocal=false}) {
 let origin;
 try{
  const u=new URL(url),local=allowLocal&&expectedProjectRef==='local'&&u.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(u.hostname);
  if((!local&&(u.protocol!=='https:'||u.hostname!==expectedProjectRef+'.supabase.co'))||u.origin!==url||u.username||u.password||u.search||u.hash)throw Error();origin=u.origin;
  if(typeof publishableKey!=='string'||!publishableKey||typeof serverKey!=='string'||serverKey===publishableKey||!serverKey)throw Error();
  if(!publishableKey.startsWith('sb_publishable_')){const p=publishableKey.split('.');if(p.length!==3||JSON.parse(Buffer.from(p[1],'base64url').toString()).role!=='anon')throw Error();}
  if(!serverKey.startsWith('sb_secret_')){
   const parts=serverKey.split('.');if(parts.length!==3||JSON.parse(Buffer.from(parts[1],'base64url').toString()).role!=='service_role')throw Error();
  }
 }catch{throw new TypeError('Invalid server photo configuration');}
 async function request(path,{method='GET',body,token=serverKey,key=serverKey,contentType='application/json',binary=false}={}) {
  if(typeof path!=='string'||!path.startsWith('/')||path.startsWith('//'))throw new PhotoError('INVALID');
  const headers={apikey:key,'Cache-Control':'no-cache, no-store','Pragma':'no-cache'};
  if(token!==serverKey||!serverKey.startsWith('sb_secret_'))headers.Authorization='Bearer '+token;
  if(body!==undefined)headers['Content-Type']=contentType;
  if(binary&&method==='POST'){headers['x-upsert']='false';headers['Cache-Control']='max-age=0';}
  let response;
  try{response=await fetchImpl(origin+path,{method,headers,body:body===undefined?undefined:binary?body:JSON.stringify(body),cache:'no-store',credentials:'omit',redirect:'error',signal:AbortSignal.timeout(30000)});}catch{throw new PhotoError('NETWORK');}
  if(response.status>=300&&response.status<400)throw new PhotoError('NETWORK');
  if(binary&&method==='GET'&&response.ok)return response;
  const raw=await limitedBytes(response.body,65536,response.headers.get('content-length'));let data=null;
  try{data=raw.length?JSON.parse(new TextDecoder().decode(raw)):null;}catch{throw new PhotoError('RESPONSE_INVALID');}
  return {ok:response.ok,status:response.status,data};
 }
 function expect(r){
     if(r.ok)return r.data;
  if(KNOWN_SQL[r.data?.code])throw new PhotoError(KNOWN_SQL[r.data.code]);
  if(r.status===404)throw new PhotoError('NOT_FOUND');
  if(r.status===401||r.status===403)throw new PhotoError('FORBIDDEN');
  if(r.status===409)throw new PhotoError('CONFLICT');
  if(r.status===413)throw new PhotoError('TOO_LARGE');
  if(r.status===415)throw new PhotoError('UNSUPPORTED_MEDIA');
  throw new PhotoError('NETWORK');
 }
 const path=(bucket,name)=>{
  if(bucket!==PHOTO_BUCKET||typeof name!=='string'||!name.split('/').every(p=>p&&p!=='.'&&p!=='..'))throw new PhotoError('INVALID');
  return encodeURIComponent(bucket)+'/'+name.split('/').map(encodeURIComponent).join('/');
 };
 return {
  async verifyToken(token){
   const r=await request('/auth/v1/user',{token,key:publishableKey});
   if(!r.ok)throw new PhotoError(r.status===401||r.status===403?'UNAUTHENTICATED':'NETWORK');
   return {id:r.data?.id};
  },
  async rpc(actor,action,args={}){
   // Only gateway-verified identity reaches p_actor, never request JSON fields.
   return expect(await request('/rest/v1/rpc/photo_server_rpc',{method:'POST',body:{...args,p_actor:actor,p_action:action}}));
  },
  async status(){return expect(await request('/rest/v1/rpc/photo_server_status',{method:'POST',body:{}}));},
  async upload(bucket,name,bytes,mime){expect(await request('/storage/v1/object/'+path(bucket,name),{method:'POST',body:bytes,contentType:mime,binary:true}));},
  async download(bucket,name){
   // This is defense in depth for the INTERNAL privileged request, not the user
   // boundary: membership has already been checked and is checked again below.
   const r=await request('/storage/v1/object/authenticated/'+path(bucket,name)+'?photo_boundary_read='+randomUUID(),{binary:true});
   if(!(r instanceof Response)) {expect(r);throw new PhotoError('RESPONSE_INVALID');}
   const length=r.headers.get('content-length');if(length!==null&&(!/^[0-9]+$/.test(length)||Number(length)>MAX_PHOTO_BYTES)){try{await r.body?.cancel();}catch{}throw new PhotoError('TOO_LARGE');}
   return {body:r.body,mimeType:(r.headers.get('content-type')||'').split(';')[0].toLowerCase(),length};
  },
  async remove(bucket,name){
   path(bucket,name);const data=expect(await request('/storage/v1/object/'+encodeURIComponent(bucket),{method:'DELETE',body:{prefixes:[name]}}));
   if(!Array.isArray(data)||data.some(row=>row.name!==name))throw new PhotoError('RESPONSE_INVALID');
  }
 };
}

/** Explicit standalone launcher. Never imported by the application. */
function bodyStream(incoming){
 let controller;const data=chunk=>{controller.enqueue(new Uint8Array(chunk));if(controller.desiredSize<=0)incoming.pause();};
 const end=()=>{detach();controller.close();};const error=()=>{detach();controller.error(new Error('Request stream failed'));};
 const detach=()=>{incoming.off('data',data);incoming.off('end',end);incoming.off('error',error);incoming.off('aborted',error);};
 return new ReadableStream({start(c){controller=c;incoming.pause();incoming.on('data',data);incoming.once('end',end);incoming.once('error',error);incoming.once('aborted',error);},pull(){incoming.resume();},cancel(){detach();incoming.pause();}});
}
function createHttpPhotoServer(handler){
 const server=http.createServer(async(req,res)=>{
  const abort=new AbortController();const close=()=>{if(!res.writableFinished)abort.abort();};req.once('aborted',close);res.once('close',close);
     try{
   if(req.headers.authorization&&Array.isArray(req.headers.authorization))throw Error();
   const count=req.rawHeaders.filter((_,i)=>i%2===0&&req.rawHeaders[i].toLowerCase()==='authorization').length;if(count>1)throw Error();
   const url=new URL(req.url,'http://photo-boundary.local');if(!req.url?.startsWith('/')||req.url.startsWith('//'))throw Error();
   const init={method:req.method,headers:req.headers,signal:abort.signal};if(!['GET','HEAD'].includes(req.method)){init.body=bodyStream(req);init.duplex='half';}
   const response=await handler(new Request(url,init));
   if(abort.signal.aborted||res.destroyed)throw Error();
   res.writeHead(response.status,Object.fromEntries(response.headers));
   if(response.body){
    const reader=response.body.getReader();let complete=false;
    try{while(true){if(abort.signal.aborted||res.destroyed)throw Error();const {done,value}=await reader.read();if(done){complete=true;break;}
     if(!res.write(value))await new Promise((resolve,reject)=>{
      const cleanup=()=>{res.off('drain',drain);res.off('close',closed);res.off('error',closed);};
      const drain=()=>{cleanup();resolve();};const closed=()=>{cleanup();reject(new Error('Response closed'));};
      res.once('drain',drain);res.once('close',closed);res.once('error',closed);
      if(res.destroyed)closed();
     });
    }}finally{if(!complete){try{await reader.cancel();}catch{}}reader.releaseLock();}
   }
   res.end();
  }catch{
   if(res.destroyed)return;
   if(!res.headersSent)res.writeHead(400,{'Content-Type':'application/json','Cache-Control':'private, no-store, max-age=0','Vary':'Authorization, Origin'});
   res.end('{"error":{"code":"INVALID","message":"INVALID"}}');
  }finally{req.off('aborted',close);res.off('close',close);}
 });
 server.requestTimeout=120000;server.headersTimeout=15000;server.maxHeadersCount=32;return server;
}
function startPhotoServer(env=process.env){
 if(env.DL_PHOTO_SERVER_START!=='YES')throw new Error('Photo server is disabled; explicit DL_PHOTO_SERVER_START=YES required');
 if(Number(process.versions.node.split('.')[0])<20)throw new Error('Node 20 or newer required');
 const port=Number(env.DL_PHOTO_SERVER_PORT||8787);if(!Number.isSafeInteger(port)||port<1||port>65535)throw new Error('Invalid photo server port');
 const host=env.DL_PHOTO_SERVER_HOST||'127.0.0.1';
 const allowedOrigins=(env.DL_PHOTO_ALLOWED_ORIGINS||'').split(',').filter(Boolean);
 if(!allowedOrigins.length)throw new Error('Explicit allowed origins required');
 const backend=createSupabasePhotoBackend({url:env.SUPABASE_URL,expectedProjectRef:env.DL_EXPECTED_PROJECT_REF,publishableKey:env.SUPABASE_PUBLISHABLE_KEY,serverKey:env.SUPABASE_SERVER_KEY,allowLocal:env.DL_PHOTO_ALLOW_LOCAL==='YES'});
 const server=createHttpPhotoServer(createPhotoGateway({backend,allowedOrigins}));server.listen(port,host);return server;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 try{const server=startPhotoServer({...process.env,DL_PHOTO_SERVER_HOST:process.env.DL_PHOTO_SERVER_HOST||(process.env.RENDER==='true'?'0.0.0.0':'127.0.0.1'),DL_PHOTO_SERVER_PORT:process.env.DL_PHOTO_SERVER_PORT||process.env.PORT||'8787'});server.on('listening',()=>process.stdout.write('DetailLane photo boundary listening. No credentials logged.\n'));server.on('error',()=>{process.stderr.write('Photo server failed to listen.\n');process.exitCode=1;});}
 catch{process.stderr.write('Photo server configuration invalid or activation gate disabled.\n');process.exitCode=2;}
}
