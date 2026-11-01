const enc=new TextEncoder(),out=(x,s=200)=>new Response(JSON.stringify(x),{status:s,headers:{"content-type":"application/json"}});
const bytes=x=>new Uint8Array(x);
const b64=x=>btoa(String.fromCharCode(...bytes(x))).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
async function jwt(id,pem){let p=pem.replace(/-----[^-]+-----|\s/g,""),key=await crypto.subtle.importKey("pkcs8",Uint8Array.from(atob(p),x=>x.charCodeAt(0)),{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["sign"]);let n=Math.floor(Date.now()/1000),v=b64(enc.encode('{"alg":"RS256","typ":"JWT"}'))+"."+b64(enc.encode(JSON.stringify({iat:n-60,exp:n+480,iss:String(id)})));return v+"."+b64(await crypto.subtle.sign("RSASSA-PKCS1-v1_5",key,enc.encode(v)))}
async function api(url,method,token,body){return fetch(url,{method,headers:{authorization:"Bearer "+token,accept:"application/vnd.github+json","x-github-api-version":"2022-11-28","content-type":"application/json"},body:JSON.stringify(body)})}
export default{async fetch(req,env){if(req.method!=="POST")return out({error:"method"},405);
let raw=await req.arrayBuffer();if(raw.byteLength>256000)return out({error:"size"},413);
let signature=req.headers.get("x-hub-signature-256");if(!env.WEBHOOK_SECRET||!/^sha256=[a-f0-9]{64}$/.test(signature||""))return out({error:"signature"},401);
let key=await crypto.subtle.importKey("raw",enc.encode(env.WEBHOOK_SECRET),{name:"HMAC",hash:"SHA-256"},false,["sign"]),h=bytes(await crypto.subtle.sign("HMAC",key,raw)),expected="sha256="+[...h].map(x=>x.toString(16).padStart(2,"0")).join("");let mismatch=0;for(let i=0;i<71;i++)mismatch|=expected.charCodeAt(i)^signature.charCodeAt(i);if(mismatch)return out({error:"signature"},401);
let kind=req.headers.get("x-github-event");if(kind==="ping")return out({ok:true});if(!["push","pull_request"].includes(kind))return out({ignored:true});
let b;try{b=JSON.parse(new TextDecoder().decode(raw))}catch{return out({error:"json"},400)}
let r=b.repository,owner=env.GITHUB_OWNER||"usedhonda";if(!r||r.private!==false||r.owner?.login?.toLowerCase()!==owner.toLowerCase()||r.fork||r.archived||!new RegExp("^"+owner+"/[A-Za-z0-9_.-]+$","i").test(r.full_name||""))return out({ignored:true});
let pr=b.pull_request,branch=r.default_branch,p=null;
if(kind==="pull_request"&&["opened","reopened","synchronize"].includes(b.action)&&pr?.base?.ref===branch&&pr?.head?.repo?.full_name===r.full_name&&pr?.user?.login?.toLowerCase()===owner.toLowerCase()&&Number.isSafeInteger(b.number))p={kind,repository:r.full_name,repository_id:r.id,branch,base:pr.base.sha,head:pr.head.sha,pr:b.number};
if(kind==="push"&&b.ref==="refs/heads/"+branch&&!b.deleted)p={kind,repository:r.full_name,repository_id:r.id,branch,base:b.before,head:b.after};
if(!p)return out({ignored:true});if(!/^[a-f0-9]{40}$/i.test(p.base||"")||!/^[a-f0-9]{40}$/i.test(p.head||""))return out({error:"revision"},400);
let delivery=req.headers.get("x-github-delivery");if(!/^[a-f0-9-]{36}$/i.test(delivery||""))return out({error:"delivery"},400);
if(!env.DEDUP||!env.APP_ID||!env.APP_PRIVATE_KEY||!env.CENTRAL_REPO)return out({error:"unconfigured"},503);
try{let insert=await env.DEDUP.prepare("INSERT OR IGNORE INTO deliveries(id,created_at) VALUES(?,?)").bind(delivery,Date.now()).run();if(!insert.meta?.changes)return out({duplicate:true});}catch{return out({error:"dedup"},503)}
try{let id=b.installation?.id;if(!Number.isSafeInteger(id))throw Error("installation");
let app=await jwt(env.APP_ID,env.APP_PRIVATE_KEY),tokenResult=await api("https://api.github.com/app/installations/"+id+"/access_tokens","POST",app,{repositories:[env.CENTRAL_REPO.split("/")[1]],permissions:{contents:"write"}});if(!tokenResult.ok)throw Error("token");let token=(await tokenResult.json()).token;if(!token)throw Error("token");
let dispatched=await api("https://api.github.com/repos/"+env.CENTRAL_REPO+"/dispatches","POST",token,{event_type:"security-review-app-v1",client_payload:{...p,delivery}});
if(dispatched.status!==204)throw Error("dispatch");return out({accepted:true},202)
}catch{try{await env.DEDUP.prepare("DELETE FROM deliveries WHERE id=?").bind(delivery).run()}catch{}return out({error:"dispatch_failed"},503)}
}}