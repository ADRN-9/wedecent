import {createClient} from "npm:@supabase/supabase-js@2";
import {deviceIDFromPublicKey} from "../_shared/port-forward-replay.mjs";
const headers={"Access-Control-Allow-Origin":"https://app.wedecent.com","Access-Control-Allow-Headers":"authorization, apikey, content-type","Access-Control-Allow-Methods":"POST, OPTIONS"};
function reply(b:unknown,s=200){return new Response(JSON.stringify(b),{status:s,headers:{...headers,"Content-Type":"application/json","Cache-Control":"no-store"}})}
function canonical(v:unknown):string{if(v===null||typeof v==="boolean"||typeof v==="string")return JSON.stringify(v);if(typeof v==="number"){if(!Number.isSafeInteger(v))throw Error("unsafe number");return JSON.stringify(v)}if(Array.isArray(v))return "["+v.map(canonical).join(",")+"]";if(typeof v==="object")return "{"+Object.keys(v as object).sort().map(k=>JSON.stringify(k)+":"+canonical((v as Record<string,unknown>)[k])).join(",")+"}";throw Error("invalid value")}
async function digest(v:unknown){const h=new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(canonical(v))));return [...h].map(x=>x.toString(16).padStart(2,"0")).join("")}
function serviceKey(){const k=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");if(k)return k;const x=Deno.env.get("SUPABASE_SECRET_KEYS");if(x){const o=JSON.parse(x);if(o.default)return o.default}throw Error("service key missing")}
function endpoint(v:unknown){if(!v||typeof v!=="object"||Array.isArray(v))return false;const x=v as Record<string,unknown>;return typeof x.device_id==="string"&&/^wd_[a-z2-7]{16}$/.test(x.device_id)&&typeof x.account_id==="string"&&/^[0-9a-f-]{36}$/.test(x.account_id)&&typeof x.organization_id==="string"&&/^[0-9a-f-]{36}$/.test(x.organization_id)&&Number.isSafeInteger(x.revocation_epoch)&&Number(x.revocation_epoch)>=0}
function fromHex(s:string){if(!/^[0-9a-f]{64}$/.test(s))throw Error("invalid digest");return Uint8Array.from(s.match(/../g)!,x=>parseInt(x,16))}
function fromBase64(s:string){if(!/^[A-Za-z0-9+/]{43}=$/.test(s))throw Error("invalid public key");const raw=atob(s);return Uint8Array.from(raw,x=>x.charCodeAt(0))}
function fromBase64Signature(s:string){if(!/^[A-Za-z0-9+/]{86}==$/.test(s))throw Error("invalid signature");const raw=atob(s);return Uint8Array.from(raw,x=>x.charCodeAt(0))}
async function verifyCanonicalCheckpoint(p:Record<string,unknown>,operationID:string){
 const chunks:Uint8Array[]=[];const enc=new TextEncoder();
 const u32=(n:number)=>{const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,false);chunks.push(b)};
 const u64=(n:number)=>{if(!Number.isSafeInteger(n)||n<0)throw Error("invalid revocation epoch");const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,BigInt(n),false);chunks.push(b)};
 const str=(s:string)=>{const b=enc.encode(s);u32(b.length);chunks.push(b)};
 const raw=(b:Uint8Array)=>chunks.push(b);
 const ep=(v:unknown)=>{if(!endpoint(v))throw Error("invalid endpoint");const x=v as Record<string,unknown>;str(String(x.device_id));str(String(x.account_id));str(String(x.organization_id));u64(Number(x.revocation_epoch))};
 const initiator=p.initiator,destination=p.destination,router=p.router;
 str("wedecent-replay-checkpoint-request-v1");u32(1);ep(initiator);ep(destination);
 str(String(p.consuming_device_id));str(String(p.jti));
 const auth=fromHex(String(p.authorization_sha256));raw(auth);
 const route=fromHex(String(p.route_authorization_sha256));const routed=route.some(x=>x!==0);
 if(routed!==(router!==null))throw Error("route binding mismatch");
 if(routed){str("route-authorization-sha256-v1");raw(route);str("route-router-membership-v1");ep(router)}
 const publicKey=fromBase64(String(p.device_public_key));const signature=fromBase64Signature(String(p.device_signature));
 if(await deviceIDFromPublicKey(publicKey)!==p.consuming_device_id)throw Error("device identity mismatch");
 raw(publicKey);const size=chunks.reduce((n,x)=>n+x.length,0);const message=new Uint8Array(size);let offset=0;for(const part of chunks){message.set(part,offset);offset+=part.length}
 const key=await crypto.subtle.importKey("raw",publicKey,{name:"Ed25519"},false,["verify"]);
 if(!await crypto.subtle.verify({name:"Ed25519"},key,signature,message))throw Error("device checkpoint signature rejected");
 const fp=new Uint8Array(await crypto.subtle.digest("SHA-256",message));const prefix=enc.encode("wedecent-checkpoint-finalization-v1\n");const opInput=new Uint8Array(prefix.length+fp.length);opInput.set(prefix);opInput.set(fp,prefix.length);
 const op=new Uint8Array(await crypto.subtle.digest("SHA-256",opInput));const expected=[...op].map(x=>x.toString(16).padStart(2,"0")).join("");
 if(expected!==operationID)throw Error("operation ID does not bind signed checkpoint request");
}
Deno.serve(async req=>{if(req.method==="OPTIONS")return new Response("ok",{headers});if(req.method!=="POST")return reply({error:"method not allowed"},405);try{
const token=req.headers.get("authorization")?.match(/^Bearer\s+([^\s]+)$/i)?.[1];if(!token||token.length>8192)return reply({error:"authentication required"},401);
const raw=await req.text();if(new TextEncoder().encode(raw).length>65536)return reply({error:"request too large"},413);
const url=Deno.env.get("SUPABASE_URL");if(!url)throw Error("URL missing");const admin=createClient(url,serviceKey(),{auth:{persistSession:false,autoRefreshToken:false}});
const {data:auth,error:authErr}=await admin.auth.getUser(token);if(authErr||!auth.user)return reply({error:"invalid user session"},401);
const b=JSON.parse(raw) as Record<string,unknown>;if(Object.keys(b).sort().join(",")!=="operation_id,outcome,payload,payload_sha256,payload_version")return reply({error:"invalid fields"},400);
const id=String(b.operation_id??""),outcome=String(b.outcome??""),sum=String(b.payload_sha256??""),p=b.payload as Record<string,unknown>;
if(!/^[0-9a-f]{64}$/.test(id)||!/^[0-9a-f]{64}$/.test(sum)||b.payload_version!==1||!["finalization_started","membership_unavailable","finalization_failed","finalized","rejected_revocation"].includes(outcome))return reply({error:"invalid request"},400);
if(!p||typeof p!=="object"||Array.isArray(p)||Object.keys(p).sort().join(",")!=="authorization_sha256,consuming_device_id,destination,device_public_key,device_signature,initiator,jti,route_authorization_sha256,router,version"||p.version!==1||!endpoint(p.initiator)||!endpoint(p.destination)||!(p.router===null||endpoint(p.router))||!/^wd_[a-z2-7]{16}$/.test(String(p.consuming_device_id??""))||!/^[A-Za-z0-9_-]{22}$/.test(String(p.jti??""))||!/^[0-9a-f]{64}$/.test(String(p.authorization_sha256??""))||!/^[0-9a-f]{64}$/.test(String(p.route_authorization_sha256??""))||!/^[A-Za-z0-9+/]{43}=$/.test(String(p.device_public_key??""))||!/^[A-Za-z0-9+/]{86}==$/.test(String(p.device_signature??"")))return reply({error:"invalid payload"},400);
if(await digest(p)!==sum)return reply({error:"digest mismatch"},400);
await verifyCanonicalCheckpoint(p,id);
const {data,error}=await admin.rpc("record_checkpoint_finalization",{p_operation_id:id,p_outcome:outcome,p_payload_version:1,p_payload:p,p_payload_sha256:"\\x"+sum,p_actor_id:auth.user.id});
if(error){console.warn("checkpoint audit rejected",{code:error.code});const status=error.code==="42501"?403:error.code==="22023"?400:error.code==="23505"?409:503;return reply({error:status===503?"audit unavailable":"audit rejected"},status)}
const result=Array.isArray(data)?data[0]:data;if(!result||result.operation_id!==id||result.outcome!==outcome||typeof result.record_id!=="string"||typeof result.created_at!=="string"||typeof result.replayed!=="boolean")throw Error("invalid RPC result");return reply(result);
}catch(e){console.error("checkpoint audit failure",e instanceof Error?e.message:"unknown");return reply({error:"audit unavailable"},503)}});