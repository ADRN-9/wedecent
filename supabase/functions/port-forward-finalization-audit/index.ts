import {createClient} from "npm:@supabase/supabase-js@2";
import {deviceIDFromPublicKey} from "../_shared/port-forward-replay.mjs";
const headers={"Access-Control-Allow-Origin":"https://app.wedecent.com","Access-Control-Allow-Headers":"authorization, apikey, content-type","Access-Control-Allow-Methods":"POST, OPTIONS"};
function reply(b:unknown,s=200){return new Response(JSON.stringify(b),{status:s,headers:{...headers,"Content-Type":"application/json","Cache-Control":"no-store"}})}
export function canonical(v:unknown):string{if(v===null||typeof v==="boolean"||typeof v==="string")return JSON.stringify(v);if(typeof v==="number"){if(!Number.isSafeInteger(v))throw Error("unsafe number");return JSON.stringify(v)}if(Array.isArray(v))return "["+v.map(canonical).join(",")+"]";if(typeof v==="object")return "{"+Object.keys(v as object).sort().map(k=>JSON.stringify(k)+":"+canonical((v as Record<string,unknown>)[k])).join(",")+"}";throw Error("invalid value")}
export async function digest(v:unknown){const h=new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(canonical(v))));return [...h].map(x=>x.toString(16).padStart(2,"0")).join("")}
function serviceKey(){const k=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");if(k)return k;const x=Deno.env.get("SUPABASE_SECRET_KEYS");if(x){const o=JSON.parse(x);if(o.default)return o.default}throw Error("service key missing")}
async function readBoundedBody(req:Request):Promise<string|null>{
 const reader=req.body?.getReader();if(!reader)return "";
 const chunks:Uint8Array[]=[];let total=0;
 try{for(;;){const part=await reader.read();if(part.done)break;total+=part.value.byteLength;if(total>65536){await reader.cancel();return null}chunks.push(part.value)}}
 finally{reader.releaseLock()}
 const body=new Uint8Array(total);let offset=0;for(const chunk of chunks){body.set(chunk,offset);offset+=chunk.byteLength}
 return new TextDecoder("utf-8",{fatal:true}).decode(body);
}
function endpoint(v:unknown){if(!v||typeof v!=="object"||Array.isArray(v))return false;const x=v as Record<string,unknown>;return Object.keys(x).sort().join(",")==="account_id,device_id,organization_id,revocation_epoch"&&typeof x.device_id==="string"&&/^wd_[a-z2-7]{16}$/.test(x.device_id)&&typeof x.account_id==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(x.account_id)&&typeof x.organization_id==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(x.organization_id)&&Number.isSafeInteger(x.revocation_epoch)&&Number(x.revocation_epoch)>=0}
function fromHex(s:string){if(!/^[0-9a-f]{64}$/.test(s))throw Error("invalid digest");return Uint8Array.from(s.match(/../g)!,x=>parseInt(x,16))}
function fromBase64(s:string){if(!/^[A-Za-z0-9+/]{43}=$/.test(s))throw Error("invalid public key");const raw=atob(s);if(btoa(raw)!==s)throw Error("non-canonical public key");return Uint8Array.from(raw,x=>x.charCodeAt(0))}
function fromBase64Signature(s:string){if(!/^[A-Za-z0-9+/]{86}==$/.test(s))throw Error("invalid signature");const raw=atob(s);if(btoa(raw)!==s)throw Error("non-canonical signature");return Uint8Array.from(raw,x=>x.charCodeAt(0))}
async function verifyCanonicalCheckpoint(p:Record<string,unknown>,operationID:string):Promise<Uint8Array>{
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
 if(routed){
  if(typeof p.route_authorization_json!=="string"||typeof p.route_authorization_id!=="string"||typeof p.route_authorization_jti!=="string")throw Error("route grant identity missing");
  if([...(await sha(enc.encode(p.route_authorization_json)))].map(x=>x.toString(16).padStart(2,"0")).join("")!==String(p.route_authorization_sha256))throw Error("route authorization digest mismatch");
  const routeAuth=JSON.parse(p.route_authorization_json) as JsonObject;
  if(!isObject(routeAuth.claims)||!isObject(routeAuth.claims.route)||routeAuth.claims.jti!==p.route_authorization_jti||
     routeAuth.claims.router!==(router as JsonObject).device_id||routeAuth.claims.route.id!==p.route_authorization_id||
     routeAuth.claims.route.source!==(initiator as JsonObject).device_id||routeAuth.claims.route.destination!==(destination as JsonObject).device_id)throw Error("route authorization does not match stored route participants");
  str("route-authorization-sha256-v1");raw(route);str("route-router-membership-v1");ep(router)
 }else if(p.route_authorization_json!==""||p.route_authorization_id!==""||p.route_authorization_jti!=="")throw Error("unexpected route authorization fields")
 const publicKey=fromBase64(String(p.device_public_key));const signature=fromBase64Signature(String(p.device_signature));
 if(await deviceIDFromPublicKey(publicKey)!==p.consuming_device_id)throw Error("device identity mismatch");
 raw(publicKey);const size=chunks.reduce((n,x)=>n+x.length,0);const message=new Uint8Array(size);let offset=0;for(const part of chunks){message.set(part,offset);offset+=part.length}
 const key=await crypto.subtle.importKey("raw",publicKey,{name:"Ed25519"},false,["verify"]);
 if(!await crypto.subtle.verify({name:"Ed25519"},key,signature,message))throw Error("device checkpoint signature rejected");
 const fp=new Uint8Array(await crypto.subtle.digest("SHA-256",message));const prefix=enc.encode("wedecent-checkpoint-finalization-v1\n");const opInput=new Uint8Array(prefix.length+fp.length);opInput.set(prefix);opInput.set(fp,prefix.length);
 const op=new Uint8Array(await crypto.subtle.digest("SHA-256",opInput));const expected=[...op].map(x=>x.toString(16).padStart(2,"0")).join("");
 if(expected!==operationID)throw Error("operation ID does not bind signed checkpoint request");
 return fp;
}

type JsonObject=Record<string,unknown>;
function isObject(v:unknown):v is JsonObject{return !!v&&typeof v==="object"&&!Array.isArray(v)}
function exact(v:unknown,keys:string[]){return isObject(v)&&Object.keys(v).sort().join(",")===keys.slice().sort().join(",")}
function b64(s:unknown,size:number){if(typeof s!=="string")throw Error("invalid base64");const raw=atob(s);if(raw.length!==size||btoa(raw)!==s)throw Error("invalid base64");return Uint8Array.from(raw,x=>x.charCodeAt(0))}
export function b64url(b:Uint8Array){let s="";for(const x of b)s+=String.fromCharCode(x);return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")}
export function u32(n:number){if(!Number.isSafeInteger(n)||n<0||n>0xffffffff)throw Error("invalid uint32");const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,false);return b}
export function u64(n:unknown){if(typeof n!=="number"||!Number.isSafeInteger(n)||n<0)throw Error("invalid uint64");const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,BigInt(n),false);return b}
function i64(n:unknown){if(typeof n!=="number"||!Number.isSafeInteger(n))throw Error("invalid int64");const b=new Uint8Array(8);new DataView(b.buffer).setBigInt64(0,BigInt(n),false);return b}
const enc=new TextEncoder();
export function str(s:unknown){if(typeof s!=="string")throw Error("invalid string");const b=enc.encode(s);return concat(u32(b.length),b)}
export function concat(...parts:Uint8Array[]){const out=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let i=0;for(const p of parts){out.set(p,i);i+=p.length}return out}
export function h32(v:unknown){return fromHex(String(v))}
export async function sha(b:Uint8Array){return new Uint8Array(await crypto.subtle.digest("SHA-256",b))}
async function verifyEd25519(publicKey:Uint8Array,signature:Uint8Array,message:Uint8Array){const key=await crypto.subtle.importKey("raw",publicKey,{name:"Ed25519"},false,["verify"]);if(!await crypto.subtle.verify({name:"Ed25519"},key,signature,message))throw Error("signature rejected")}
export async function providerKeyID(publicKey:Uint8Array){return "ed25519-"+b64url(await sha(publicKey))}
function endpointScope(v:unknown){if(!endpoint(v))throw Error("invalid endpoint");const x=v as JsonObject;return {device_id:String(x.device_id),account_id:String(x.account_id),organization_id:String(x.organization_id),revocation_epoch:Number(x.revocation_epoch)}}
function sameScope(a:unknown,b:unknown){if(!isObject(a)||!isObject(b))return false;return a.device_id===b.device_id&&a.account_id===b.account_id&&a.organization_id===b.organization_id}
export function checkpointReceiptMessage(r:JsonObject){return concat(enc.encode("wedecent-replay-checkpoint-receipt-v1\n"),u32(Number(r.version)),str(r.device_id),str(r.account_id),str(r.organization_id),str(r.jti),str(r.provider_key_id),u64(r.generation),h32(r.authorization_sha256),h32(r.request_sha256),h32(r.previous_hash),h32(r.record_hash))}
export function checkpointHeadMessage(h:JsonObject){return concat(enc.encode("wedecent-replay-checkpoint-head-v1\n"),u32(Number(h.version)),str(h.device_id),str(h.account_id),str(h.organization_id),str(h.provider_key_id),u64(h.generation),u64(h.revocation_epoch),h32(h.record_hash))}
export function witnessAckMessage(a:JsonObject){const s=a.scope as JsonObject;return concat(enc.encode("wedecent-independent-witness-ack-v2\n"),str(a.witness_id),str(s.device_id),str(s.account_id),str(s.organization_id),str(a.jti),h32(a.request_sha256),h32(a.primary_receipt_sha256),str(a.decision),str(a.witness_key_id))}
export function witnessHeadMessage(h:JsonObject){const s=h.scope as JsonObject;return concat(enc.encode("wedecent-independent-witness-head-v1\n"),str(h.witness_id),str(s.device_id),str(s.account_id),str(s.organization_id),u64(h.generation),h32(h.record_hash),u64(h.primary_generation),h32(h.primary_head),u64(h.revocation_epoch),str(h.witness_key_id))}
export async function verifyRouteAuthorization(auth:JsonObject,p:JsonObject){
 const keyID=Deno.env.get("WEDECENT_ROUTE_AUTH_KEY_ID"),rawKey=Deno.env.get("WEDECENT_ROUTE_AUTH_PUBLIC_KEY");
 if(!keyID||!rawKey)throw Error("independent route authorization trust anchor missing");
 if(auth.kid!==keyID||!exact(auth,["kid","claims","signature"])||!isObject(auth.claims)||
   !exact(auth.claims,["v","iss","aud","permission","jti","router","route","iat_unix_ms","exp_unix_ms"])||
   !isObject(auth.claims.route)||!exact(auth.claims.route,["ID","Source","Destination","Hops","ExpiresAt"]))throw Error("route authorization key or claims mismatch");
 const c=auth.claims,r=c.route,hops=r.Hops;
 if(c.v!==1||c.iss!=="wedecent-control-plane"||c.aud!=="wedecent-mesh-router"||c.permission!=="mesh.forward"||
   typeof c.jti!=="string"||!/^[A-Za-z0-9_-]{22}$/.test(c.jti)||typeof c.router!=="string"||
   typeof r.ID!=="string"||r.ID.length===0||!Array.isArray(hops)||hops.length!==2)throw Error("invalid route authorization claims");
 const jtiRaw=atob(c.jti.replace(/-/g,"+").replace(/_/g,"/")+"==");
 if(jtiRaw.length!==16||b64url(Uint8Array.from(jtiRaw,x=>x.charCodeAt(0)))!==c.jti)throw Error("invalid route authorization JTI");
 const issued=Number(c.iat_unix_ms),expires=Number(c.exp_unix_ms),routeExpires=Date.parse(String(r.ExpiresAt));
 if(!Number.isSafeInteger(issued)||!Number.isSafeInteger(expires)||issued<=0||expires<=issued||expires-issued>120000||
   !Number.isSafeInteger(routeExpires)||routeExpires!==expires)throw Error("invalid route authorization lifetime");
 if(r.Source!==(p.initiator as JsonObject).device_id||r.Destination!==(p.destination as JsonObject).device_id||
   c.router!==(p.router as JsonObject).device_id||r.ID!==p.route_authorization_id||c.jti!==p.route_authorization_jti)throw Error("route authorization participant mismatch");
 const first=hops[0] as JsonObject,second=hops[1] as JsonObject;
 if(first.From!==r.Source||first.To!==c.router||second.From!==c.router||second.To!==r.Destination)throw Error("route authorization hop mismatch");
 const key=b64(rawKey,32),signatureText=String(auth.signature??"");
 const primaryRaw=Deno.env.get("WEDECENT_CHECKPOINT_PRIMARY_PUBLIC_KEY");
 if(primaryRaw&&b64url(key)===b64url(b64(primaryRaw,32)))throw Error("route and primary trust anchors must be independent");
 const witnesses=trustedWitnessKeys();
 for(const witnessKey of witnesses.keys.values())if(b64url(key)===b64url(witnessKey))throw Error("route and witness trust anchors must be independent");
 if(!/^[A-Za-z0-9_-]{86}$/.test(signatureText))throw Error("invalid route authorization signature encoding");
 const signatureRaw=atob(signatureText.replace(/-/g,"+").replace(/_/g,"/")+"==");
 const signature=Uint8Array.from(signatureRaw,x=>x.charCodeAt(0));
 if(signature.length!==64||b64url(signature)!==signatureText)throw Error("non-canonical route authorization signature");
 const fields=[String(auth.kid),String(c.iss),String(c.aud),String(c.permission),String(c.jti),String(c.router),String(r.ID),String(r.Source),String(r.Destination)];
 const parts=[str("wedecent-mesh-forward-v1"),u32(Number(c.v)),...fields.map(str),i64(issued),i64(expires),i64(routeExpires),u32(hops.length)];
 for(const rawHop of hops){
  const hop=rawHop as JsonObject;
  if(!exact(hop,["From","To","Transport","Cost"])||typeof hop.From!=="string"||typeof hop.To!=="string"||typeof hop.Transport!=="string"||hop.Transport.length===0||
     typeof hop.Cost!=="number"||!Number.isSafeInteger(hop.Cost)||hop.Cost<0)throw Error("invalid route hop");
  parts.push(str(hop.From),str(hop.To),str(hop.Transport),u64(hop.Cost));
 }
 await verifyEd25519(key,signature,concat(...parts));
}

export function checkpointRecordHash(previous:Uint8Array,generation:unknown,requestHash:Uint8Array){return sha(concat(previous,u64(generation),requestHash))}
function trustedWitnessKeys(){
 const raw=Deno.env.get("WEDECENT_CHECKPOINT_WITNESS_KEYS");if(!raw)throw Error("independent witness trust anchors missing");
 const parsed=JSON.parse(raw) as unknown;if(!isObject(parsed))throw Error("invalid witness trust anchors");
 const keys=new Map<string,Uint8Array>(),seenKeys=new Set<string>();for(const [id,value] of Object.entries(parsed)){if(!/^[A-Za-z0-9._-]{1,128}$/.test(id))throw Error("invalid witness ID");const key=b64(value,32),fingerprint=b64url(key);if(seenKeys.has(fingerprint))throw Error("witness trust anchors must be unique");seenKeys.add(fingerprint);keys.set(id,key)}
 const quorum=Number(Deno.env.get("WEDECENT_CHECKPOINT_WITNESS_QUORUM"));if(!Number.isSafeInteger(quorum)||keys.size<2||keys.size>16||quorum<=Math.floor(keys.size/2)||quorum>keys.size)throw Error("invalid witness quorum");
 return {keys,quorum};
}
export async function verifyFinalizationEvidence(p:JsonObject,operationID:string,requestHash:Uint8Array,evidence:unknown,evidenceSHA256:string){
 if(!exact(evidence,["primary_receipt","witness_acknowledgements","revocation_proofs"]))throw Error("missing finalization evidence");
 if(await digest(evidence)!==evidenceSHA256)throw Error("finalization evidence digest mismatch");
 const primaryRaw=Deno.env.get("WEDECENT_CHECKPOINT_PRIMARY_PUBLIC_KEY");if(!primaryRaw)throw Error("independent primary trust anchor missing");
 const primaryKey=b64(primaryRaw,32),primaryID=await providerKeyID(primaryKey);
 const {keys:witnessKeys,quorum}=trustedWitnessKeys();
 for(const key of witnessKeys.values())if(b64url(key)===b64url(primaryKey))throw Error("primary and witness trust anchors must be independent");
 const receipt=evidence.primary_receipt as JsonObject;
 if(!exact(receipt,["version","device_id","account_id","organization_id","jti","authorization_sha256","request_sha256","generation","previous_hash","record_hash","provider_key_id","signature"])||
 Number(receipt.version)!==1||receipt.provider_key_id!==primaryID||receipt.request_sha256!==[...requestHash].map(x=>x.toString(16).padStart(2,"0")).join("")||
 receipt.jti!==p.jti||receipt.authorization_sha256!==p.authorization_sha256||Number(receipt.generation)<1)throw Error("primary receipt scope mismatch");
 const consumer=String(p.consuming_device_id),consumerEndpoint=(p.initiator as JsonObject).device_id===consumer?p.initiator:p.destination;
 if(!isObject(consumerEndpoint)||receipt.device_id!==consumerEndpoint.device_id||receipt.account_id!==consumerEndpoint.account_id||receipt.organization_id!==consumerEndpoint.organization_id)throw Error("primary receipt consumer mismatch");
 const expectedRecord=await checkpointRecordHash(h32(receipt.previous_hash),receipt.generation,requestHash);
 if(b64url(expectedRecord)!==b64url(h32(receipt.record_hash)))throw Error("primary receipt chain hash mismatch");
 const receiptMessage=checkpointReceiptMessage(receipt);
 await verifyEd25519(primaryKey,b64(receipt.signature,64),receiptMessage);
 const receiptDigest=await sha(receiptMessage),receiptDigestHex=[...receiptDigest].map(x=>x.toString(16).padStart(2,"0")).join("");
 const acks=evidence.witness_acknowledgements;
 if(!Array.isArray(acks))throw Error("witness acknowledgements missing");
 const ackIDs=new Set<string>();
 for(const rawAck of acks){
  if(!exact(rawAck,["witness_id","scope","jti","request_sha256","primary_receipt_sha256","decision","status","witness_key_id","signature"]))throw Error("invalid witness acknowledgement");
  const ack=rawAck as JsonObject,id=String(ack.witness_id),key=witnessKeys.get(id);
  if(!key||ackIDs.has(id)||!sameScope(ack.scope,consumerEndpoint)||ack.jti!==p.jti||ack.request_sha256!==receipt.request_sha256||ack.primary_receipt_sha256!==receiptDigestHex||ack.decision!=="committed"||!["acknowledged","already_acknowledged"].includes(String(ack.status))||ack.witness_key_id!==await providerKeyID(key))throw Error("witness acknowledgement scope mismatch");
  await verifyEd25519(key,b64(ack.signature,64),witnessAckMessage(ack));ackIDs.add(id);
 }
 if(ackIDs.size<quorum)throw Error("independent witness quorum not met");
 const participants=[p.initiator,p.destination];if(p.router!==null)participants.push(p.router);
 const proofs=evidence.revocation_proofs;if(!Array.isArray(proofs)||proofs.length!==participants.length)throw Error("revocation proof vector incomplete");
 for(let i=0;i<participants.length;i++){
  const participant=endpointScope(participants[i]),proof=proofs[i] as JsonObject;
  if(!exact(proof,["primary_head","witness_heads"]))throw Error("invalid revocation proof");
  const head=proof.primary_head as JsonObject;
  if(!exact(head,["version","device_id","account_id","organization_id","generation","record_hash","revocation_epoch","provider_key_id","signature"])||
    Number(head.version)!==1||head.device_id!==participant.device_id||head.account_id!==participant.account_id||head.organization_id!==participant.organization_id||
    Number(head.revocation_epoch)!==participant.revocation_epoch||head.provider_key_id!==primaryID)throw Error("primary revocation head mismatch");
  await verifyEd25519(primaryKey,b64(head.signature,64),checkpointHeadMessage(head));
  const witnessHeads=proof.witness_heads;if(!Array.isArray(witnessHeads))throw Error("witness revocation heads missing");
  const headIDs=new Set<string>();
  for(const rawHead of witnessHeads){
   if(!exact(rawHead,["witness_id","scope","generation","record_hash","primary_generation","primary_head","revocation_epoch","witness_key_id","signature"]))throw Error("invalid witness head");
   const wh=rawHead as JsonObject,id=String(wh.witness_id),key=witnessKeys.get(id);
   if(!key||headIDs.has(id)||!sameScope(wh.scope,participant)||Number(wh.primary_generation)!==Number(head.generation)||
      wh.primary_head!==head.record_hash||Number(wh.revocation_epoch)!==Number(head.revocation_epoch)||wh.witness_key_id!==await providerKeyID(key))throw Error("witness revocation head mismatch");
   await verifyEd25519(key,b64(wh.signature,64),witnessHeadMessage(wh));headIDs.add(id);
  }
  if(headIDs.size<quorum)throw Error("revocation witness quorum not met");
 }
 if(operationID!==[...await sha(concat(enc.encode("wedecent-checkpoint-finalization-v1\n"),requestHash))].map(x=>x.toString(16).padStart(2,"0")).join(""))throw Error("finalization operation ID mismatch");
}

if (import.meta.main) Deno.serve(async req=>{if(req.method==="OPTIONS")return new Response("ok",{headers});if(req.method!=="POST")return reply({error:"method not allowed"},405);try{
const token=req.headers.get("authorization")?.match(/^Bearer\s+([^\s]+)$/i)?.[1];if(!token||token.length>8192)return reply({error:"authentication required"},401);
const raw=await readBoundedBody(req);if(raw===null)return reply({error:"request too large"},413);
const url=Deno.env.get("SUPABASE_URL");if(!url)throw Error("URL missing");const admin=createClient(url,serviceKey(),{auth:{persistSession:false,autoRefreshToken:false}});
const {data:auth,error:authErr}=await admin.auth.getUser(token);if(authErr||!auth.user)return reply({error:"invalid user session"},401);
const b=JSON.parse(raw) as Record<string,unknown>;if(Object.keys(b).sort().join(",")!=="evidence,evidence_sha256,operation_id,outcome,payload,payload_sha256,payload_version")return reply({error:"invalid fields"},400);
const id=String(b.operation_id??""),outcome=String(b.outcome??""),sum=String(b.payload_sha256??""),p=b.payload as Record<string,unknown>;
if(!/^[0-9a-f]{64}$/.test(id)||!/^[0-9a-f]{64}$/.test(sum)||b.payload_version!==1||!["finalization_started","membership_unavailable","finalization_failed","finalized","rejected_revocation"].includes(outcome))return reply({error:"invalid request"},400);
if(!p||typeof p!=="object"||Array.isArray(p)||Object.keys(p).sort().join(",")!=="authorization_sha256,consuming_device_id,destination,device_public_key,device_signature,initiator,jti,route_authorization_id,route_authorization_json,route_authorization_jti,route_authorization_sha256,router,version"||p.version!==1||!endpoint(p.initiator)||!endpoint(p.destination)||!(p.router===null||endpoint(p.router))||!/^wd_[a-z2-7]{16}$/.test(String(p.consuming_device_id??""))||!([String((p.initiator as Record<string,unknown>).device_id),String((p.destination as Record<string,unknown>).device_id)].includes(String(p.consuming_device_id)))||!/^[A-Za-z0-9_-]{22}$/.test(String(p.jti??""))||!/^[0-9a-f]{64}$/.test(String(p.authorization_sha256??""))||!/^[0-9a-f]{64}$/.test(String(p.route_authorization_sha256??""))||!/^[A-Za-z0-9+/]{43}=$/.test(String(p.device_public_key??""))||!/^[A-Za-z0-9+/]{86}==$/.test(String(p.device_signature??"")))return reply({error:"invalid payload"},400);
if(await digest(p)!==sum)return reply({error:"digest mismatch"},400);
const requestHash=await verifyCanonicalCheckpoint(p,id);
const evidence=b.evidence,evidenceSum=String(b.evidence_sha256??"");
if(!/^[0-9a-f]{64}$/.test(evidenceSum))return reply({error:"invalid evidence digest"},400);
if(outcome==="finalization_started"){
 if(!exact(evidence,[]))return reply({error:"unexpected start evidence"},400);
 if(await digest(evidence)!==evidenceSum)return reply({error:"evidence digest mismatch"},400);
}else{
 if(outcome!=="finalized")return reply({error:"unsupported terminal outcome"},400);
 await verifyFinalizationEvidence(p,id,requestHash,evidence,evidenceSum);
}
const {data,error}=await admin.rpc("record_checkpoint_finalization",{p_operation_id:id,p_outcome:outcome,p_payload_version:1,p_payload:p,p_payload_sha256:"\\x"+sum,p_evidence:evidence,p_evidence_sha256:"\\x"+evidenceSum,p_actor_id:auth.user.id});
if(error){console.warn("checkpoint audit rejected",{code:error.code});const status=error.code==="42501"?403:error.code==="22023"?400:error.code==="23505"?409:503;return reply({error:status===503?"audit unavailable":"audit rejected"},status)}
const result=Array.isArray(data)?data[0]:data;if(!result||result.operation_id!==id||result.outcome!==outcome||typeof result.record_id!=="string"||typeof result.created_at!=="string"||typeof result.replayed!=="boolean")throw Error("invalid RPC result");return reply(result);
}catch(e){console.error("checkpoint audit failure",e instanceof Error?e.message:"unknown");return reply({error:"audit unavailable"},503)}});