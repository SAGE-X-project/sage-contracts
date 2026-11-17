import assert from 'node:assert/strict';
import crypto from 'node:crypto';
export const b64=b=>Buffer.from(b).toString('base64url');
export const digest=b=>crypto.createHash('sha256').update(b).digest();
export function json(v){if(Array.isArray(v))return '['+v.map(json).join(',')+']';if(v&&typeof v==='object')return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+json(v[k])).join(',')+'}';return JSON.stringify(v);}
export const registry='eip155:1:0x0000000000000000000000000000000000003000';
export const agent='a'.repeat(64),did='did:sage:'+registry+':'+agent;
const length=b=>{assert(b.length<=65535);const h=Buffer.alloc(2);h.writeUInt16BE(b.length);return Buffer.concat([h,b]);};
export function key(i,{kem=false,expires=null,name:chosenName=null}={}){
 const seed=digest(Buffer.from('SAGE ordinary state-path public seed '+i));
 const secret=crypto.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});
 const publicKey=crypto.createPublicKey(secret),signing=publicKey.export({format:'der',type:'spki'}).subarray(-32);
 const name=chosenName??(kem?'a':'s')+String(i).padStart(31,'0');const alg=kem?'x25519':'Ed25519';
 let raw=signing;
 if(kem){const k=crypto.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b656e04220420','hex'),digest(Buffer.from('SAGE ordinary state-path public KEM seed '+i))]),format:'der',type:'pkcs8'});raw=crypto.createPublicKey(k).export({format:'der',type:'spki'}).subarray(-32);}
 const challenge=Buffer.concat([Buffer.from('sage-pop-0.11.0'),...[registry,agent,name,alg].map(s=>length(Buffer.from(s))),length(raw)]);
 const proof=crypto.sign(null,challenge,secret);assert(crypto.verify(null,challenge,publicKey,proof));
 const signer=did+'#'+(kem?'s'+String(i).padStart(31,'0'):name);
 return {name,alg,key:raw,signer,proof,hasExpiry:expires!==null,expires:BigInt(expires??0),challenge};
}
export const publicKey=k=>({...k.hasExpiry?{expires:Number(k.expires)}:{},name:k.name,alg:k.alg,key:b64(k.key),proof:{signer:k.signer,value:b64(k.proof)},state:'accepted'});
export function services(count=0){return Array.from({length:count},(_,i)=>({name:'svc-'+String(i).padStart(2,'0'),serviceType:i===0?'type"\\':'fixture',uri:'https://example.invalid/'+i+'/'}));}
export function initial(controller,count,{full=false,kem=false,expiredSecond=false}={}){
 const keys=Array.from({length:count},(_,i)=>key(i,{expires:expiredSecond&&i===1?0:null}));if(kem)keys.push(key(0,{kem:true}));keys.sort((a,b)=>a.name.localeCompare(b.name,'en'));
 const list=services(full?16:2);const record={controller,id:did,keys:keys.map(publicKey),services:list.map(({name,serviceType:type,uri})=>({name,type,uri})),state:'created',version:'1'};
 if(full){let extra=65513-Buffer.byteLength(json(record));assert(extra>=0);for(const s of list){const n=Math.min(extra,2048-s.uri.length);s.uri+='x'.repeat(n);extra-=n;}assert.equal(extra,0);record.services=list.map(({name,serviceType:type,uri})=>({name,type,uri}));assert.equal(Buffer.byteLength(json(record)),65513);}
 const salt=digest(Buffer.from('SAGE ordinary public reveal salt '+controller+' '+count));
 const claim={registryId:registry,agentId:agent,controller,keys:record.keys,services:record.services,salt:b64(salt)};
 const commitment=digest(Buffer.concat([Buffer.from('sage-claim-0.11.0'),Buffer.from([0]),Buffer.from(json(claim))]));
 return {keys,services:list,salt,record,claim,commitment};
}
