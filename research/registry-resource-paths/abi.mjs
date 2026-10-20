import assert from 'node:assert/strict';
import {keccak_256} from '@noble/hashes/sha3.js';
export const word=n=>{n=BigInt(n);assert(n>=0n&&n<1n<<256n);return Buffer.from(n.toString(16).padStart(64,'0'),'hex');};
const pad=b=>Buffer.concat([b,Buffer.alloc((32-b.length%32)%32)]);
export const canonical=t=>t.type.startsWith('tuple')?'('+t.components.map(canonical).join(',')+')'+t.type.slice(5):t.type;
const dynamic=t=>['string','bytes'].includes(t.type)||t.type.endsWith('[]')||(t.type==='tuple'&&t.components.some(dynamic));
const size=t=>dynamic(t)?32:t.type==='tuple'?t.components.reduce((n,x)=>n+size(x),0):32;
export function tuple(types,values){assert.equal(types.length,values.length);const heads=[],tails=[];let offset=types.reduce((n,t)=>n+size(t),0);
 for(let i=0;i<types.length;++i){const encoded=encode(types[i],values[i]);if(dynamic(types[i])){heads.push(word(offset));tails.push(encoded);offset+=encoded.length;}else heads.push(encoded);}return Buffer.concat([...heads,...tails]);}
function encode(t,v){
 if(t.type.endsWith('[]')){assert(Array.isArray(v));const item={...t,type:t.type.slice(0,-2)};return Buffer.concat([word(v.length),tuple(v.map(()=>item),v)]);}
 if(t.type==='tuple')return tuple(t.components,Array.isArray(v)?v:t.components.map(x=>v[x.name]));
 if(t.type==='string'||t.type==='bytes'){const b=t.type==='string'?Buffer.from(v):Buffer.from(v);return Buffer.concat([word(b.length),pad(b)]);}
 if(t.type==='address'){assert(/^0x[0-9a-f]{40}$/.test(v));return word(BigInt(v));}
 if(t.type==='bool'){assert.equal(typeof v,'boolean');return word(v?1:0);}
 if(/^uint\d+$/.test(t.type)){const n=BigInt(v),bits=BigInt(t.type.slice(4));assert(n>=0n&&n<1n<<bits);return word(n);}
 assert(/^bytes\d+$/.test(t.type));const b=Buffer.from(v);assert.equal(b.length,Number(t.type.slice(5)));return pad(b);
}
export function method(abi,name){const entries=abi.filter(x=>x.type==='function'&&x.name===name);assert.equal(entries.length,1);const entry=entries[0];const signature=name+'('+entry.inputs.map(canonical).join(',')+')';return {...entry,signature,selector:Buffer.from(keccak_256(Buffer.from(signature))).subarray(0,4)};}
export function call(abi,name,values=[]){const m=method(abi,name);return Buffer.concat([m.selector,tuple(m.inputs,values)]);}
const number=(b,at)=>{assert(at>=0&&at+32<=b.length);const n=BigInt('0x'+b.subarray(at,at+32).toString('hex'));assert(n<=BigInt(Number.MAX_SAFE_INTEGER));return Number(n);};
function decodeTuple(types,b,start){let at=start;return types.map(t=>{const out=decode(t,b,dynamic(t)?start+number(b,at):at);at+=size(t);return out;});}
function decode(t,b,at){
 if(t.type.endsWith('[]')){const n=number(b,at);assert(n<=1024);const item={...t,type:t.type.slice(0,-2)};return decodeTuple(Array.from({length:n},()=>item),b,at+32);}
 if(t.type==='tuple')return decodeTuple(t.components,b,at);
 if(t.type==='string'||t.type==='bytes'){const n=number(b,at);assert(at+32+n<=b.length);const raw=b.subarray(at+32,at+32+n);return t.type==='string'?raw.toString('utf8'):raw;}
 assert(at+32<=b.length);const raw=b.subarray(at,at+32);
 if(t.type==='address')return '0x'+raw.subarray(12).toString('hex');
 if(t.type==='bool'){const n=BigInt('0x'+raw.toString('hex'));assert(n===0n||n===1n);return n===1n;}
 if(t.type.startsWith('uint'))return BigInt('0x'+raw.toString('hex'));
 return raw.subarray(0,Number(t.type.slice(5)));
}
export const output=(abi,name,bytes)=>decodeTuple(method(abi,name).outputs,Buffer.from(bytes),0);
