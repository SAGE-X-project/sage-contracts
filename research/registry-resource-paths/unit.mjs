import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {tuple,call,output,word,canonical} from './abi.mjs';
import {key,initial,publicKey,json,registry,agent} from './fixture.mjs';
import {build,write,evidence,identity} from './compile.mjs';
import {environment} from './run.mjs';
test('ABI fixed canonical words, booleans, arrays and tuple layout',()=>{
 const types=[{type:'uint64'},{type:'bool'},{type:'address'},{type:'bytes32'}],values=[7n,true,'0x'+'1'.repeat(40),Buffer.alloc(32,2)];
 const expected=Buffer.from('0'.repeat(63)+'7'+'0'.repeat(63)+'1'+'0'.repeat(24)+'1'.repeat(40)+'02'.repeat(32),'hex');assert.deepEqual(tuple(types,values),expected);
 const abi=[{type:'function',name:'fixed',inputs:types,outputs:types}];assert.deepEqual(output(abi,'fixed',expected),values);
 const struct={type:'tuple',components:[{name:'n',type:'uint64'},{name:'b',type:'bool'}]};assert.equal(canonical(struct),'(uint64,bool)');
 assert.deepEqual(tuple([struct],[[9n,false]]),Buffer.from('0'.repeat(63)+'9'+'0'.repeat(64),'hex'));
 const array={type:'tuple[]',components:struct.components},encoded=Buffer.from('0'.repeat(62)+'20'+'0'.repeat(63)+'1'+'0'.repeat(63)+'9'+'0'.repeat(64),'hex');
 assert.deepEqual(tuple([array],[[[9n,false]]]),encoded);assert.deepEqual(output([{type:'function',name:'x',inputs:[],outputs:[array]}],'x',encoded),[[[9n,false]]]);
 assert.deepEqual(output([{type:'function',name:'x',inputs:[],outputs:[struct]}],'x',Buffer.concat([word(9),word(0)])),[[9n,false]]);
 const transfer=[{type:'function',name:'transfer',inputs:[{type:'address'},{type:'uint256'}],outputs:[]}];
 assert.equal(call(transfer,'transfer',['0x'+'1'.repeat(40),1n]).toString('hex'),'a9059cbb'+'0'.repeat(24)+'1'.repeat(40)+'0'.repeat(63)+'1');
 assert.equal(tuple([{type:'uint64'},{type:'string'}],[7n,'abc']).toString('hex'),'0'.repeat(63)+'7'+'0'.repeat(62)+'40'+'0'.repeat(63)+'3'+'616263'+'0'.repeat(58));
 assert.throws(()=>word(-1));assert.throws(()=>tuple([{type:'bool'}],[1]));assert.throws(()=>tuple([{type:'int8'}],[1]));
 assert.throws(()=>output(abi,'fixed',Buffer.alloc(2)));assert.throws(()=>call([],'missing'));
});
test('ordinary fixture roles, expiry presence and independently bounded full record',()=>{
 const owner='0x'+'1'.repeat(40),a=initial(owner,1),b=initial(owner,128,{full:true}),c=initial(owner,2,{kem:true,expiredSecond:true});
 assert.equal(Buffer.byteLength(json(b.record)),65513);assert.equal(b.record.keys.length,128);assert.equal(b.services.length,16);
 assert(c.keys.some(k=>k.alg==='x25519'));assert(c.keys.some(k=>k.hasExpiry&&k.expires===0n));
 assert.equal(publicKey(key(0,{expires:0})).expires,0);assert(!('expires'in publicKey(key(0))));
 assert.equal(a.claim.registryId,registry);assert.equal(a.claim.agentId,agent);assert(a.keys[0].challenge.includes(Buffer.from('sage-pop-0.11.0')));
 assert.equal(key(99,{name:'b'.repeat(32)}).name,'b'.repeat(32));
});
test('owned pure-codec runtime controls, including every short padding and escape',async()=>{
 const target=process.env.SAGE_EVM_FORK;assert(['paris','shanghai'].includes(target));const compiled=build(target,'unit-');
 const env=await environment(compiled,{trace:true,prefix:'unit-'});
 for(const text of ['', 'plain', '"\\\b\t\n\f\r\0\x1f'])for(const n of [0,1,2,3,4]){
  const raw=Buffer.alloc(n,255),r=await env.transact('inspect',[text,raw,2n**256n-1n,'0x'+'1'.repeat(40)],{target:'codec',category:'fixed-codec-unit'});
  assert.equal(r.decoded[0].toString(),JSON.stringify(text));assert.equal(r.decoded[1],raw.toString('base64url'));assert.equal(r.decoded[2].toString(),(2n**256n-1n).toString());assert.equal(r.decoded[3],'0x'+'1'.repeat(40));
 }
 const zero=await env.transact('inspect',['',Buffer.alloc(0),0n,'0x'+'0'.repeat(40)],{target:'codec',category:'fixed-codec-unit'});assert.equal(zero.decoded[2].toString(),'0');
 for(const list of [[],['1'],['1','2'],['"abc"','null','true','0'.repeat(31),'0'.repeat(32),'0'.repeat(33)]]){
  const r=await env.transact('joined',[list.map(x=>Buffer.from(x))],{target:'codec',category:'fixed-codec-unit'});assert.equal(r.decoded[0].toString(),'['+list.join(',')+']');
 }
 await env.transact('inspect',['한',Buffer.alloc(0),0n,'0x'+'0'.repeat(40)],{target:'codec',category:'fixed-codec-unit',expectSuccess:false});
 write('unit-visited.json',{identity:identity(compiled),visited:Object.fromEntries(Object.entries(env.visited).map(([k,v])=>[k,[...v]]))});
 write('unit-results.json',{scope:'Fixed ABI/fixture/pure ASCII codec units only; no signature forgery, protocol conformance or public chain',target,rows:env.rows});
 assert(fs.existsSync(new URL('unit-paths-output.json',evidence)));
});
