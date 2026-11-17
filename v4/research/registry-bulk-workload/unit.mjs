// Finite offline artifact/codec scenarios, never attack traffic or signing for others.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';
import {build,evidence,root} from './compile.mjs';
import {verifyLayout} from './layout.mjs';
import {fixture} from './fixture.mjs';
import {encodeBatch,decodeBatch,word} from './codec.mjs';
import {sourceLines} from './source-lines.mjs';
const compiled=build(process.env.SAGE_EVM_FORK??'paris','unit-');
const output=JSON.parse(fs.readFileSync(new URL('unit-layout-output.json',evidence)));
const expected=JSON.parse(fs.readFileSync(new URL('types.json',root)));
const copy=()=>structuredClone(output);
const changeType=(label,field,value)=>{const out=copy();Object.values(out.contracts['Storage.sol'].StorageProbe.storageLayout.types).find(v=>v.label===label)[field]=value;return out;};
test('complete independently authored slots and types',()=>assert.equal(verifyLayout(output,expected).reachable_types,25));
test('same-size type substitution and primitive size refuse',()=>{
  assert.throws(()=>verifyLayout(changeType('bool','label','uint8'),expected));
  assert.throws(()=>verifyLayout(changeType('uint256','numberOfBytes','8'),expected));
});
test('slot, offset, complete member inventory refuse',()=>{
  for(const [field,value] of [['slot','9'],['offset',1],['label','other']]) {const out=copy();out.contracts['Storage.sol'].StorageProbe.storageLayout.storage[0][field]=value;assert.throws(()=>verifyLayout(out,expected));}
});
test('artifact cannot acquire runtime or functions',()=>{
  for(const [field,value] of [['evm',{}],['abi',[{type:'function'}]]]) {const out=copy();out.contracts['Storage.sol'].StorageProbe[field]=value;assert.throws(()=>verifyLayout(out,expected));}
});
test('missing, cyclic and unreachable types refuse',()=>{
  for(const mode of ['missing','cycle','extra']) {
    const out=copy(),types=out.contracts['Storage.sol'].StorageProbe.storageLayout.types;
    const [ref,value]=Object.entries(types).find(([,v])=>v.encoding==='mapping');
    if(mode==='extra') types.extra={encoding:'inplace',label:'uint256',numberOfBytes:'32'};else value.value=mode==='cycle'?ref:'absent';
    assert.throws(()=>verifyLayout(out,expected));
  }
});
test('mapping, dynamic and struct sizes and identities refuse',()=>{
  for(const [label,field,value] of [['string','numberOfBytes','1'],['struct StorageProbe.Key[]','numberOfBytes','64'],['mapping(bytes => bool)','numberOfBytes','64'],['struct StorageProbe.Claim','label','struct Other.Claim'],['uint256','numberOfBytes',32],['uint256','encoding','other']]) assert.throws(()=>verifyLayout(changeType(label,field,value),expected));
});
test('normal public fixture is deterministic and bounded',()=>{
  const first=fixture(),second=fixture();assert.deepEqual(first,second);
  assert.equal(first.proofs.length,128);assert.equal(Buffer.byteLength(first.record_jcs),65513);assert.equal(first.record.services.length,16);
  assert(first.proofs.every(v=>v.message_hex.length===484));assert.equal(new Set(first.proofs.map(v=>v.key_hex)).size,128);
});
test('standard bytes array head origin and exact round trip',()=>{
  const values=[[Buffer.from('ab','hex'),Buffer.alloc(32,7)],[],[Buffer.alloc(33,3)]];
  const bytes=encodeBatch('12345678',values);assert.equal(bytes.subarray(4,36).toString('hex'),word(96).toString('hex'));
  assert.equal(bytes.subarray(132,164).toString('hex'),word(64).toString('hex'));assert.deepEqual(decodeBatch(bytes),values);
  assert.throws(()=>word(-1));assert.throws(()=>word(1n<<256n));assert.throws(()=>encodeBatch('x',values));assert.throws(()=>encodeBatch('12345678',[]));assert.throws(()=>decodeBatch(Buffer.alloc(4)));
});
test('truncated and out-of-range artifact bytes refuse',()=>{
  const data=encodeBatch('12345678',[[Buffer.alloc(33)],[],[]]);assert.throws(()=>decodeBatch(data.subarray(0,130)));
  const changed=Buffer.from(data);changed.set(word(100000),4);assert.throws(()=>decodeBatch(changed));
});
test('source map cannot count PUSH payload or whole source as executable',()=>{
  const source='// unit\ncontract X {\n return true;\n}\n',loc=source.indexOf('return');
  const out={__source:source,sources:{'Batch.sol':{id:0,ast:{nodeType:'SourceUnit',src:`0:${source.length}:0`,nodes:[]}}},contracts:{'Batch.sol':{BatchProbe:{evm:{deployedBytecode:{object:'60010000',sourceMap:`0:${source.length}:0;${loc}:11:0;`}}}}}};
  assert.equal(sourceLines(out,new Set([1])).percent,0);assert.equal(sourceLines(out,new Set([2])).percent,100);
  out.contracts['Batch.sol'].BatchProbe.evm.deployedBytecode.sourceMap='-1:0:-1';assert.throws(()=>sourceLines(out,new Set()));
});
test('fixed compiler selectors identify separate research API',()=>{
  assert.deepEqual(Object.keys(compiled.batch.evm.methodIdentifiers),['verifyBatch(bytes[],bytes[],bytes[])']);assert.equal(compiled.codeHash.length,64);
});
