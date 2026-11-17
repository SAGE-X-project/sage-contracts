import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { createVM } from '@ethereumjs/vm';
import { Common, Mainnet, Hardfork } from '@ethereumjs/common';

const root = path.dirname(new URL(import.meta.url).pathname);
const evidence = path.join(root, 'evidence');
const require = createRequire(import.meta.url);
const soljson = require(path.join(evidence, 'soljson.cjs'));
const version = soljson.cwrap('solidity_version', 'string', [])();
assert.equal(version, '0.8.20+commit.a1b79de6.Emscripten.clang');
const compile = soljson.cwrap('solidity_compile', 'string', ['string', 'number', 'number']);
const sha = data => crypto.createHash('sha256').update(data).digest('hex');
const write = (name, value) => fs.writeFileSync(path.join(evidence, name), JSON.stringify(value, null, 2) + '\n');
const sourceNames = ['StrictEd25519.sol', 'upstream/external/sha512/Sha2Ext.sol', 'upstream/external/sha512/LibBytes.sol'];
const sources = Object.fromEntries(sourceNames.map(n => [n, {content: fs.readFileSync(path.join(root, n), 'utf8')}]));
const GAS_CAP = 15_000_000n; // Fixed experimental execution cap, selected before measuring.
const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const bytes = hex => Buffer.from(hex, 'hex');
const little = n => { const b = Buffer.alloc(32); for (let i = 0; i < 32; ++i) { b[i] = Number(n & 255n); n >>= 8n; } return b; };
const word = n => bytes(BigInt(n).toString(16).padStart(64, '0'));
function callBytes(selector, args) {
  let offset = 32 * args.length;
  const heads = [], tails = [];
  for (const value of args) { heads.push(word(offset)); const tail = Buffer.concat([word(value.length), value, Buffer.alloc((32 - value.length % 32) % 32)]); tails.push(tail); offset += tail.length; }
  return Buffer.concat([bytes(selector), ...heads, ...tails]);
}
const vectors = [
  {name:'RFC8032-1', key:'d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', message:'', signature:'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'},
  {name:'RFC8032-2', key:'3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', message:'72', signature:'92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'},
  {name:'RFC8032-3', key:'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', message:'af82', signature:'6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a'},
];
const publicObject = raw => crypto.createPublicKey({key:Buffer.concat([bytes('302a300506032b6570032100'), raw]),format:'der',type:'spki'});
const normal = vectors.map(v => ({...v,key:bytes(v.key),message:bytes(v.message),signature:bytes(v.signature)}));
// Public, deterministic test seed only. No runtime credentials or user input are loaded.
const testKey = crypto.createPrivateKey({key:Buffer.concat([bytes('302e020100300506032b657004220420'), Buffer.alloc(32,7)]),format:'der',type:'pkcs8'});
const pub = crypto.createPublicKey(testKey).export({type:'spki',format:'der'}).subarray(-32);
for (const length of [47,48,117,175,176,241,242,1024]) {
  const message = Buffer.from(Array.from({length},(_,i)=>(i * 17) % 256));
  normal.push({name:'normal-binary-'+length,key:pub,message,signature:crypto.sign(null,message,testKey)});
}
for (const v of normal) assert(crypto.verify(null,v.message,publicObject(v.key),v.signature),v.name);
const mixed = JSON.parse(fs.readFileSync(path.join(root, 'point-components.json'), 'utf8'));
assert.equal(mixed.source.revision, '65519336fda78a3d016e947df6d82848aca0c9da');
const first = normal[0], identity = little(1n), negativeZero = little(1n | 1n << 255n);
const unit = [
  {name:'short-key',key:Buffer.alloc(31)}, {name:'long-key',key:Buffer.alloc(33)},
  {name:'short-signature',signature:Buffer.alloc(63)}, {name:'long-signature',signature:Buffer.alloc(65)},
  {name:'bounded-message',message:Buffer.alloc(1025)},
  {name:'identity-A',key:identity}, {name:'order-four-A',key:Buffer.alloc(32)},
  {name:'field-range-A',key:little(P)}, {name:'noncanonical-zero-sign-A',key:negativeZero},
  {name:'unrecoverable-A',key:little(2n)},
  {name:'mixed-order-A',key:bytes(mixed.mixed_A)},
  {name:'mixed-order-R',signature:Buffer.concat([bytes(mixed.mixed_R),first.signature.subarray(32)])},
  {name:'identity-R',signature:Buffer.concat([identity,first.signature.subarray(32)])},
  {name:'order-four-R',signature:Buffer.concat([Buffer.alloc(32),first.signature.subarray(32)])},
  {name:'field-range-R',signature:Buffer.concat([little(P),first.signature.subarray(32)])},
  {name:'noncanonical-zero-sign-R',signature:Buffer.concat([negativeZero,first.signature.subarray(32)])},
  {name:'scalar-L',signature:Buffer.concat([first.signature.subarray(0,32),little(L)])},
  {name:'scalar-L-minus-one',signature:Buffer.concat([first.signature.subarray(0,32),little(L-1n)])},
  {name:'zero-scalar-equation',signature:Buffer.concat([first.signature.subarray(0,32),little(0n)])},
  {name:'different-message',message:bytes('01')},
].map(v=>({...first,...v,expected:false,group:'fixed-unit-data',contract:'StrictEd25519'}));
const rows = [];
for (const [evmVersion, hardfork] of [['paris',Hardfork.Paris],['shanghai',Hardfork.Shanghai]]) {
  const input={language:'Solidity',sources,settings:{optimizer:{enabled:true,runs:200,details:{yul:true,yulDetails:{stackAllocation:true,optimizerSteps:'dhfoDgvulfnTUtnIf'}}},viaIR:false,evmVersion,metadata:{bytecodeHash:'ipfs',appendCBOR:true},outputSelection:{'*':{'*':['abi','evm.bytecode','evm.deployedBytecode','evm.methodIdentifiers','metadata'],'':['ast']}}}};
  write(evmVersion+'-input.json',input);
  const output=JSON.parse(compile(JSON.stringify(input),0,0));write(evmVersion+'-output.json',output);
  const errors=(output.errors||[]).filter(e=>e.severity==='error');assert.equal(errors.length,0,JSON.stringify(errors));
  const contracts=output.contracts['StrictEd25519.sol'];
  const cases=[...normal.map(v=>({...v,expected:true,group:'ordinary-runtime',contract:'StrictEd25519'})),...unit,
    ...['MissingBackendControl','InvalidBackendControl'].map(contract=>({...first,name:contract,expected:false,group:'fixed-unit-backend',contract})),
    ...['zeroScalarIdentity','baseOrderIdentity','neutralAddition','invalidProjectiveRefused'].map(name=>({name,expected:true,group:'fixed-unit-arithmetic',contract:'ArithmeticControls',method:name+'()'}))];
  const pointCases = [
    ['prime-A',first.key,[true,false,true]],
    ['prime-R',first.signature.subarray(0,32),[true,false,true]],
    ['mixed-A',bytes(mixed.mixed_A),[true,false,false]],
    ['mixed-R',bytes(mixed.mixed_R),[true,false,false]],
    ['identity-point',identity,[true,true,true]],
    ['order-four-point',Buffer.alloc(32),[true,false,false]],
    ['non-point',little(2n),[false,false,false]],
  ];
  for(const [name,encoded,expectedWords] of pointCases) cases.push({name,expectedWords,group:'fixed-unit-membership',contract:'ArithmeticControls',method:'inspectPoint(bytes)',args:[encoded]});
  write(evmVersion+'-case-fixtures.json', cases.map(v=>({name:v.name,group:v.group,contract:v.contract,method:v.method||'verify(bytes,bytes,bytes)',expected:v.expected,expectedWords:v.expectedWords,args:v.args?.map(b=>b.toString('hex')),key:v.key?.toString('hex'),message:v.message?.toString('hex'),signature:v.signature?.toString('hex')})));
  const visited=Object.fromEntries(Object.keys(contracts).map(n=>[n,new Set()]));
  for(const test of cases){
    const artifact=contracts[test.contract],code=bytes(artifact.evm.deployedBytecode.object);
    const signature=test.method||'verify(bytes,bytes,bytes)';
    const data=callBytes(artifact.evm.methodIdentifiers[signature],test.args||(test.method?[]:[test.key,test.message,test.signature]));
    const common=new Common({chain:Mainnet,hardfork});assert.equal(common.hardfork(),evmVersion);
    const vm=await createVM({common});
    vm.evm.events.on('step',(step,next)=>{visited[test.contract].add(step.pc);next?.();});
    const start=performance.now();
    const result=await vm.evm.runCode({code,data,gasLimit:GAS_CAP,isStatic:true});
    const elapsed=performance.now()-start;
    const actual=result.exceptionError?null:Buffer.from(result.returnValue).toString('hex');
    const expected=Buffer.concat((test.expectedWords||[test.expected]).map(v=>word(v?1:0))).toString('hex');
    const row={evmVersion,group:test.group,name:test.name,contract:test.contract,expected,actual,exception:result.exceptionError?.error||null,execution_gas:result.executionGasUsed.toString(),execution_ms:Math.round(elapsed),calldata_sha256:sha(data),runtime_object_sha256:sha(code)};
    rows.push(row);write('partial-results.json',rows);console.log(JSON.stringify(row));
    assert.equal(row.exception,null,test.name);assert.equal(actual,expected,test.name);
  }
  write(evmVersion+'-visited-pcs.json',Object.fromEntries(Object.entries(visited).map(([n,pcs])=>[n,[...pcs].sort((a,b)=>a-b)])));
}
write('results.json',{scope:'isolated EVM runCode evaluation; no chain transaction, deployment, Registry admission or conformance verdict',compiler:version,node:process.version,execution_gas_cap:GAS_CAP.toString(),message_limit:1024,rows,remaining:['valid-zero-signature equation fixture NOT_RUN','full Registry storage/lifecycle/maximum key-count costs NOT_RUN','operating source and versioned adoption NOT_RUN']});
