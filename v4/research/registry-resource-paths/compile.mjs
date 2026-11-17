import fs from 'node:fs';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {keccak_256} from '@noble/hashes/sha3.js';
export const root=new URL('./',import.meta.url),evidence=new URL('evidence/',root);
export const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
export const write=(name,value)=>fs.writeFileSync(new URL(name,evidence),JSON.stringify(value,null,2)+'\n');
export const identity=compiled=>({target:compiled.target,compiler:compiled.version,output_sha256:sha(JSON.stringify(compiled.output)),verifier_runtime_sha256:sha(compiled.code)});
export function build(target,prefix='') {
 assert(['paris','shanghai'].includes(target));fs.mkdirSync(evidence,{recursive:true});
 const prior=new URL('../registry-ed25519/',root),compiler=new URL('evidence/soljson.cjs',prior);
 assert.equal(sha(fs.readFileSync(compiler)),'5c509f760dc110a695c8b39bbc21e08c17dee431aa14d606f59e623d7c3cc657');
 const sol=createRequire(import.meta.url)(compiler.pathname),version=sol.cwrap('solidity_version','string',[])();
 assert.equal(version,'0.8.20+commit.a1b79de6.Emscripten.clang');const compile=sol.cwrap('solidity_compile','string',['string','number','number']);
 const selection={'*':{'*':['abi','evm.deployedBytecode','evm.methodIdentifiers'],'':['ast']}};
 const run=(name,sources,ir)=>{const input={language:'Solidity',sources,settings:{optimizer:ir?{enabled:true,runs:1}:{enabled:true,runs:200,details:{yul:true,yulDetails:{stackAllocation:true,optimizerSteps:'dhfoDgvulfnTUtnIf'}}},viaIR:ir,evmVersion:target,metadata:{bytecodeHash:'ipfs',appendCBOR:true},outputSelection:selection}};
 const output=JSON.parse(compile(JSON.stringify(input),0,0));write(prefix+name+'-input.json',input);write(prefix+name+'-output.json',output);
 assert.equal((output.errors??[]).filter(v=>v.severity==='error').length,0,JSON.stringify(output.errors));return output;};
 const old=['StrictEd25519.sol','upstream/external/sha512/Sha2Ext.sol','upstream/external/sha512/LibBytes.sol'];
 const strict=run('strict',Object.fromEntries(old.map(n=>[n,{content:fs.readFileSync(new URL(n,prior),'utf8')}])),false).contracts['StrictEd25519.sol'].StrictEd25519;
 const code=Buffer.from(strict.evm.deployedBytecode.object,'hex'),hash=Buffer.from(keccak_256(code)).toString('hex');
 const marker='bytes32(0); // BUILD_CODE_HASH',template=fs.readFileSync(new URL('PathProbe.sol',root),'utf8');assert.equal(template.split(marker).length,2);
 const content=template.replace(marker,'bytes32(0x'+hash+'); // BUILD_CODE_HASH');fs.writeFileSync(new URL(prefix+'PathProbe.compiled.sol',evidence),content);
 const sources={'PathProbe.sol':{content},'Codec.sol':{content:fs.readFileSync(new URL('Codec.sol',root),'utf8')},'Storage.sol':{content:fs.readFileSync(new URL('../registry-bulk-workload/Storage.sol',root),'utf8')}};
 const output=run('paths',sources,true);
 return {target,version,code,hash,contracts:output.contracts,output};
}
