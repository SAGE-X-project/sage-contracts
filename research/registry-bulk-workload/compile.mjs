import fs from 'node:fs';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {keccak_256} from '@noble/hashes/sha3.js';
import {verifyLayout} from './layout.mjs';
export const root = new URL('./',import.meta.url);
export const evidence = new URL('evidence/',root);
export const sha = bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
export const write = (name,value)=>fs.writeFileSync(new URL(name,evidence),JSON.stringify(value,null,2)+'\n');
export function build(target, prefix='') {
  assert(['paris','shanghai'].includes(target)); fs.mkdirSync(evidence,{recursive:true});
  const oldRoot=new URL('../registry-ed25519/',root), compiler=new URL('evidence/soljson.cjs',oldRoot);
  assert.equal(sha(fs.readFileSync(compiler)),'5c509f760dc110a695c8b39bbc21e08c17dee431aa14d606f59e623d7c3cc657');
  const sol=createRequire(import.meta.url)(compiler.pathname);
  const version=sol.cwrap('solidity_version','string',[])(); assert.equal(version,'0.8.20+commit.a1b79de6.Emscripten.clang');
  const compile=sol.cwrap('solidity_compile','string',['string','number','number']);
  const settings={optimizer:{enabled:true,runs:200,details:{yul:true,yulDetails:{stackAllocation:true,optimizerSteps:'dhfoDgvulfnTUtnIf'}}},viaIR:false,evmVersion:target,metadata:{bytecodeHash:'ipfs',appendCBOR:true}};
  const run = (name,sources,selection) => {
    const input={language:'Solidity',sources,settings:{...settings,outputSelection:selection}};
    const output=JSON.parse(compile(JSON.stringify(input),0,0)); write(prefix+name+'-input.json',input); write(prefix+name+'-output.json',output);
    assert.equal((output.errors??[]).filter(v=>v.severity==='error').length,0,JSON.stringify(output.errors)); return output;
  };
  const storage=run('layout',{'Storage.sol':{content:fs.readFileSync(new URL('Storage.sol',root),'utf8')}},{'*':{'*':['abi','storageLayout']}});
  write(prefix+'layout-check.json',verifyLayout(storage,JSON.parse(fs.readFileSync(new URL('types.json',root)))));
  const files=['StrictEd25519.sol','upstream/external/sha512/Sha2Ext.sol','upstream/external/sha512/LibBytes.sol'];
  const source=Object.fromEntries(files.map(name=>[name,{content:fs.readFileSync(new URL(name,oldRoot),'utf8')}]));
  const selection={'*':{'*':['abi','evm.deployedBytecode','evm.methodIdentifiers'],'':['ast']}};
  const strict=run('verifier',source,selection).contracts['StrictEd25519.sol'].StrictEd25519;
  const code=Buffer.from(strict.evm.deployedBytecode.object,'hex'), codeHash=Buffer.from(keccak_256(code)).toString('hex');
  const template=fs.readFileSync(new URL('Batch.sol',root),'utf8'), marker='bytes32(0); // BUILD_CODE_HASH'; assert.equal(template.split(marker).length,2);
  const content=template.replace(marker,'bytes32(0x'+codeHash+'); // BUILD_CODE_HASH'); fs.writeFileSync(new URL(prefix+'Batch.compiled.sol',evidence),content);
  const wrapperOutput=run('batch',{'Batch.sol':{content}},selection);
  return {target,compiler:version,code,codeHash,strict,batch:wrapperOutput.contracts['Batch.sol'].BatchProbe};
}
