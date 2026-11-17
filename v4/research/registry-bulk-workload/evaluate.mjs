import fs from 'node:fs';
import assert from 'node:assert/strict';
import {createVM} from '@ethereumjs/vm';
import {Common,Mainnet,Hardfork} from '@ethereumjs/common';
import {createAddressFromString} from '@ethereumjs/util';
import {build,evidence,sha,write} from './compile.mjs';
import {fixture} from './fixture.mjs';
import {encodeBatch,decodeBatch,word} from './codec.mjs';
import {sourceLines} from './source-lines.mjs';
const target=process.env.SAGE_EVM_FORK;
assert(['paris','shanghai'].includes(target),'fixed CI fork required');
const compiled=build(target),normal=fixture(); write('fixture.json',normal);
const arrays=['key_hex','message_hex','signature_hex'].map(name=>normal.proofs.map(row=>Buffer.from(row[name],'hex')));
const take=n=>arrays.map(values=>values.slice(0,n));
const first=take(1),rows=[],visited=new Set(),GAS_CAP=1_000_000_000n;
const verifier=createAddressFromString('0x0000000000000000000000000000000000001000');
const wrapper=createAddressFromString('0x0000000000000000000000000000000000002000');
const wrapperCode=Buffer.from(compiled.batch.evm.deployedBytecode.object,'hex');
const selector=compiled.batch.evm.methodIdentifiers['verifyBatch(bytes[],bytes[],bytes[])'];
const cases=[
  {name:'ordinary-one',values:first,valid:true,count:1,trace:true,install:true},
  {name:'ordinary-full-count',values:take(128),valid:true,count:128,trace:false,install:true},
  {name:'empty-fixed-unit',values:[[],[],[]],valid:false,count:0,trace:true,install:true},
  {name:'count-over-cap-fixed-unit',values:arrays.map(values=>[...values,values[0]]),valid:false,count:0,trace:true,install:true},
  {name:'unequal-count-fixed-unit',values:[first[0],[],first[2]],valid:false,count:0,trace:true,install:true},
  {name:'short-key-fixed-unit',values:[[Buffer.alloc(31)],first[1],first[2]],valid:false,count:0,trace:true,install:true},
  {name:'short-message-fixed-unit',values:[first[0],[Buffer.alloc(241)],first[2]],valid:false,count:0,trace:true,install:true},
  {name:'short-signature-fixed-unit',values:[first[0],first[1],[Buffer.alloc(63)]],valid:false,count:0,trace:true,install:true},
  {name:'absent-code-fixed-unit',values:first,valid:false,count:0,trace:true,install:false},
];
for(const item of cases) {
  const vm=await createVM({common:new Common({chain:Mainnet,hardfork:target==='paris'?Hardfork.Paris:Hardfork.Shanghai})});
  // Owned isolated VM state only; no CREATE, chain transaction, external RPC or deployment.
  if(item.install) await vm.stateManager.putCode(verifier,compiled.code);
  await vm.stateManager.putCode(wrapper,wrapperCode);
  if(item.install) assert.equal(Buffer.from((await vm.stateManager.getAccount(verifier)).codeHash).toString('hex'),compiled.codeHash);
  if(item.trace) vm.evm.events.on('step',(step,next)=>{if(step.address.equals(wrapper)) visited.add(step.pc);next?.();});
  const data=encodeBatch(selector,item.values); assert.deepEqual(decodeBatch(data),item.values);
  fs.writeFileSync(new URL(item.name+'-calldata.hex',evidence),data.toString('hex')+'\n');
  const start=performance.now();
  const result=await vm.evm.runCode({to:wrapper,code:wrapperCode,data,gasLimit:GAS_CAP,isStatic:true});
  const row={name:item.name,target,ordinary:item.name.startsWith('ordinary-'),proofs:item.values[0].length,instruction_trace:item.trace,
    local_vm_verifier_code_installed:item.install,local_vm_wrapper_code_installed:true,calldata_bytes:data.length,calldata_sha256:sha(data),
    verifier_runtime_sha256:sha(compiled.code),verifier_code_hash:compiled.codeHash,wrapper_runtime_sha256:sha(wrapperCode),
    expected:Buffer.concat([word(item.valid?1:0),word(item.count)]).toString('hex'),actual:Buffer.from(result.returnValue).toString('hex'),
    exception:result.exceptionError?.error??null,execution_gas:result.executionGasUsed.toString(),execution_ms:Math.round(performance.now()-start)};
  rows.push(row);write('partial-results.json',rows);console.log(JSON.stringify(row));
  assert.equal(row.exception,null,item.name);assert.equal(row.actual,row.expected,item.name);
}
write('visited-pcs.json',[...visited].sort((a,b)=>a-b));
const output=JSON.parse(fs.readFileSync(new URL('batch-output.json',evidence)));output.__source=fs.readFileSync(new URL('Batch.compiled.sol',evidence),'utf8');
const coverage=sourceLines(output,visited);write('solidity-coverage.json',coverage);assert(coverage.percent>=90,'new wrapper mapped start-line coverage below 90%');
write('results.json',{scope:'single owned isolated VM runCode calls with code installation; signature component only; not Registry, public-chain deployment, transaction, admission, Source or conformance',
 target,compiler:compiled.compiler,node:process.version,gas_cap:GAS_CAP.toString(),per_proof_staticcall_cap:'15000000',record_bytes:Buffer.byteLength(normal.record_jcs),rows,
 remaining:['complete valid S=0 signature fixture NOT_RUN','full Registry decoder/authorization/claim/storage/history/serializer/cost NOT_RUN','intrinsic transaction/finality/operating Source/versioned adoption NOT_RUN']});
