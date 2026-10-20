import fs from 'node:fs';
import assert from 'node:assert/strict';
import {build,write,evidence,sha,identity} from './compile.mjs';
import {environment,normalScenario} from './run.mjs';
import {coverage} from './coverage.mjs';
const target=process.env.SAGE_EVM_FORK;assert(['paris','shanghai'].includes(target));const compiled=build(target);
const all={probe:new Set(),codec:new Set(),wallet:new Set()},scenarios=[];
const cases=[...([1,2,4,8].map(count=>({label:'bounded-'+count,count}))),
 {label:'full-128',count:128,full:true,lifecycle:true},
 {label:'late-first-insertion',count:127,grow:1,lateFirst:true},
 {label:'owned-wallet',count:1,kem:true,lifecycle:true,trace:true,wallet:true},
 {label:'last-signer',count:2,terminal:true,trace:true},
 {label:'max-grants',count:1,grantCount:128}];
for(const item of cases){
 const env=await environment(compiled,{trace:item.trace??false,prefix:item.label+'-'});
 const result=await normalScenario(env,item);for(const k of Object.keys(all))for(const pc of result.visited[k])all[k].add(pc);
 const selected=result.rows.filter(r=>r.category==='normal');assert(selected.every(r=>r.exception===null));
 const summary={label:item.label,parameters:item,rows:result.rows,transitions:result.witness.length,final_record_bytes:Buffer.byteLength(JSON.stringify(result.finalRecord)),instruction_trace:item.trace??false};
 scenarios.push(summary);write('scenario-'+item.label+'.json',summary);write('partial-results.json',scenarios);console.log(JSON.stringify({label:item.label,target,rows:selected.map(r=>({operation:r.name,gas:r.total_gas,execution:r.execution_gas,refund:r.refund_applied,ms:r.execution_ms}))}));
}
const unit=JSON.parse(fs.readFileSync(new URL('unit-visited.json',evidence)));assert.deepEqual(unit.identity,identity(compiled));for(const k of Object.keys(all))for(const pc of unit.visited[k])all[k].add(pc);
const input=JSON.parse(fs.readFileSync(new URL('paths-input.json',evidence))),lineCoverage=coverage(compiled.output,input,all);
write('solidity-coverage.json',lineCoverage);for(const c of Object.values(lineCoverage))assert(c.percent>=90,'mapped start-line coverage below90%');
write('visited.json',Object.fromEntries(Object.entries(all).map(([k,v])=>[k,[...v].sort((a,b)=>a-b)])));
const code=Object.fromEntries(Object.entries(compiled.contracts).flatMap(([f,v])=>Object.entries(v).filter(([,c])=>c.evm.deployedBytecode.object.length>0).map(([n,c])=>[f+':'+n,{bytes:c.evm.deployedBytecode.object.length/2,sha256:sha(Buffer.from(c.evm.deployedBytecode.object,'hex'))}])));
write('results.json',{scope:'Owned isolated VM type2 simulated transactions and normal-state probe composition; not a production Registry, public deployment, finality/Source or conformance',target,compiler:compiled.version,node:process.version,experimental_block_and_transaction_cap:'5000000000',verifier_call_cap:'15000000',code,scenarios,remaining:['full valid S=0 fixture NOT_RUN','complete production decoder/URI/optional algorithms/custom error guards NOT_IMPLEMENTED','optional ERC companion/payment-wallet costs NOT_RUN','public deployment/constructor/finality/Source/operating budget NOT_RUN','not an exhaustive scalar/input gas bound']});
