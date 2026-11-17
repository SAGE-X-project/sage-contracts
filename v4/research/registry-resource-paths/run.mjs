import assert from 'node:assert/strict';
import fs from 'node:fs';
import {keccak_256} from '@noble/hashes/sha3.js';
import {createVM,runTx} from '@ethereumjs/vm';
import {Common,Mainnet,Hardfork} from '@ethereumjs/common';
import {createBlock} from '@ethereumjs/block';
import {createFeeMarket1559Tx} from '@ethereumjs/tx';
import {createAddressFromString,createAddressFromPrivateKey,createAccount} from '@ethereumjs/util';
import {call,output,tuple} from './abi.mjs';
import {agent,did,registry,json,digest,b64,initial,publicKey,key,services} from './fixture.mjs';
import {sha,write,evidence} from './compile.mjs';
export const addresses={strict:createAddressFromString('0x0000000000000000000000000000000000001000'),wallet:createAddressFromString('0x0000000000000000000000000000000000002000'),probe:createAddressFromString('0x0000000000000000000000000000000000003000'),codec:createAddressFromString('0x0000000000000000000000000000000000004000')};
const secret=i=>digest(Buffer.from('SAGE ordinary isolated VM sender public recipe '+i));
export const senders=[0,1].map(i=>createAddressFromPrivateKey(secret(i)));
export async function environment(compiled,{trace=false,prefix=''}={}){
 const common=new Common({chain:Mainnet,hardfork:compiled.target==='paris'?Hardfork.Paris:Hardfork.Shanghai});
 const vm=await createVM({common});const items={probe:compiled.contracts['PathProbe.sol'].PathProbe,wallet:compiled.contracts['PathProbe.sol'].OrdinaryWallet,codec:compiled.contracts['Codec.sol'].CodecControls};
 await vm.stateManager.putCode(addresses.strict,compiled.code);
 for(const [name,item]of Object.entries(items)){const code=Buffer.from(item.evm.deployedBytecode.object,'hex');assert(code.length<=24576,name+' exceeds code-size limit');await vm.stateManager.putCode(addresses[name],code);}
 for(const a of senders)await vm.stateManager.putAccount(a,createAccount({balance:10n**30n}));
 const visited={probe:new Set(),codec:new Set(),wallet:new Set()};
 if(trace)vm.evm.events.on('step',(s,next)=>{for(const n of Object.keys(visited))if(s.address.equals(addresses[n]))visited[n].add(s.pc);next?.();});
 let height=1n,index=0;const rows=[];
 const transact=async(name,values,{sender=0,wallet=false,target='probe',expectSuccess=true,category='normal',data:provided}={})=>{
  const inner=provided??call(items[target].abi,name,values),data=wallet?call(items.wallet.abi,'invoke',[inner]):inner,to=wallet?addresses.wallet:addresses[target];
  const nonce=(await vm.stateManager.getAccount(senders[sender])).nonce;
  const tx=createFeeMarket1559Tx({chainId:1n,nonce,to,data,gasLimit:5_000_000_000n,maxFeePerGas:2n,maxPriorityFeePerGas:1n,value:0n,accessList:[]},{common}).sign(secret(sender));
  assert(tx.getSenderAddress().equals(senders[sender]));const block=createBlock({header:{number:height++,timestamp:10000n+height,gasLimit:5_000_000_000n,baseFeePerGas:1n}},{common});
  const start=performance.now(),result=await runTx(vm,{tx,block});
  const intrinsic=tx.getIntrinsicGas(),beforeRefund=result.execResult.executionGasUsed+intrinsic,rawRefund=result.gasRefund;
  const refundApplied=rawRefund<beforeRefund/5n?rawRefund:beforeRefund/5n;assert.equal(result.totalGasSpent,beforeRefund-refundApplied);
  const row={index:index++,name,category,target,wallet,caller:(wallet?addresses.wallet:senders[sender]).toString(),outer_sender:senders[sender].toString(),block_number:block.header.number.toString(),timestamp:block.header.timestamp.toString(),transaction_type:tx.type,transaction_hash:Buffer.from(tx.hash()).toString('hex'),calldata_bytes:data.length,calldata_sha256:sha(data),inner_calldata_sha256:sha(inner),execution_gas:result.execResult.executionGasUsed.toString(),total_gas:result.totalGasSpent.toString(),gas_refund_raw:rawRefund.toString(),refund_applied:refundApplied.toString(),intrinsic_gas:intrinsic.toString(),exception:result.execResult.exceptionError?.error??null,return_hex:Buffer.from(result.execResult.returnValue).toString('hex'),logs:(result.execResult.logs??[]).map(([a,t,d])=>({address:Buffer.from(a).toString('hex'),topics:t.map(x=>Buffer.from(x).toString('hex')),data:Buffer.from(d).toString('hex')})),execution_ms:Math.round(performance.now()-start)};
  rows.push(row);write(prefix+'partial.json',rows);fs.writeFileSync(new URL(prefix+'call-'+row.index+'.hex',evidence),data.toString('hex')+'\n');
  assert.equal(row.exception===null,expectSuccess,JSON.stringify(row));
  const raw=Buffer.from(row.return_hex,'hex'),innerResult=wallet&&row.exception===null?output(items.wallet.abi,'invoke',raw)[0]:raw;
  return {row,decoded:row.exception===null?output(items[target].abi,name,innerResult):[]};
 };
 await transact('initialize',[],{category:'setup'});await transact('initialize',[],{target:'wallet',category:'setup'});
 return {vm,items,transact,rows,visited,compiled};
}
const grant=(operator,scope)=>({operator,scope});
function sorted(list){return list.sort((a,b)=>a.operator.localeCompare(b.operator)||a.scope.localeCompare(b.scope));}
export async function normalScenario(env,{count=1,full=false,wallet=false,lifecycle=false,grow=0,kem=false,terminal=false,lateFirst=false,grantCount=0,label='ordinary'}={}){
 const actor=(wallet?addresses.wallet:senders[0]).toString(),fix=initial(actor,count,{full,kem,expiredSecond:terminal}),expected=structuredClone(fix.record);let grants=[];let version=0;
 const witness=[];write(label+'-fixture.json',JSON.parse(json({...fix,keys:fix.keys.map(k=>({...k,key:k.key.toString('hex'),proof:k.proof.toString('hex'),expires:k.expires.toString(),challenge:k.challenge.toString('hex')})),salt:fix.salt.toString('hex'),commitment:fix.commitment.toString('hex')})));
 const change=async(name,values,operation,args,apply,{sender=0,removed=[],target=null}={})=>{
  const prior=version;apply();version++;expected.version=String(version);
  const result=await env.transact(name,values,{wallet,sender});assert.deepEqual(result.decoded,[BigInt(version)]);
  const caller=(wallet?addresses.wallet:senders[sender]).toString();
  const command={actor:caller,arguments:args,binding:'sage-registry-chain-0.11.0',did,expectedVersion:prior?String(prior):'',operation,registry};
  const entry={actor:caller,admitted:Number(result.row.timestamp),automaticRemovals:removed,commandDigest:b64(digest(Buffer.from(json(command)))),grantsDigest:b64(digest(Buffer.from(json(grants)))),operation,previousVersion:prior?String(prior):'',recordDigest:b64(digest(Buffer.from(json(expected)))),target,version:String(version)};
  const read=await env.transact('record',[agent],{category:'read'});assert.equal(read.decoded[0],true);assert.equal(read.decoded[1].toString(),json(expected));
  const view=await env.transact('activeGrants',[agent],{category:'read'});assert.equal(view.decoded[0].toString(),json(grants));
  const history=await env.transact('historyItem',[agent,version],{category:'read'});assert.equal(history.decoded[0].toString(),json(entry));assert.equal(history.decoded[1].toString(),json(command));
  const events=result.row.logs.filter(x=>x.address===addresses.probe.toString().slice(2));assert.equal(events.length,1);
  assert.deepEqual(events[0],{address:addresses.probe.toString().slice(2),topics:[Buffer.from(keccak_256(Buffer.from('Changed(address,uint64,bytes32,bytes32,bytes32)'))).toString('hex')],data:tuple([{type:'address'},{type:'uint64'},...Array.from({length:3},()=>({type:'bytes32'}))],[caller,BigInt(version),digest(Buffer.from(json(command))),digest(Buffer.from(json(expected))),digest(Buffer.from(json(grants)))]).toString('hex')});
  witness.push({operation,version,record_bytes:Buffer.byteLength(json(expected)),record:expected,grants,command,entry,mutation_row:result.row.index,read_rows:[read.row.index,view.row.index,history.row.index]});
  // Capture immutable independent expected values, never references mutated later.
  witness[witness.length-1]=JSON.parse(json(witness[witness.length-1]));write(label+'-witness.json',witness);
 };
 const commit=await env.transact('commitClaim',[fix.commitment],{wallet});assert.deepEqual(commit.decoded,[]);
 await change('revealClaim',[agent,actor,fix.keys,fix.services,fix.salt],'create',{controller:actor,keys:fix.record.keys,salt:b64(fix.salt),services:fix.record.services},()=>{});
 if(lifecycle||grow||terminal||grantCount){
  const operator=senders[1].toString();
  await change('authorizeOperator',[agent,version,operator,'activate'],'authorize-operator',grant(operator,'activate'),()=>{grants=sorted([...grants,grant(operator,'activate')]);},{target:grant(operator,'activate')});
  const removed=[...grants];await change('activate',[agent,version],'activate',{},()=>{expected.state='active';grants=[];},{sender:wallet?0:1,removed});
  for(let i=count;i<count+grow;++i){const next=key(i,{name:lateFirst?'b'.repeat(32):null});await change('addKey',[agent,version,next],'add-key',{key:publicKey(next)},()=>{expected.keys.push(publicKey(next));expected.keys.sort((a,b)=>a.name.localeCompare(b.name));});}
  if(terminal){await change('revokeKey',[agent,version,fix.keys[0].name],'revoke-key',{name:fix.keys[0].name},()=>{expected.keys[0].state='revoked';expected.state='deactivated';grants=[];});}
  if(grantCount){for(let i=0;i<grantCount;++i){const op=createAddressFromPrivateKey(secret(2+Math.floor(i/4))).toString(),scope=['add-key','revoke-key','update-services','deactivate'][i%4];await change('authorizeOperator',[agent,version,op,scope],'authorize-operator',grant(op,scope),()=>{grants=sorted([...grants,grant(op,scope)]);},{target:grant(op,scope)});}const removed=[...grants];await change('deactivate',[agent,version],'deactivate',{},()=>{expected.state='deactivated';grants=[];},{removed});}
  if(lifecycle){
   const added=count+grow<128?key(128):fix.keys.at(-1);
   if(count+grow<128)await change('addKey',[agent,version,added],'add-key',{key:publicKey(added)},()=>{expected.keys.push(publicKey(added));expected.keys.sort((a,b)=>a.name.localeCompare(b.name));});
   const rotated=services(3);await change('updateServices',[agent,version,rotated],'update-services',{services:rotated.map(({name,serviceType:type,uri})=>({name,type,uri}))},()=>{expected.services=rotated.map(({name,serviceType:type,uri})=>({name,type,uri}));});
   for(const scope of ['update-services','deactivate'])await change('authorizeOperator',[agent,version,operator,scope],'authorize-operator',grant(operator,scope),()=>{grants=sorted([...grants,grant(operator,scope)]);},{target:grant(operator,scope)});
   await change('revokeOperator',[agent,version,operator,'update-services'],'revoke-operator',grant(operator,'update-services'),()=>{grants=grants.filter(g=>g.scope!=='update-services');},{target:grant(operator,'update-services')});
   await change('revokeKey',[agent,version,added.name],'revoke-key',{name:added.name},()=>{expected.keys.find(k=>k.name===added.name).state='revoked';});
   const clear=[...grants];await change('deactivate',[agent,version],'deactivate',{},()=>{expected.state='deactivated';grants=[];},{removed:clear});
  }
 }
 return {witness,rows:env.rows,visited:env.visited,finalRecord:expected};
}
