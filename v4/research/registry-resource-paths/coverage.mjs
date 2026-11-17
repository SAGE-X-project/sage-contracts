// Compiler-mapped start-line observations, not branch or protocol correctness coverage.
import assert from 'node:assert/strict';
export function coverage(output,input,visited){
 const summaries=Object.fromEntries(['Codec.sol','PathProbe.sol'].map(n=>[n,{all:new Set(),hit:new Set()}]));
 const containers=new Set();
 const walk=x=>{if(Array.isArray(x))x.forEach(walk);else if(x&&typeof x==='object'){if(['SourceUnit','ContractDefinition','FunctionDefinition','Block','ParameterList'].includes(x.nodeType))containers.add(x.src);Object.values(x).forEach(walk);}};
 Object.values(output.sources).forEach(s=>walk(s.ast));
 for(const [file,name,key]of [['Codec.sol','CodecControls','codec'],['PathProbe.sol','PathProbe','probe'],['PathProbe.sol','OrdinaryWallet','wallet']]){
  const item=output.contracts[file][name].evm.deployedBytecode,code=Buffer.from(item.object,'hex'),pcs=[];
  for(let pc=0;pc<code.length;){pcs.push(pc);const op=code[pc];pc+=1+(op>=0x60&&op<=0x7f?op-0x5f:0);}
  const previous=['-1','0','-1','',''];
  for(const [index,part]of item.sourceMap.split(';').entries()){
   if(index>=pcs.length)break;part.split(':').forEach((v,i)=>{if(v)previous[i]=v;});
   const [start,length,id]=previous.slice(0,3).map(Number),entry=Object.entries(output.sources).find(([,v])=>v.id===id);
   if(!entry||start<0||length<=0||containers.has(start+':'+length+':'+id)||!summaries[entry[0]])continue;
   const text=input.sources[entry[0]].content,line=text.slice(0,start).split('\n').length,content=text.split('\n')[line-1].trim();
   if(!content||content.startsWith('//'))continue;
   summaries[entry[0]].all.add(line);if(visited[key].has(pcs[index]))summaries[entry[0]].hit.add(line);
  }
 }
 return Object.fromEntries(Object.entries(summaries).map(([file,{all,hit}])=>{assert(all.size>0);return[file,{scope:'Mapped start lines from selected normal paths and finite codec units only; not branches, upstream crypto or full Registry behavior',executable:all.size,hit:[...hit].sort((a,b)=>a-b),missing:[...all].filter(v=>!hit.has(v)).sort((a,b)=>a-b),percent:100*hit.size/all.size}];}));
}
