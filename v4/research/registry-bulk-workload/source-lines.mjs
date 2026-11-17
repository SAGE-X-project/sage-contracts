// Compiler source-map start-line observation; not branch/correctness coverage.
import assert from 'node:assert/strict';
export function sourceLines(output, visited) {
  const source=output.sources['Batch.sol'],text=output.__source,containers=new Set();
  const walk=value=>{
    if(Array.isArray(value)) { for(const child of value) walk(child); }
    else if(value && typeof value==='object') {
      if(['SourceUnit','ContractDefinition','FunctionDefinition','Block','ParameterList'].includes(value.nodeType)) containers.add(value.src);
      for(const child of Object.values(value)) walk(child);
    }
  };
  walk(source.ast);
  const object=output.contracts['Batch.sol'].BatchProbe.evm.deployedBytecode, code=Buffer.from(object.object,'hex'),pcs=[];
  for(let pc=0;pc<code.length;) { pcs.push(pc); const op=code[pc]; pc+=1+(op>=0x60 && op<=0x7f ? op-0x5f : 0); }
  const all=new Set(),hit=new Set(),previous=['-1','0','-1','',''];
  for(const [index,part] of object.sourceMap.split(';').entries()) {
    if(index>=pcs.length) break;
    for(const [field,value] of part.split(':').entries()) if(value) previous[field]=value;
    const [start,length,id]=previous.slice(0,3).map(Number);
    if(id!==source.id || start<0 || length<=0 || containers.has(`${start}:${length}:${id}`)) continue;
    const line=text.slice(0,start).split('\n').length,content=text.split('\n')[line-1].trim();
    if(!content || content.startsWith('//')) continue;
    all.add(line); if(visited.has(pcs[index])) hit.add(line);
  }
  assert(all.size>0,'no executable mapped start lines');
  return {scope:'BatchProbe mapped start-line coverage only, bulk untraced; not underlying verifier or branch coverage',executable:all.size,hit:[...hit].sort((a,b)=>a-b),missing:[...all].filter(v=>!hit.has(v)).sort((a,b)=>a-b),percent:100*hit.size/all.size};
}
