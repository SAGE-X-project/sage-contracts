"""Report compiled source-map line hits, not branch or cryptographic correctness."""
from pathlib import Path
import json,hashlib
ROOT=Path(__file__).resolve().parent
def main():
 evidence=ROOT/'evidence';text=(ROOT/'StrictEd25519.sol').read_text();containers=set()
 def walk(value):
  if isinstance(value,dict):
   if value.get('nodeType')in ['SourceUnit','ContractDefinition','FunctionDefinition','Block','ParameterList','StructDefinition']:
    s,l,f=map(int,value['src'].split(':'));containers.add((s,l,f))
   for v in value.values():walk(v)
  elif isinstance(value,list):
   for v in value:walk(v)
 result=[]
 for target in ['paris','shanghai']:
  input_data=json.loads((evidence/(target+'-input.json')).read_text());assert input_data['sources']['StrictEd25519.sol']['content']==text,'source differs from compiler input'
  output=json.loads((evidence/(target+'-output.json')).read_text());walk(output['sources']['StrictEd25519.sol']['ast']);source_id=output['sources']['StrictEd25519.sol']['id'];visited=json.loads((evidence/(target+'-visited-pcs.json')).read_text());all_lines=set();hits=set()
  for name,contract in output['contracts']['StrictEd25519.sol'].items():
   obj=contract['evm']['deployedBytecode'];code=bytes.fromhex(obj['object']);pcs=[];pc=0
   while pc<len(code):
    pcs.append(pc);opcode=code[pc];pc+=1+(opcode-0x5f if 0x60<=opcode<=0x7f else 0)
   previous=['-1','0','-1','',''];maps=obj['sourceMap'].split(';')
   for offset,part in enumerate(maps):
    if offset>=len(pcs):break
    cols=part.split(':')
    for i,col in enumerate(cols):
     if col:previous[i]=col
    start,length,fileid=map(int,previous[:3])
    if fileid!=source_id or start<0 or length<=0 or(start,length,fileid)in containers:continue
    # Record the start line of each non-container compiler source location.
    line=text.count('\n',0,start)+1
    if not text.splitlines()[line-1].strip()or text.splitlines()[line-1].lstrip().startswith(('//','///')):continue
    all_lines.add(line)
    if pcs[offset]in visited[name]:hits.add(line)
  assert all_lines,'no mapped executable lines'
  missing=sorted(all_lines-hits);percent=100*len(hits)/len(all_lines)
  result.append({'target':target,'scope':'compiled source-map start-line coverage of evaluation Solidity only; not branch coverage','source_sha256':hashlib.sha256(text.encode()).hexdigest(),'executable_mapped_lines':len(all_lines),'hit_lines':sorted(hits),'missing_lines':missing,'percent':percent})
 (evidence/'coverage.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
 if not all(v['percent']>=90 for v in result):raise SystemExit('Solidity evaluation source-map line coverage below 90%')

if __name__=='__main__':main()
