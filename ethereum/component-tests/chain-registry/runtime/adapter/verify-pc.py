"""Read-only fixed adapter PC/source-map observations; no runtime/coverage upgrade."""
from pathlib import Path
import json,hashlib
root=Path(__file__).resolve().parent;runtime=root.parent
read=lambda p:json.loads(p.read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
statements={'Break','Continue','DoWhileStatement','EmitStatement','ExpressionStatement','ForStatement','IfStatement','InlineAssembly','Return','RevertStatement','TryStatement','VariableDeclarationStatement','WhileStatement'}
def walk(value):
 if isinstance(value,dict):
  yield value
  for child in value.values():yield from walk(child)
 elif isinstance(value,list):
  for child in value:yield from walk(child)
def instructions(code):
 out=[];pc=0
 while pc<len(code):
  out.append(pc);opcode=code[pc];pc+=1+(opcode-0x5f if 0x60<=opcode<=0x7f else 0)
 return out
def mappings(code,source_map):
 pcs=instructions(code);previous=['0','0','-1','',''];rows={}
 for index,fragment in enumerate(source_map.split(';')):
  assert index<len(pcs),'More source-map fragments than bytecode instructions'
  incoming=fragment.split(':');row=[incoming[i] if i<len(incoming) and incoming[i]!='' else previous[i] for i in range(5)]
  start,length,source=map(int,row[:3]);assert start>=-1 and length>=-1 and source>=-1
  if source>=0:assert start>=0 and length>=0
  rows[pcs[index]]=(start,length,source);previous=row
 return set(pcs),rows
manifest=read(runtime/'source-identities.json');repo=runtime.parents[3]
for group in ['source_files_sha256','tool_files_sha256']:
 for name,digest in manifest[group].items():
  p=repo/name;assert not Path(name).is_absolute() and '..' not in Path(name).parts and p.is_file() and not p.is_symlink() and sha(p)==digest,name
assert manifest['tool_files_sha256'][str(Path(__file__).resolve().relative_to(repo))]==sha(Path(__file__))
check=read(runtime/'evidence/compiler-check.json');assert check['verified'] is True and check['source_manifest_sha256']==sha(runtime/'source-identities.json')
compiler=runtime/'evidence/compiler'
for name,digest in check['evidence_files_sha256'].items():assert '/' not in name and sha(compiler/name)==digest
fixed=read(root/'goldens.json');assert len(fixed['cases'])==255 and len(fixed['skipped'])==137
policy={'max_input_bytes':1024,'max_expected_output_bytes':1024,'max_steps':2048,'max_memory_bytes':4096}
baseline=read(runtime/'fixtures/expected-modules.json');results={}
for target in ['paris','shanghai']:
 compiled=read(compiler/(target+'-output.json'));evidence=runtime/'evidence/adapter'
 observed=read(evidence/(target+'-result.json'));prefix=read(evidence/(target+'-pc-prefix.json'))
 rows=[json.loads(line)for line in (evidence/(target+'-rows.jsonl')).read_text().splitlines()]
 assert observed['complete'] is True and observed['cases']==255 and len(rows)==255 and prefix['cases_completed']==255
 assert observed['source_manifest_sha256']==sha(runtime/'source-identities.json') and observed['compiler_check_sha256']==sha(runtime/'evidence/compiler-check.json')
 assert observed['goldens_sha256']==sha(root/'goldens.json') and observed['rows_sha256']==sha(evidence/(target+'-rows.jsonl'))
 assert observed['pc_prefix_sha256']==sha(evidence/(target+'-pc-prefix.json'))
 assert observed['pc_policy']==prefix['policy']==policy
 traced=[];untraced=[]
 assert observed['skipped_data_cases']==137 and observed['PC_observations_recorded'] is True and observed['coverage_percent'] is None
 assert set(prefix['visited'])=={'RegistryRules','RegistryRenderer'}
 for index,(row,golden)in enumerate(zip(rows,fixed['cases'])):
  assert row['index']==index and all(row[name]==golden[name]for name in ['name','contract','method'])
  assert row['exception']==row['expected_exception']==golden['exception']
  assert row['return_hex']==row['expected_return_hex']==golden['expected_return_hex']
  assert hashlib.sha256(bytes.fromhex(row['input_hex'])).hexdigest()==row['input_sha256']
  assert 0<=int(row['execution_gas'])<=int(row['gas_limit'])==250000000
  assert row['logs']==[]
  info=row['pc_trace'];eligible=len(bytes.fromhex(row['input_hex']))<=policy['max_input_bytes'] and len(bytes.fromhex(golden['expected_return_hex']))<=policy['max_expected_output_bytes']
  assert type(info['eligible'])is bool and info['eligible']==eligible
  assert type(info['steps'])is int and type(info['max_memory_bytes'])is int and info['max_memory_bytes']>=0
  if not eligible:assert info=={'eligible':False,'steps':0,'max_memory_bytes':0,'stop':'size'}
  else:
   assert 1<=info['steps']<=policy['max_steps']
   if info['stop']=='memory':assert info['max_memory_bytes']>policy['max_memory_bytes']
   elif info['stop']=='steps':assert info['steps']==policy['max_steps'] and info['max_memory_bytes']<=policy['max_memory_bytes']
   else:assert info['stop']=='complete' and info['steps']<policy['max_steps'] and info['max_memory_bytes']<=policy['max_memory_bytes']
  (traced if eligible else untraced).append({'index':index,'name':row['name']})
 assert prefix['traced']==traced and prefix['untraced']==untraced and len(traced)+len(untraced)==255
 assert traced,'No PC observations were eligible'
 hits=[];subjects={}
 for contract,role in [('RegistryRules','RULES'),('RegistryRenderer','RENDERER')]:
  artifact=compiled['contracts']['ethereum/contracts/chain-registry/'+contract+'.sol'][contract]
  bytecode=artifact['evm']['deployedBytecode'];code=bytes.fromhex(bytecode['object'])
  digest=hashlib.sha256(code).hexdigest();assert digest==baseline['targets'][target][role]['runtime_sha256']==observed['runtime_sha256'][contract]
  assert not bytecode.get('immutableReferences')
  assert all(row['runtime_sha256']==digest for row in rows if row['contract']==contract)
  visited=prefix['visited'][contract];assert visited==sorted(set(visited)) and all(type(pc)is int and pc>=0 for pc in visited)
  pcs,mapped=mappings(code,bytecode['sourceMap']);assert set(visited)<=pcs
  hits.extend(mapped[pc]for pc in visited if pc in mapped)
  subjects[contract]={'runtime_sha256':digest,'visited_pcs':visited,'mapped_pcs':len(set(visited)&mapped.keys()),'unmapped_pcs':sorted(set(visited)-mapped.keys())}
 sources={};total=covered=0
 for name,source in compiled['sources'].items():
  if name not in manifest['source_files_sha256']:continue
  records=[]
  for node in walk(source['ast']):
   if node.get('nodeType')not in statements:continue
   start,length,file=map(int,node['src'].split(':'));assert file==source['id'] and start>=0 and length>=0
   hit=any(file==f and size>0 and pos>=start and pos+size<=start+length for pos,size,f in hits)
   records.append({'id':node['id'],'type':node['nodeType'],'start':start,'length':length,'file':file,'covered':hit})
  n=sum(row['covered']for row in records);total+=len(records);covered+=n
  sources[name]={'source_id':source['id'],'source_sha256':manifest['source_files_sha256'][name],'statements':records,'covered':n,'total':len(records),'percent':100*n/len(records)if records else None}
 assert len(sources)==29 and total>0
 results[target]={'subjects':subjects,'sources':sources,'covered':covered,'total':total,'percent':100*covered/total,'required_percent':90,'whole_registry_coverage_qualified':False,'scope':'Conservative contained AST statement observations for only two pure module runtimes; all29 source denominators retained, no Registry admission/operating verdict'}
print(json.dumps({'scope':'Fixed stateless unit PC observations only; independent semantic ABI/expected-value validation remains a separate review','targets':results,'skipped_data_cases':137,'fixed5_complete':False,'operating_ready':False},separators=(',',':')))
