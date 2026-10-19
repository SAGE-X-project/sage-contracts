"""Offline evidence-tool scenarios. No network, keys or runtime attack traffic."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import trace
import unittest
from unittest.mock import patch
import prepare
import check_source_coverage as source_coverage

class ToolTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);(self.root/'evidence').mkdir()
 def prepare_run(self,existing=None,download=b'fixed public input'):
  data=b'fixed public input';files={'evidence/input':('https://fixture.invalid/input',hashlib.sha256(data).hexdigest())}
  if existing is not None:(self.root/'evidence/input').write_bytes(existing)
  with patch.object(prepare,'ROOT',self.root),patch.object(prepare,'FILES',files),patch.object(prepare.subprocess,'check_output',**({'side_effect':download} if isinstance(download,Exception) else {'return_value':download})) as fetch:
   prepare.main()
  receipt=json.loads((self.root/'evidence/source-receipt.json').read_text())
  self.assertEqual(receipt['files']['evidence/input']['sha256'],hashlib.sha256(data).hexdigest())
  return fetch
 def test_fixed_cache_avoids_network(self):
  self.assertEqual(self.prepare_run(b'fixed public input').call_count,0)
 def test_missing_download_checked_before_persist(self):
  fetch=self.prepare_run();self.assertEqual(fetch.call_count,1)
  self.assertIn('--max-filesize',fetch.call_args.args[0])
 def test_corrupt_cache_replaced(self):
  self.assertEqual(self.prepare_run(b'corrupt').call_count,1)
 def test_bad_digest_never_receipted(self):
  with self.assertRaises(AssertionError):self.prepare_run(download=b'wrong')
  self.assertFalse((self.root/'evidence/source-receipt.json').exists())
  self.assertFalse((self.root/'evidence/input').exists())
 def test_download_error_never_receipted(self):
  with self.assertRaises(subprocess.CalledProcessError):self.prepare_run(download=subprocess.CalledProcessError(22,['curl']))
  self.assertFalse((self.root/'evidence/source-receipt.json').exists())
 def fixture(self,visited):
  text='// comment\ncontract Example {\n    return true;\n\n}\n'
  (self.root/'StrictEd25519.sol').write_text(text)
  loc=lambda start,length,source=0:f'{start}:{length}:{source}'
  whole=loc(0,len(text)); statement=loc(text.index('return'),11)
  ast={'nodeType':'SourceUnit','src':whole,'nodes':[{'nodeType':'ContractDefinition','src':loc(text.index('contract'),len(text)-11),'children':[{'nodeType':'FunctionDefinition','src':loc(11,4),'body':{'nodeType':'Block','src':loc(15,3),'parameters':{'nodeType':'ParameterList','src':loc(18,1)},'struct':{'nodeType':'StructDefinition','src':loc(19,1)}}}]}]}
  # PUSH1 payload must not be counted as an instruction. Empty entries inherit maps.
  mapping=';'.join([whole,statement,'','0:10:0','0:1:1','0:0:0','-1:0:-1',loc(text.index('\n\n')+1,1)])
  output={'sources':{'StrictEd25519.sol':{'ast':ast,'id':0}},'contracts':{'StrictEd25519.sol':{'Example':{'evm':{'deployedBytecode':{'object':'600100000000000000','sourceMap':mapping}}}}}}
  for target in ['paris','shanghai']:
   (self.root/'evidence'/f'{target}-output.json').write_text(json.dumps(output))
   (self.root/'evidence'/f'{target}-input.json').write_text(json.dumps({'sources':{'StrictEd25519.sol':{'content':text}}}))
   (self.root/'evidence'/f'{target}-visited-pcs.json').write_text(json.dumps({'Example':visited}))
 def test_pc_width_inheritance_and_container_filter(self):
  self.fixture([2])
  with patch.object(source_coverage,'ROOT',self.root):source_coverage.main()
  data=json.loads((self.root/'evidence/coverage.json').read_text())
  self.assertTrue(all(row['percent']==100 and row['hit_lines']==[3] for row in data))
 def test_missing_line_refuses_acceptance(self):
  self.fixture([0])
  with patch.object(source_coverage,'ROOT',self.root),self.assertRaises(SystemExit):source_coverage.main()
  data=json.loads((self.root/'evidence/coverage.json').read_text());self.assertEqual(data[0]['missing_lines'],[3])
 def test_empty_mapping_cannot_claim_full_coverage(self):
  self.fixture([2])
  for target in ['paris','shanghai']:
   p=self.root/'evidence'/f'{target}-output.json';data=json.loads(p.read_text())
   data['contracts']['StrictEd25519.sol']['Example']['evm']['deployedBytecode']['sourceMap']='0:0:0'
   p.write_text(json.dumps(data))
  with patch.object(source_coverage,'ROOT',self.root),self.assertRaises(AssertionError):source_coverage.main()
 def test_changed_source_refuses_old_evidence(self):
  self.fixture([2]);(self.root/'StrictEd25519.sol').write_text('changed source')
  with patch.object(source_coverage,'ROOT',self.root),self.assertRaises(AssertionError):source_coverage.main()

if __name__=='__main__':
 tracer=trace.Trace(count=True,trace=False,ignoredirs=[])
 with contextlib.redirect_stdout(io.StringIO()):program=tracer.runfunc(unittest.main,exit=False)
 if not program.result.wasSuccessful():raise SystemExit(1)
 results=tracer.results();rows=[]
 for name in ['prepare.py','check_source_coverage.py']:
  file=Path(__file__).parent/name
  executable=set(trace._find_executable_linenos(str(file)))
  hits={line for (filename,line),count in results.counts.items() if Path(filename).resolve()==file.resolve() and count>0}
  # Module definitions/imports execute before tracing; measure them in a separate import run.
  import runpy
  with contextlib.redirect_stdout(io.StringIO()):tracer.runfunc(runpy.run_path,str(file),run_name='coverage_import')
  hits={line for (filename,line),count in tracer.results().counts.items() if Path(filename).resolve()==file.resolve() and count>0}
  rows.append({'file':name,'sha256':hashlib.sha256(file.read_bytes()).hexdigest(),'scope':'stdlib trace executable-line coverage; unit scenarios plus module import','hit_lines':sorted(hits&executable),'missing_lines':sorted(executable-hits),'percent':100*len(hits&executable)/len(executable)})
 evidence=Path(__file__).parent/'evidence';evidence.mkdir(exist_ok=True)
 (evidence/'python-coverage.json').write_text(json.dumps(rows,indent=2)+'\n')
 print(json.dumps(rows,indent=2))
 if not all(row['percent']>=90 for row in rows):raise SystemExit('Python tool coverage below 90%')
