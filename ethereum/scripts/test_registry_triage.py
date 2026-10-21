"""Fixed data scenarios only; no EVM, input producer, network or submission."""
from pathlib import Path
import copy,json,runpy,unittest,tempfile
from unittest.mock import patch
from registry_triage import check,reports,FINDING,commit_parents
root=Path(__file__).resolve().parents[1]
source=(root/'contracts/chain-registry/ChainRegistry.sol').read_bytes()
triage=json.loads((root/'slither.db.json').read_text())
config=json.loads((root/'.slither.config.json').read_text())
class InvariantTests(unittest.TestCase):
 def test_exact_review(self):check(source,triage,config)
 def test_changed_core(self):
  with self.assertRaises(AssertionError):check(source+b'\n',triage,config)
 def test_second_finding(self):
  with self.assertRaises(AssertionError):check(source,triage+triage,config)
 def test_different_id(self):
  changed=copy.deepcopy(triage);changed[0]['id']='0'*64
  with self.assertRaises(AssertionError):check(source,changed,config)
 def test_different_detector(self):
  changed=copy.deepcopy(triage);changed[0]['check']='unused-return'
  with self.assertRaises(AssertionError):check(source,changed,config)
 def test_changed_review_hash(self):
  changed=copy.deepcopy(triage);changed[0]['sage_review']['source_sha256']='0'*64
  with self.assertRaises(AssertionError):check(source,changed,config)
 def test_other_high_suppression(self):
  changed=copy.deepcopy(triage);changed[0]['sage_review']['other_high_findings_suppressed']=True
  with self.assertRaises(AssertionError):check(source,changed,config)
 def test_severity_disabled(self):
  changed=copy.deepcopy(config);changed['exclude_high']=True
  with self.assertRaises(AssertionError):check(source,triage,changed)
 def test_detector_disabled(self):
  changed=copy.deepcopy(config);changed['detectors_to_exclude']+=',msg-value-in-nonpayable'
  with self.assertRaises(AssertionError):check(source,triage,changed)
 def test_changed_description(self):
  changed=copy.deepcopy(triage);changed[0]['description']='Another finding'
  with self.assertRaises(AssertionError):check(source,changed,config)
 def test_another_exclusion(self):
  changed=copy.deepcopy(config);changed['detectors_to_exclude']+=',arbitrary-send-eth'
  with self.assertRaises(AssertionError):check(source,triage,changed)
 def test_actual_guard_entry(self):runpy.run_path(str(root/'scripts/registry_triage.py'),run_name='__main__')
class ReportTests(unittest.TestCase):
 def setUp(self):
  self.row={'id':FINDING,'check':'msg-value-in-nonpayable','impact':'High','description':triage[0]['description']}
  self.other={'id':'fixed-medium','check':'unused-return','impact':'Medium','description':'Fixed unit observation'}
  self.raw={'success':True,'error':None,'results':{'detectors':[self.row,self.other]}}
  self.after={'success':True,'error':None,'results':{'detectors':[self.other]}}
 def test_raw(self):self.assertEqual(reports(self.raw)['reviewed_high_count'],1)
 def test_exact_difference(self):self.assertEqual(reports(self.raw,self.after)['excluded_ids'],[FINDING])
 def test_unknown_high(self):
  self.raw['results']['detectors'].append({'id':'unknown-high','impact':'High'})
  with self.assertRaises(AssertionError):reports(self.raw,self.after)
 def test_analysis_failure(self):
  self.raw['success']=False
  with self.assertRaises(AssertionError):reports(self.raw,self.after)
 def test_duplicate_id(self):
  self.raw['results']['detectors'].append(self.other)
  with self.assertRaises(AssertionError):reports(self.raw,self.after)
 def test_missing_other_finding(self):
  self.after['results']['detectors']=[]
  with self.assertRaises(AssertionError):reports(self.raw,self.after)
 def test_other_details_changed(self):
  self.after=copy.deepcopy(self.after);self.after['results']['detectors'][0]['description']='Changed'
  with self.assertRaises(AssertionError):reports(self.raw,self.after)
 def test_report_cli_modes(self):
  with tempfile.TemporaryDirectory()as name:
   raw=Path(name)/'raw.json';after=Path(name)/'after.json'
   raw.write_text(json.dumps(self.raw));after.write_text(json.dumps(self.after))
   for args in [['raw',str(raw),'255'],['compare',str(raw),str(after)]]:
    with patch('sys.argv',['registry_triage.py',*args]):runpy.run_path(str(root/'scripts/registry_triage.py'),run_name='__main__')
 def test_triaged_analysis_failure(self):
  self.after['success']=False
  with self.assertRaises(AssertionError):reports(self.raw,self.after)
class ParentHeaderTests(unittest.TestCase):
 def test_root_header(self):self.assertEqual(commit_parents('tree '+'a'*40+'\n\nparent '+'b'*40),[])
 def test_single_parent(self):self.assertEqual(commit_parents('tree '+'a'*40+'\nparent '+'b'*40+'\nauthor Example\n\nbody'),['b'*40])
 def test_merge_and_signature(self):self.assertEqual(commit_parents('tree '+'a'*40+'\nparent '+'b'*40+'\nparent '+'c'*40+'\ngpgsig signature\n parent '+'d'*40+'\n\nparent '+'e'*40),['b'*40,'c'*40])
 def test_invalid_parent(self):
  with self.assertRaises(AssertionError):commit_parents('tree '+'a'*40+'\nparent invalid\n\nbody')
suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(kind) for kind in [InvariantTests,ReportTests,ParentHeaderTests]])
assert unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful()
