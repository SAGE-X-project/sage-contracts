"""Fixed data and CLI exit scenarios; no analyzer, VM, transaction or network."""
from pathlib import Path
import hashlib,json,os,runpy,sys,tempfile,types,unittest
from unittest.mock import patch
import registry_slither as subject

class OrderTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);self.source=self.root/'detector.py';self.source.write_bytes(b'fixed unit detector source')
  self.expected=hashlib.sha256(self.source.read_bytes()).hexdigest();self.observed=[]
  class Detector:
   def _build_info(self,function,callers):return (function,callers)
  self.detector=Detector
  self.function=types.SimpleNamespace(canonical_name='Fixed.context()')
 def install(self):
  with patch.object(subject,'DETECTOR_SHA256',self.expected):subject.install(self.detector,self.source,self.observed)
 def test_order_preserves_callers(self):
  self.install();callers=[types.SimpleNamespace(canonical_name=name)for name in ['B.b()','A.a()']]
  function,actual=self.detector()._build_info(self.function,callers)
  self.assertIs(function,self.function);self.assertEqual(actual,[callers[1],callers[0]])
  self.assertEqual([v.canonical_name for v in callers],['B.b()','A.a()'])
  self.assertEqual(self.observed,[{'function':'Fixed.context()','before':['B.b()','A.a()'],'after':['A.a()','B.b()']}])
 def test_empty_and_duplicate_callers_retained(self):
  self.install();caller=types.SimpleNamespace(canonical_name='A.a()')
  self.assertEqual(self.detector()._build_info(self.function,[])[1],[])
  self.assertEqual(self.detector()._build_info(self.function,[caller,caller])[1],[caller,caller])
 def test_changed_detector_refused(self):
  with self.assertRaises(AssertionError):subject.install(self.detector,self.source,self.observed)
 def test_changed_version_refused(self):
  with patch.object(subject,'version',return_value='changed'),self.assertRaises(AssertionError):subject.run()
 def cli(self,exit_code,existing=False):
  target=self.root/('receipt-'+str(exit_code)+'.json')
  if existing:target.write_text('prior observation')
  detector_module=types.ModuleType('slither.detectors.statements.msg_value_in_nonpayable');detector_module.MsgValueInNonPayable=self.detector
  entry=types.ModuleType('slither.__main__')
  def main():
   self.detector()._build_info(self.function,[types.SimpleNamespace(canonical_name='A.a()')]);raise SystemExit(exit_code)
  entry.main=main
  with patch.dict(sys.modules,{'slither.detectors.statements.msg_value_in_nonpayable':detector_module,'slither.__main__':entry}),patch.dict(os.environ,{'REGISTRY_SLITHER_ORDER_RECEIPT':str(target)}),patch.object(subject,'version',return_value='0.11.6'),patch.object(subject.inspect,'getsourcefile',return_value=str(self.source)),patch.object(subject,'DETECTOR_SHA256',self.expected):
   if existing:
    with self.assertRaises(AssertionError):subject.run()
    self.assertEqual(target.read_text(),'prior observation')
   else:
    with self.assertRaises(SystemExit)as error:subject.run()
    self.assertEqual(error.exception.code,exit_code)
    receipt=json.loads(target.read_text());self.assertEqual(receipt['detector_source_sha256'],self.expected);self.assertEqual(receipt['observations'][0]['after'],['A.a()'])
 def test_cli_statuses_and_receipts(self):
  self.cli(0);self.cli(255)
 def test_existing_receipt_preserved(self):self.cli(1,existing=True)
 def test_actual_entry(self):
  entry=Path(subject.__file__)
  with patch.dict(os.environ,{'REGISTRY_SLITHER_ORDER_RECEIPT':str(self.root/'entry.json')}),patch('importlib.metadata.version',return_value='changed'),self.assertRaises(AssertionError):runpy.run_path(str(entry),run_name='__main__')

assert unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(OrderTests)).wasSuccessful()
