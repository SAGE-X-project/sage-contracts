"""Keep pinned Slither detection unchanged while ordering caller presentation."""
from pathlib import Path
import hashlib,inspect,json,os
from importlib.metadata import version

DETECTOR_SHA256='2c9fde6f7ed5553d57064c4e3675400e45b2e2b42c6b924d7a0fd3e5285ac1c2'

def install(detector,source,observations):
 assert hashlib.sha256(source.read_bytes()).hexdigest()==DETECTOR_SHA256,'Analyzer detector changed; review again'
 original=detector._build_info
 def stable(self,function,callers):
  ordered=sorted(callers,key=lambda caller:caller.canonical_name)
  observations.append({'function':function.canonical_name,'before':[caller.canonical_name for caller in callers],'after':[caller.canonical_name for caller in ordered]})
  return original(self,function,ordered)
 detector._build_info=stable

def run():
 assert version('slither-analyzer')=='0.11.6','Analyzer version changed; review again'
 from slither.detectors.statements.msg_value_in_nonpayable import MsgValueInNonPayable
 from slither.__main__ import main
 source=Path(inspect.getsourcefile(MsgValueInNonPayable))
 target=Path(os.environ['REGISTRY_SLITHER_ORDER_RECEIPT'])
 assert not target.exists(),'Preserve prior analyzer observation'
 observations=[]
 install(MsgValueInNonPayable,source,observations)
 try:main()
 finally:
  with target.open('x')as stream:
   json.dump({'scope':'Caller presentation order only; no detector, finding, severity or exit filtering','detector_source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'version':'0.11.6','observations':observations},stream,indent=2);stream.write('\n')

if __name__=='__main__':run()
