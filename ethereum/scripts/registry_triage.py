"""Validate one reviewed redundant invariant without changing detector severity."""
from pathlib import Path
import hashlib,json
CORE_SHA256='3333eaa40034afe3458da9ab41afcf1afcc363557e0b4314e7c21e9e9ed6a9a2'
FINDING='d3a282bc668c92ed22d4da8cd2e8a693decf382ee3e22133c92756bba9d104f9'
DESCRIPTION_SHA256='336cd15f93479a113f5cd7d6b43ce349142b7db54694f9b48f09a4c5e85dda43'
CONFIG_SHA256='6ae022ee896dc584764901dc0baaeb14c85a83e0f0e8caa0fa2e077d638843ff'
def commit_parents(raw):
 header=raw.split('\n\n',1)[0]
 parents=[line[7:]for line in header.splitlines()if line.startswith('parent ')]
 assert all(len(value)in (40,64)and all(c in '0123456789abcdef'for c in value)for value in parents),'Invalid commit parent header'
 return parents

def check(source,triage,config):
 assert hashlib.sha256(source).hexdigest()==CORE_SHA256,'Core changed; review this invariant again'
 assert type(triage)is list and len(triage)==1,'Only the reviewed finding is allowed'
 finding=triage[0]
 assert finding['id']==FINDING and finding['check']=='msg-value-in-nonpayable'
 assert hashlib.sha256(finding['description'].encode()).hexdigest()==DESCRIPTION_SHA256,'Legacy description matching must stay exact'
 assert finding['sage_review']['source_sha256']==CORE_SHA256
 assert finding['sage_review']['other_high_findings_suppressed'] is False
 assert config['exclude_high'] is False
 assert hashlib.sha256(json.dumps(config,sort_keys=True,separators=(',',':')).encode()).hexdigest()==CONFIG_SHA256,'Detector configuration changed; review again'
 excluded={x.strip()for x in config['detectors_to_exclude'].split(',')}
 assert 'msg-value-in-nonpayable'not in excluded

def reports(raw,triaged=None):
 assert raw['success'] is True and raw.get('error')is None
 before=raw['results']['detectors'];ids=[row['id']for row in before]
 assert len(ids)==len(set(ids))
 high=[row for row in before if row['impact']=='High']
 assert len(high)==1 and high[0]['id']==FINDING and high[0]['check']=='msg-value-in-nonpayable'
 assert hashlib.sha256(high[0]['description'].encode()).hexdigest()==DESCRIPTION_SHA256
 if triaged is None:return {'phase':'raw','reviewed_high_count':1,'total_findings':len(before)}
 assert triaged['success'] is True and triaged.get('error')is None
 after=triaged['results']['detectors'];after_ids=[row['id']for row in after]
 assert len(after_ids)==len(set(after_ids))
 assert set(after_ids)==set(ids)-{FINDING},'Only the exact reviewed finding may be excluded'
 assert not any(row['impact']=='High'for row in after)
 assert {row['id']:row for row in after}=={row['id']:row for row in before if row['id']!=FINDING},'All other finding details must be preserved'
 return {'phase':'compared','raw_findings':len(before),'triaged_findings':len(after),'excluded_ids':[FINDING],'unknown_high_fail_closed':True}

if __name__=='__main__':
 root=Path(__file__).resolve().parents[1]
 check((root/'contracts/chain-registry/ChainRegistry.sol').read_bytes(),json.loads((root/'slither.db.json').read_text()),json.loads((root/'.slither.config.json').read_text()))
 import sys
 if len(sys.argv)==1:
  print('One reviewed invariant bound to unchanged Core; all other High findings still block')
 elif sys.argv[1:] and sys.argv[1]=='raw':
  assert len(sys.argv)==4 and sys.argv[3]=='255','Expected successful analysis to block on its one reviewed High finding'
  print(json.dumps(reports(json.loads(Path(sys.argv[2]).read_text()))))
 else:
  assert len(sys.argv)==4 and sys.argv[1]=='compare'
  print(json.dumps(reports(json.loads(Path(sys.argv[2]).read_text()),json.loads(Path(sys.argv[3]).read_text()))))
