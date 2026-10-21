"""Additional exact-size recipes: distinguish actual headroom from a flat subtraction.
Data construction only. No Registry, signature generation, network or transaction.
"""
from pathlib import Path
import json,copy
root=Path(__file__).resolve().parent
cases=json.loads((root/'goldens.json').read_text())['cases'];base=next(c for c in cases if c['name']=='actual-record-65512');rows=[]
states=['created','active','deactivated']
for name,state,version,extra,ok in [
 ('created-1-exact',0,'1',0,True),('created-1-over',0,'1',1,False),
 ('active-max-exact',1,'18446744073709551615',0,True),('active-max-over',1,'18446744073709551615',1,False),
 ('created-max-exact',0,'18446744073709551615',0,True),('created-max-over',0,'18446744073709551615',1,False)]:
 typed=copy.deepcopy(base['arguments'][0]);expected=json.loads(bytes.fromhex(base['expected_hex']));typed['state']=state;typed['version']=version;expected['state']=states[state];expected['version']=version
 if extra:
  index=next(i for i,s in enumerate(typed['services']) if len(s['uri'])<2048);typed['services'][index]['uri']+='a';expected['services'][index]['uri']+='a'
 canonical=lambda x:json.dumps(x,sort_keys=True,separators=(',',':')).encode('ascii')
 temporary={**expected,'state':'deactivated','version':'18446744073709551615'}
 assert len(canonical(temporary))==(65536 if ok else 65537)
 rows.append(dict(name=name,method='record',arguments=[typed,True],actual_json_bytes=len(canonical(expected)),temporary_json_bytes=len(canonical(temporary)),expected_hex=canonical(expected).hex() if ok else '8b54271a',exception=None if ok else 'revert'))
(root/'headroom-goldens.json').write_text(json.dumps({'scope':'Supplemental exact-size pure internal construction controls; production-settings outputs only, not new source coverage or Registry admission','cases':rows},indent=2)+'\n')
print([(r['name'],r['actual_json_bytes'],r['temporary_json_bytes']) for r in rows])
