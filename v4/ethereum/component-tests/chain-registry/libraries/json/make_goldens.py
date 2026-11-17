"""Independent fixed Python JSON byte recipes, not a protocol admission oracle."""
from pathlib import Path
import base64,json,copy
root=Path(__file__).resolve().parent
addr=lambda n:'0x'+format(n,'040x')
registry='eip155:1:'+addr(0x3000);agent='agent.unit';did='did:sage:'+registry+':'+agent
states=['created','active','deactivated'];ops=['create','activate','add-key','revoke-key','update-services','authorize-operator','revoke-operator','deactivate']
raw=lambda data:{'$hex':data.hex()}
def b64(value):return base64.urlsafe_b64encode(bytes.fromhex(value['$hex'])).rstrip(b'=').decode()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('ascii')
def key(i=0,expiry=None,alg='ed25519',width=32):
 return dict(name=f'key_{i:03d}',alg=alg,key=raw(bytes((i+j)%256 for j in range(width))),signer=did+'#key_000',proof=raw(bytes((i+j)%256 for j in range(64))),hasExpiry=expiry is not None,expires=0 if expiry is None else str(expiry))
def key_json(value,state=0):
 d={k:value[k] for k in ['name','alg']};d.update(key=b64(value['key']),proof={'signer':value['signer'],'value':b64(value['proof'])},state=['accepted','revoked'][state])
 if value['hasExpiry']:d['expires']=int(value['expires'])
 return d
def service(i=0):return dict(name=f'svc_{i:02d}',serviceType='https',uri='HTTPS://example.test/a@b?x=%2f&z=%22')
def service_json(v):return dict(name=v['name'],type=v['serviceType'],uri=v['uri'])
def record(state=0,version=1):return dict(did=did,controller=addr(0x1000),keys=[dict(input=key(),state=0)],services=[],state=state,version=str(version))
def record_json(v,state=None,version=None):return dict(id=v['did'],controller=v['controller'],keys=[key_json(k['input'],k['state']) for k in v['keys']],services=[service_json(t) for t in v['services']],state=states[v['state'] if state is None else state],version=v['version'] if version is None else str(version))
def command(i,version=None):
 return dict(actor=addr(0x1000),operation=i,registry=registry,did=did,expectedVersion=str(0 if i==0 else 1) if version is None else str(version),controller=addr(0x1000),keys=[key()],services=[service()],salt=raw(bytes(range(32))),key=key(1),name='key_000',operator=addr(0x2000),scope='activate' if i==5 else 'deactivate')
def arguments(v):
 op=v['operation']
 if op==0:return dict(controller=v['controller'],keys=[key_json(k) for k in v['keys']],services=[service_json(t) for t in v['services']],salt=b64(v['salt']))
 if op==2:return dict(key=key_json(v['key']))
 if op==3:return dict(name=v['name'])
 if op==4:return dict(services=[service_json(t) for t in v['services']])
 if op in [5,6]:return dict(operator=v['operator'],scope=v['scope'])
 return {}
def command_json(v):return dict(actor=v['actor'],arguments=arguments(v),binding='sage-registry-chain-0.11.0',did=v['did'],expectedVersion='' if int(v['expectedVersion'])==0 else v['expectedVersion'],operation=ops[v['operation']],registry=v['registry'])
def history(i):return dict(actor=addr(0x1000),admitted='9007199254740991' if i%2 else '0',operation=i,previousVersion='0' if i==0 else '1',version='1' if i==0 else '2',commandDigest=raw(bytes(range(32))),recordDigest=raw(bytes(range(31,-1,-1))),grantsDigest=raw(bytes([255])*32),target=dict(operator=addr(0x2000),scope='activate'),automaticRemovals=[] if i%2 else [dict(operator=addr(0x2001),scope='deactivate')])
def history_json(v):return dict(actor=v['actor'],admitted=int(v['admitted']),automaticRemovals=v['automaticRemovals'],commandDigest=b64(v['commandDigest']),grantsDigest=b64(v['grantsDigest']),operation=ops[v['operation']],previousVersion='' if int(v['previousVersion'])==0 else v['previousVersion'],recordDigest=b64(v['recordDigest']),target=v['target'] if v['operation'] in [5,6] else None,version=v['version'])
cases=[]
def add(name,method,args,expected=None,error=None):cases.append(dict(name=name,method=method,arguments=args,expected_hex=canonical(expected).hex() if error is None else error,exception=None if error is None else 'revert'))
for state in range(3):
 for version in [1,2,18446744073709551615]:
  v=record(state,version);add(f'record-{state}-{version}','record',[v,True],record_json(v))
for expiry in [None,0,9007199254740991]:
 v=record(1);v['keys'][0]['input']=key(expiry=expiry);v['keys'][0]['state']=1
 v['services']=[service()];v['services'][0]['serviceType']=''.join(map(chr,range(32)))+'"\\\x7f'
 add('expiry-'+str(expiry),'record',[v,True],record_json(v))
v=record();v['keys']=[dict(input=key(0,alg='sage-secp256k1-keccak256',width=65),state=0),dict(input=key(1,alg='x25519'),state=0)]
add('optional-suite-representation','record',[v,True],record_json(v))
for i in range(8):
 c=command(i);add('command-'+ops[i],'command',[c],command_json(c))
 h=history(i);add('history-'+ops[i],'history',[h],history_json(h))
c=command(1,18446744073709551615);add('command-maximum-predecessor','command',[c],command_json(c))
h=history(7);h.update(previousVersion='18446744073709551614',version='18446744073709551615');add('history-maximum-successor','history',[h],history_json(h))
for n in [0,1,128]:
 g=[dict(operator=addr(i+0x2000),scope='update-services') for i in range(n)]
 add('grants-'+str(n),'grants',[g],g)
for n in [0,16]:
 v=record();v['services']=[service(i) for i in range(n)]
 add('services-'+str(n),'record',[v,True],record_json(v))
for expiry in [None,0,9007199254740991]:
 c=command(0);c['keys'][0]=key(expiry=expiry)
 a=[registry,agent,c['controller'],c['keys'],c['services'],c['salt']]
 expected=dict(registryId=registry,agentId=agent,controller=c['controller'],keys=[key_json(k) for k in c['keys']],services=[service_json(t) for t in c['services']],salt=b64(c['salt']))
 add('claim-expiry-'+str(expiry),'claim',a,expected)
# Fill valid ASCII URI components to exact schema byte lengths. No proofs are verified.
def boundary(length,state=1,version=1):
 v=record(state,version);v['keys']=[dict(input=key(i),state=0) for i in range(128)];v['services']=[dict(name=f'svc_{i:02d}',serviceType='https',uri='https://example.test/') for i in range(16)]
 needed=length-len(canonical(record_json(v)));assert needed>=0
 for t in v['services']:
  n=min(needed,2048-len(t['uri']));t['uri']+='a'*n;needed-=n
 assert needed==0
 assert len(canonical(record_json(v)))==length
 return v
for length in [65512,65513,65536,65537]:
 v=boundary(length)
 add('actual-record-'+str(length),'record',[v,False],record_json(v) if length<=65536 else None,error=None if length<=65536 else '8b54271a')
 terminal=len(canonical(record_json(v,2,18446744073709551615)))
 add('headroom-record-'+str(length),'record',[v,True],record_json(v) if terminal<=65536 else None,error=None if terminal<=65536 else '8b54271a')
v=boundary(65536,2,18446744073709551615);add('terminal-exact-limit','record',[v,True],record_json(v))
# Pure internal construction guards; not public Registry diagnostic qualification.
v=record();v['version']='0';add('zero-record-version','record',[v,False],error='887efaa5')
v=record();v['keys'][0]['input']['expires']='1';add('absent-expiry-nonzero','record',[v,False],error='887efaa5')
v=record();v['keys'][0]['input']['hasExpiry']=True;v['keys'][0]['input']['expires']='9007199254740992';add('unsafe-expiry','record',[v,False],error='a90a3db6')
for op,version in [(0,1),(1,0)]:add('command-predecessor-'+str(op),'command',[command(op,version)],error='887efaa5')
for name,changes in [('unsafe-time',dict(admitted='9007199254740992')),('exhausted',dict(previousVersion='18446744073709551615',version='0')),('non-successor',dict(version='3')),('create-predecessor',dict(operation=0)),('non-create-zero',dict(previousVersion='0',version='1'))]:
 h=history(1);h.update(**changes);add('history-'+name,'history',[h],error='a90a3db6' if name=='unsafe-time' else '887efaa5')
v=record();v['keys']*=129;add('too-many-keys','record',[v,False],error='8b54271a')
v=record();v['services']=[service(i) for i in range(17)];add('too-many-services','record',[v,False],error='8b54271a')
add('too-many-grants','grants',[[dict(operator=addr(i),scope='activate') for i in range(129)]],error='8b54271a')
assert len({c['name'] for c in cases})==len(cases)
(root/'goldens.json').write_text(json.dumps({'scope':'Fixed bounded ASCII schema construction only; no admission, proof verification, Source or protocol runtime','cases':cases},indent=2)+'\n')
print('Fixed cases',len(cases),'boundary headroom',[(c['name'],c['exception']) for c in cases if c['name'].startswith('headroom')])
