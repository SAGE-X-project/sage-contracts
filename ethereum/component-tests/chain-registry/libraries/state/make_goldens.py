"""Fixed field-local lifecycle/grant unit expectations; not Registry admission.
Independent normal ABI output encoding copied with exact reference identity from
an existing reviewed Python oracle. No VM, network or signature generation.
"""
from pathlib import Path
import json,copy,hashlib,importlib.util
root=Path(__file__).resolve().parent;r=root.parent
reference=r.parent/'expected_cases.py'
spec=importlib.util.spec_from_file_location('fixed_expected_abi',reference);oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
addr=lambda n:'0x'+format(n,'040x')
booltype={'type':'bool'};granttype={'type':'tuple[]','components':[{'name':'operator','type':'address'},{'name':'scope','type':'string'}]}
errors=json.loads((r.parent/'fixtures/error-selector-reference.json').read_text())['error_selectors']
cases=[]
def snap(state=0,version=1,admitted=10,grants=None):return {'value':dict(did='did:sage:unit',controller=addr(0x1000),keys=[],services=[],state=state,version=str(version)),'admitted':str(admitted),'grants':[] if grants is None else grants}
def pair(operator=0x2000,scope='activate'):return dict(operator=addr(operator),scope=scope)
def add(name,method,args,types=None,values=None,error=None):
 data=bytes.fromhex(errors[error][2:]) if error else oracle._sequence(types,values)
 cases.append(dict(name=name,method=method,arguments=args,expected_return_hex=data.hex(),exception='revert' if error else None,expected_types=None if error else types,expected_values=None if error else values))
ops=['create','activate','add-key','revoke-key','update-services','authorize-operator','revoke-operator','deactivate']
# Permission fragments never imply that omitted record fields form a valid record.
for state in range(3):
 for op in range(8):
  add(f'controller-{state}-{op}','authorized',[snap(state),addr(0x1000),op],[booltype],[op!=0])
for op,scope in [(1,'activate'),(2,'add-key'),(3,'revoke-key'),(4,'update-services'),(7,'deactivate')]:
 for state in [0,1]:
  expected=not(op==3 and state==0)
  add(f'operator-{state}-{op}','authorized',[snap(state,grants=[pair(scope=scope)]),addr(0x2000),op],[booltype],[expected])
  add(f'wrong-scope-{state}-{op}','authorized',[snap(state,grants=[pair(scope='other')]),addr(0x2000),op],[booltype],[False])
for op in [0,5,6]:add(f'operator-no-delegation-{op}','authorized',[snap(1,grants=[pair(scope=ops[op])]),addr(0x2000),op],[booltype],[False])
add('wrong-operator','authorized',[snap(grants=[pair(0x2001)]),addr(0x2000),1],[booltype],[False])
for state in range(3):
 for op in range(8):
  allowed=op!=0 and state!=2 and not(op==1 and state!=0) and not(op in [2,4] and state!=1)
  args=[snap(state),op,'1','10']
  if allowed:add(f'advance-{state}-{op}','advance',args,[{'type':'uint64'},{'type':'uint8'},{'type':'uint64'}],[2,1 if op==1 else 2 if op==7 else state,10])
  else:add(f'advance-{state}-{op}','advance',args,error='WrongRecordState')
for name,value,version,now,error in [
 ('zero-stored-version',snap(version=0),0,10,'WrongRecordState'),('wrong-predecessor',snap(),2,10,'PreviousVersionMismatch'),
 ('exhaustion',snap(version=2**64-1),2**64-1,10,'VersionExhausted'),('exhaustion-before-clock',snap(version=2**64-1),2**64-1,2**53,'VersionExhausted'),
 ('wrong-version-before-exhaustion',snap(version=2**64-1),1,10,'PreviousVersionMismatch'),
 ('rollback-clock',snap(),1,9,'TimeInvalid'),('unsafe-clock',snap(),1,2**53,'TimeInvalid')]:
 add(name,'advance',[value,7,str(version),str(now)],error=error)
add('maximum-safe-clock','advance',[snap(),7,'1',str(2**53-1)],[{'type':'uint64'},{'type':'uint8'},{'type':'uint64'}],[2,2,2**53-1])
add('maximum-version-successor','advance',[snap(version=2**64-2),7,str(2**64-2),'11'],[{'type':'uint64'},{'type':'uint8'},{'type':'uint64'}],[2**64-1,2,11])
scopes=['activate','deactivate','add-key','revoke-key','update-services','unknown','']
for state in range(3):
 for scope in scopes:
  allowed=scope in (['activate','deactivate'] if state==0 else ['add-key','deactivate','revoke-key','update-services'] if state==1 else [])
  add(f'scope-{state}-{scope}','allowedScope',[state,scope],[booltype],[allowed])
for state,scope in [(0,'activate'),(0,'deactivate'),(1,'add-key'),(1,'revoke-key'),(1,'update-services'),(1,'deactivate')]:
 grants=[pair(0x2000,'deactivate'),pair(0x3000,'deactivate')]
 # Avoid duplicate pairs while testing insertion at start/end/equal-operator scope.
 for operator in [0,0x1500,0x2000,0x4000]:
  if operator==0x2000 and scope=='deactivate':continue
  expected=sorted(grants+[pair(operator,scope)],key=lambda g:(g['operator'],g['scope']))
  add(f'grant-insert-{state}-{scope}-{operator}','authorizeGrant',[snap(state,grants=grants),addr(operator),scope],[granttype],[expected])
for name,value,operator,scope,error in [
 ('self-target',snap(),0x1000,'activate','InvalidEntry'),('wrong-created-scope',snap(),0x2000,'add-key','InvalidEntry'),
 ('wrong-active-scope',snap(1),0x2000,'activate','InvalidEntry'),('terminal-scope',snap(2),0x2000,'deactivate','InvalidEntry'),
 ('duplicate',snap(grants=[pair()]),0x2000,'activate','GrantAlreadyPresent')]:
 add('grant-'+name,'authorizeGrant',[value,addr(operator),scope],error=error)
full=[pair(i+0x2000,'activate') for i in range(128)]
add('full-grants','authorizeGrant',[snap(grants=full),addr(0x3000),'activate'],error='BoundsExceeded')
add('full-duplicate-priority','authorizeGrant',[snap(grants=full),addr(0x2000),'activate'],error='GrantAlreadyPresent')
for index in range(3):
 grants=[pair(0x2000+i) for i in range(3)];expected=grants[:index]+grants[index+1:]
 add(f'grant-revoke-{index}','revokeGrant',[snap(grants=grants),grants[index]['operator'],'activate'],[granttype],[expected])
add('revoke-self','revokeGrant',[snap(),addr(0x1000),'activate'],error='InvalidEntry')
add('revoke-absent','revokeGrant',[snap(),addr(0x2000),'activate'],error='GrantUnavailable')
for grants in [[],[pair()],[pair(0x2000,'activate'),pair(0x2000,'deactivate'),pair(0x3000,'activate'),pair(0x4000,'deactivate')]]:
 for activation in [False,True]:
  for terminal in [False,True]:
   removed=[g for g in grants if terminal or (activation and g['scope']=='activate')];retained=[g for g in grants if not(terminal or (activation and g['scope']=='activate'))]
   add(f'cleanup-{len(grants)}-{activation}-{terminal}','cleanup',[grants,activation,terminal],[granttype,granttype],[retained,removed])
assert len({c['name'] for c in cases})==len(cases)
(root/'goldens.json').write_text(json.dumps({'scope':'Finite field-local pure permission/lifecycle/grant fragments; not full valid record, msg.sender binding, proof, storage/history/atomicity or protected runtime','python_abi_reference_sha256':hashlib.sha256(reference.read_bytes()).hexdigest(),'cases':cases},indent=2)+'\n')
print('State fixed cases',len(cases))
