"""Fixed pure structural scenarios. No point/signature/invalid-call generator.
Keys and proofs below are inert widths for partial entry guards, never valid
admission fixtures, cryptographic proofs, or remotely submitted payloads.
"""
from pathlib import Path
import json,copy,hashlib
r=Path(__file__).resolve().parent.parent;root=Path(__file__).resolve().parent
error_file=r.parent/'fixtures/error-selector-reference.json'
errors=json.loads(error_file.read_text())['error_selectors']
did='did:sage:eip155:1:0x0000000000000000000000000000000000003000:agent.unit'
base=json.loads((r/'json/goldens.json').read_text())['cases'][0]['arguments'][0]
cases=[]
def key(name='s',alg='ed25519',number=1,**changes):
 value=copy.deepcopy(base['keys'][0]['input']);value.update(name=name,alg=alg,key={'$hex':number.to_bytes(32,'big').hex()},signer=did+'#'+name);value.update(changes);return value
wrap=lambda k,state=0:dict(input=k,state=state)
def record(keys=None,services=None):return dict(did=did,controller=base['controller'],keys=[wrap(key())]if keys is None else keys,services=[]if services is None else services,state=0,version='1')
def service(name='api',**changes):
 value=dict(name=name,serviceType='agent',uri='https://example.invalid/service');value.update(changes);return value

def add(name,method,args,error=None,boolean=None):
 expected=errors[error][2:]if error else ('01'if boolean is None else format(int(boolean),'064x'))
 cases.append(dict(name=name,method=method,arguments=args,expected_hex=expected,exception='revert'if error else None))
# Scalar-only success deliberately says nothing about selected algorithm/proof validity.
for name,changes,error in [
 ('ordinary',{},None),('empty-algorithm-scalar-only',{'alg':''},None),
 ('nonascii-algorithm',{'alg':'é'},'InvalidEntry'),('algorithm-over24',{'alg':'a'*25},'BoundsExceeded'),
 ('raw-over65',{'key':{'$hex':'00'*66}},'BoundsExceeded'),
 ('signer-nonascii',{'signer':'é'},'InvalidEntry'),('signer-over189',{'signer':'a'*190},'BoundsExceeded'),
 ('proof-over65',{'proof':{'$hex':'00'*66}},'BoundsExceeded'),
 ('unsafe-expiry',{'hasExpiry':True,'expires':str(2**53)},'InvalidEntry'),
 ('absent-nonzero-expiry',{'hasExpiry':False,'expires':'1'},'InvalidEntry'),
 ('present-zero-expiry',{'hasExpiry':True,'expires':'0'},None),
 ('maximum-safe-expiry',{'hasExpiry':True,'expires':str(2**53-1)},None),
 ('key-dot',{'name':'key.name'},'InvalidEntry'),('empty-name',{'name':''},'InvalidEntry')]:add('scalar-'+name,'keyScalars',[key(**changes)],error)
for name,list_,error in [
 ('empty',[],None),('normal',[service()],None),('escaped-type',[service(serviceType='agent\n\x00')],None),
 ('uri-path-at',[service(uri='https://example.invalid/a@b?q=@c')],None),
 ('uri-userinfo',[service(uri='https://user@example.invalid')],'InvalidEntry'),
 ('uri-fragment',[service(uri='https://example.invalid/#x')],'InvalidEntry'),
 ('count17',[service('s'+str(i))for i in range(17)],'BoundsExceeded'),
 ('name-before-type',[service(name='a.b',serviceType='é')],'InvalidEntry'),
 ('empty-type',[service(serviceType='')],'InvalidEntry')]:add('service-scalars-'+name,'serviceScalars',[list_],error)
add('created-one-structural','createTargets',[record(),10])
add('empty-lifetime-list','createTargets',[record(keys=[]),10],'InvalidEntry')
add('initial-equal-names','createTargets',[record(keys=[wrap(key('a')),wrap(key('a',number=2))]),10],'KeyNameReused')
add('initial-inverted-names','createTargets',[record(keys=[wrap(key('b')),wrap(key('a',number=2))]),10],'InvalidEntry')
for names in [['b','a','a'],['a','b','a']]:
 add('all-equality-before-inversion-'+''.join(names),'createTargets',[record(keys=[wrap(key(n,number=i+1))for i,n in enumerate(names)]),10],'KeyNameReused')
add('initial-material-before-role','createTargets',[record(keys=[wrap(key('a')),wrap(key('b',alg='unknown'))]),10],'KeyMaterialReused')
add('initial-services-before-role','createTargets',[record(keys=[wrap(key('a',alg='unknown'))],services=[service('a')]),10],'InvalidEntry')
add('initial-revoked-wrapper','createTargets',[record(keys=[wrap(key(),1)]),10],'InvalidEntry')
add('initial-signing-url','createTargets',[record(keys=[wrap(key(signer=did+'#other'))]),10],'InvalidEntry')
add('initial-key-width','createTargets',[record(keys=[wrap(key(key={'$hex':'00'*31}))]),10],'InvalidEntry')
add('initial-proof-width','createTargets',[record(keys=[wrap(key(proof={'$hex':'00'*63}))]),10],'InvalidEntry')
for alg in ['Ed25519','ecdsa-p256-sha256','sage-secp256k1-keccak256','unknown','']:
 add('unsupported-'+(alg or 'empty'),'createTargets',[record(keys=[wrap(key(alg=alg,key={'$hex':''}))]),10],'UnsupportedKeyAlgorithm')
# KEM material is not normalized or subjected to an extra Registry blacklist.
for material in ['00'*32,'ff'*32]:
 kem=key('a_kem',alg='x25519',number=2,signer=did+'#z_sign',key={'$hex':material})
 add('kem-before-signing-'+material[:2],'createTargets',[record(keys=[wrap(kem),wrap(key('z_sign'))]),10])
for name,signer,state,error in [
 ('expired',key('z_sign',hasExpiry=True,expires='10'),0,'InvalidEntry'),
 ('unexpired',key('z_sign',hasExpiry=True,expires='11'),0,None),
 ('revoked',key('z_sign'),1,'InvalidEntry'),
 ('kem-role',key('z_sign',alg='x25519'),0,'InvalidEntry')]:
 current=record(keys=[wrap(signer,state)]);new=key('a_kem',alg='x25519',number=2,signer=did+'#z_sign')
 add('kem-signer-'+name,'addTargets',[current,new,10],error)
for name,signer in [('missing',did+'#missing'),('other-record','did:sage:other#z_sign')]:
 add('kem-'+name,'addTargets',[record(keys=[wrap(key('z_sign'))]),key('a_kem',alg='x25519',number=2,signer=signer),10],'InvalidEntry')
add('added-signing-structural','addTargets',[record(),key('t',number=2),10])
add('used-revoked-name','addTargets',[record(keys=[wrap(key(),1)]),key(number=2),10],'KeyNameReused')
add('used-revoked-material','addTargets',[record(keys=[wrap(key(),1)]),key('t'),10],'KeyMaterialReused')
add('new-service-collision','addTargets',[record(services=[service('t')]),key('t',number=2),10],'InvalidEntry')
full=[wrap(key('s'+str(i).zfill(3),number=i+1))for i in range(128)]
add('lifetime128-before-name','addTargets',[record(keys=full),key('s000'),10],'BoundsExceeded')
add('initial-lifetime129','createTargets',[record(keys=full+[wrap(key('t',number=129))]),10],'BoundsExceeded')
add('lifetime127-new-signing','addTargets',[record(keys=full[:-1]),key('t',number=129),10])
for name,services,keys_,error in [
 ('empty',[],[],None),('sorted',[service('a'),service('z')],[wrap(key('s'))],None),
 ('duplicate',[service('a'),service('a')],[],'InvalidEntry'),
 ('inverted',[service('z'),service('a')],[],'InvalidEntry'),
 ('revoked-key-collision',[service('s')],[wrap(key(),1)],'InvalidEntry')]:add('service-target-'+name,'serviceTargets',[services,keys_],error)
for name,entry,now,expected in [
 ('normal',wrap(key()),10,True),('revoked',wrap(key(),1),10,False),
 ('kem',wrap(key(alg='x25519')),10,False),('optional',wrap(key(alg='ecdsa-p256-sha256')),10,False),
 ('exact-expiry',wrap(key(hasExpiry=True,expires='10')),10,False),
 ('future-expiry',wrap(key(hasExpiry=True,expires='11')),10,True),
 ('present-zero',wrap(key(hasExpiry=True,expires='0')),0,False)]:add('eligibility-'+name,'eligible',[entry,now],boolean=expected)
add('no-keys-usable','usable',[[],10],boolean=False)
add('later-usable-signer','usable',[[wrap(key('a',alg='x25519')),wrap(key('z',number=2))],10],boolean=True)
add('all-signers-expired','usable',[[wrap(key('a',hasExpiry=True,expires='10')),wrap(key('z',number=2,hasExpiry=True,expires='9'))],10],boolean=False)
assert len(cases)==len({c['name']for c in cases})
(root/'goldens.json').write_text(json.dumps({'scope':'Partial pure structural guard controls; widths/dummy proofs are NOT cryptographic/admission fixtures','error_reference_sha256':hashlib.sha256(error_file.read_bytes()).hexdigest(),'cases':cases},indent=2)+'\n')
print('fixed structural scenarios:',len(cases))
