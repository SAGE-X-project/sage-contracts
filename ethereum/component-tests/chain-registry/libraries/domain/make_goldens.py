"""Fixed REG04 construction and domain-hash recipes; no signature/key generator."""
from pathlib import Path
import hashlib,json,copy
root=Path(__file__).resolve().parent
cases=[]
def add(name,method,args,expected,error=False):cases.append(dict(name=name,method=method,arguments=args,expected_hex=expected.hex(),exception='revert' if error else None))
def raw(b):return {'$hex':b.hex()}
small=['eip155:1:0x'+'0'*39+'1','agent.unit','sign_0','ed25519',bytes(range(32))]
maximum=['eip155:'+'9'*32+':0x'+'f'*40,'a'*64,'k'*32,'sage-secp256k1-keccak256',bytes(range(65))]
for name,args in [('ordinary',small),('maximum',maximum),('empty-internal-fields',['','','','',b''])]:
 fields=[v.encode('ascii') if isinstance(v,str) else v for v in args]
 expected=b'sage-pop-0.11.0'+b''.join(len(v).to_bytes(2,'big')+v for v in fields)
 if name=='maximum':assert len(expected)==292
 values=[*args[:4],raw(args[4])];add('pop-'+name,'pop',values,expected)
for index,limit in enumerate([82,64,32,24,65]):
 args=copy.deepcopy(small)
 args[index]=('x'*(limit+1)) if index<4 else bytes(limit+1)
 add('pop-field-'+str(index)+'-too-long','pop',args[:4]+[raw(args[4])],bytes.fromhex('8b54271a'),True)
# Pure bytes-to-digest test, not schema/admission acceptance.
for n,data in [('empty',b''),('object',b'{}'),('ascii-control-escapes',b'{"type":"\\u0000\\n\\\"\\\\"}'),('block-boundary',b'a'*64),('long-normal-bytes',b'a'*69632)]:
 expected=hashlib.sha256(b'sage-claim-0.11.0\0'+data).digest()
 add('claim-domain-'+n,'claimDigest',[raw(data)],expected)
(root/'goldens.json').write_text(json.dumps({'scope':'Exact domain/length and bytes-to-digest unit controls only; not claim JSON/admission/proof conformance','cases':cases},indent=2)+'\n')
print('Domain fixed cases',len(cases))
