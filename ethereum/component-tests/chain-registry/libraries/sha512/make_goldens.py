"""Fixed SHA512/byte-range expectations, using Python hashlib; no key/signature work."""
from pathlib import Path
import hashlib,json
root=Path(__file__).resolve().parent;cases=[]
raw=lambda b:{'$hex':b.hex()}
def add(name,method,args,expected,error=False):cases.append(dict(name=name,method=method,arguments=args,expected_hex=expected.hex(),exception='revert' if error else None))
for n in [0,1,2,55,56,63,64,110,111,112,113,127,128,129,175,176,241,242,254,255,256,291,292,293,355,356]:
 data=bytes(i%256 for i in range(n));add('hash-'+str(n),'digest',[raw(data)],hashlib.sha512(data).digest())
add('hash-abc','digest',[raw(b'abc')],hashlib.sha512(b'abc').digest())
assert next(c for c in cases if c['name']=='hash-0')['expected_hex']=='cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'
add('hash-over-bound','digest',[raw(bytes(357))],bytes.fromhex('8b54271a'),True)
data=bytes(range(128))
for start,end in [(0,0),(0,128),(0,1),(1,9),(120,128),(128,128),(3,127)]:add(f'slice-{start}-{end}','slice',[raw(data),str(start),str(end)],data[start:end])
for start,end in [(1,0),(0,129),(129,129),(2**256-1,2**256-1)]:add(f'slice-refuse-{start}-{end}','slice',[raw(data),str(start),str(end)],b'',True)
for n,offset in [(8,0),(16,0),(16,1),(16,8),(128,120)]:add(f'read-{n}-{offset}','readBytes8',[raw(data[:n]),str(offset)],data[offset:offset+8])
for n,offset in [(0,0),(7,0),(16,9),(16,17),(16,2**256-1)]:add(f'read-refuse-{n}-{offset}','readBytes8',[raw(data[:n]),str(offset)],b'',True)
(root/'goldens.json').write_text(json.dumps({'scope':'Finite hashing and independently written byte-accessor controls only; no signatures, Registry, network or production verifier qualification','cases':cases},indent=2)+'\n')
print('Hash/adapter fixed cases',len(cases))
