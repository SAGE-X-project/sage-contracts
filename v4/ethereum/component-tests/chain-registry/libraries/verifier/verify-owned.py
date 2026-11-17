"""Independent plain-byte check for ordinary PoP frame fixtures only; no VM or signing."""
from pathlib import Path
import json,hashlib
r=Path(__file__).resolve().parent;v=json.loads((r/'owned-cases.json').read_text());assert len(v['cases'])==4
for row in v['cases']:
 message=bytes.fromhex(row['message']);assert len(bytes.fromhex(row['key']))==32 and len(bytes.fromhex(row['signature']))==64
 if 'pop_fields'in row:
  fields=list(map(bytes.fromhex,row['pop_fields']));assert len(fields)==5
  assert message==b'sage-pop-0.11.0'+b''.join(len(x).to_bytes(2,'big')+x for x in fields)
  assert fields[0]==b'eip155:'+b'9'*32+b':0x'+b'0'*39+b'1' and fields[1]==b'a'*64 and fields[2]==b's'*32
  assert fields[3]in[b'ed25519',b'x25519']
  assert fields[4]==(bytes.fromhex(row['key'])if fields[3]==b'ed25519'else bytes([9])*32)
  assert len(message)==(242 if fields[3]==b'ed25519'else 241)and row['expected']is True
 else:
  length=int(row['name'].split('-')[-1]);assert message==bytes((i*17)%256 for i in range(length));assert row['expected']==(length==292)
print('Exact four owned ordinary inputs independently checked; no verifier/Registry verdict')
