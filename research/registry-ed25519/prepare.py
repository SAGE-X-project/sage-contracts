"""Fetch fixed public evaluation inputs without running upstream build scripts."""
from pathlib import Path
import hashlib,json,subprocess
ROOT=Path(__file__).resolve().parent
FILES={
 'upstream/external/sha512/Sha2Ext.sol':('https://raw.githubusercontent.com/get-smooth/crypto-lib/d714e9824e2e2e44be3c8fd498e0de651ddc9425/external/sha512/Sha2Ext.sol','6805690675019ff8e343da59d4cabfc6cc364b733a80cae7829caffdd0ceb19a'),
 'upstream/external/sha512/LibBytes.sol':('https://raw.githubusercontent.com/get-smooth/crypto-lib/d714e9824e2e2e44be3c8fd498e0de651ddc9425/external/sha512/LibBytes.sol','aa73aca6b1f1a7617ff908116cccd1233c3664bb0f25f90b7aef59d53cff16f7'),
 'upstream/SCL-LICENSE':('https://raw.githubusercontent.com/get-smooth/crypto-lib/d714e9824e2e2e44be3c8fd498e0de651ddc9425/LICENSE','3d1d72d138fe69058becf7fcbe0ae559bf58d35f2948f1e0e98f01aeb350aadb'),
 'upstream/ZeroEx-LICENSE':('https://raw.githubusercontent.com/0xProject/exchange-v3/aae46bef841bfd1cc31028f41793db4fe7197084/LICENSE','37c1de367c1711ccec6aaacf231e55d5cd67dd4d890781e7828428a628bc2c86'),
 'evidence/soljson.cjs':('https://binaries.soliditylang.org/wasm/soljson-v0.8.20+commit.a1b79de6.js','5c509f760dc110a695c8b39bbc21e08c17dee431aa14d606f59e623d7c3cc657'),
}
def main():
 for name,(url,digest) in FILES.items():
  p=ROOT/name;p.parent.mkdir(parents=True,exist_ok=True)
  if not p.is_file()or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:
   data=subprocess.check_output(['curl','--fail','--silent','--show-error','--max-time','60','--max-filesize','16777216',url]);assert hashlib.sha256(data).hexdigest()==digest,name;p.write_bytes(data)
  assert hashlib.sha256(p.read_bytes()).hexdigest()==digest
 (ROOT/'evidence/source-receipt.json').write_text(json.dumps({'scope':'evaluation inputs only; notices retained; no legal clearance or library adoption','files':{n:{'url':u,'sha256':h}for n,(u,h)in FILES.items()}},indent=2)+'\n')
 print('Verified fixed compiler, SHA-512 sources and original license texts.')

if __name__=='__main__':main()
