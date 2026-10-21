"""Run finite public constructor validation and preserve each failed prefix."""
from pathlib import Path
import hashlib,json,subprocess,sys,time
root=Path(__file__).resolve().parent
repo=root.parents[3]
evidence=root/'evidence'
evidence.mkdir(exist_ok=True)
manifest_path=root/'source-identities.json'
manifest=json.loads(manifest_path.read_text())
for section in ['source_files_sha256','tool_files_sha256']:
 for name,expected in manifest[section].items():
  p=repo/name
  assert not Path(name).is_absolute() and '..' not in Path(name).parts
  assert p.is_file() and not p.is_symlink() and hashlib.sha256(p.read_bytes()).hexdigest()==expected,name
assert manifest['tool_files_sha256'][str(Path(__file__).resolve().relative_to(repo))]==hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
assert not (evidence/'local-result.json').exists(),'Preserve prior result before another attempt'
result={'scope':'Finite isolated constructor validation, not Source or operating qualification','source_manifest_sha256':hashlib.sha256(manifest_path.read_bytes()).hexdigest(),'complete':False,'stages':[],'operating_ready':False}
try:
 for stage,command in [('compile',['node','--max-old-space-size=512','compile.mjs']),('compiler-check',[sys.executable,'-B','verify-compiler.py']),('ordinary',['node','--max-old-space-size=512','--test','--test-concurrency=1','constructor-unit.mjs'])]:
  began=time.monotonic()
  with (evidence/(stage+'.log')).open('xb') as out:
   if stage=='compiler-check':
    with (evidence/'compiler-check.json').open('xb') as observed:
     status=subprocess.run(command,cwd=root,stdout=observed,stderr=out,check=False).returncode
   else:status=subprocess.run(command,cwd=root,stdout=out,stderr=subprocess.STDOUT,check=False).returncode
  result['stages'].append({'stage':stage,'command':command,'exit':status,'elapsed_seconds':time.monotonic()-began})
  if status:raise RuntimeError(stage+' failed; preserve all evidence before changes')
 result['complete']=True
finally:
 result['evidence_sha256']={str(p.relative_to(evidence)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(evidence.rglob('*')) if p.is_file()}
 with (evidence/'local-result.json').open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
 print(json.dumps(result))
