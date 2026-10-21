"""Run fixed library units sequentially; no RPC, deployment or live transaction."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import time

root = Path(__file__).resolve().parent
repository = root.parents[3]
groups = ['text', 'buffer', 'json', 'domain', 'grammar', 'state', 'sha512', 'verifier', 'entries']
selection = sys.argv[1:] or ['all']
assert len(selection) == 1 and selection[0] in ['all', *groups]
selected = groups if selection == ['all'] else selection
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
manifest_path = root / 'source-identities.json'
manifest = json.loads(manifest_path.read_text())
source_inputs = manifest['files_sha256']
assert manifest['scope'] == 'Fixed standalone Registry library controls; no whole Registry or operating qualification'


def check_sources():
    for name, expected in source_inputs.items():
        path = Path(name)
        assert not path.is_absolute() and '..' not in path.parts
        actual = repository / path
        assert actual.is_file() and not actual.is_symlink()
        assert digest(actual) == expected, name


def write_new(path, value):
    with path.open('x') as stream:
        stream.write(json.dumps(value, indent=2) + '\n')


check_sources()
assert source_inputs[str(Path(__file__).resolve().relative_to(repository))] == digest(Path(__file__))
for name in selected:
    folder = root / name
    assert not (folder / 'evidence').exists(), 'Preserve existing results before another execution'
    if name == 'json':
        assert not (folder / 'headroom/evidence').exists()
results = []
for name in selected:
    check_sources()
    folder = root / name
    evidence = folder / 'evidence'
    evidence.mkdir()
    command = ['node', '--max-old-space-size=512', '--test', '--test-concurrency=1', '--experimental-test-coverage',
               '--test-coverage-lines=90', '--test-coverage-include=**/unit.mjs', '--test-reporter=spec', '--test-reporter-destination=stdout',
               '--test-reporter=lcov', '--test-reporter-destination=evidence/js-coverage.lcov', 'unit.mjs']
    started = time.monotonic()
    # The environment is inherited. Each VM unit checks DEBUG and observer state;
    # this coordinator never disables a failing guard or runs another VM in parallel.
    with (evidence / 'execution.log').open('xb') as output:
        completed = subprocess.run(command, cwd=folder, stdout=output, stderr=subprocess.STDOUT)
    check_sources()
    files = {str(path.relative_to(evidence)): digest(path)
             for path in sorted(evidence.rglob('*')) if path.is_file()}
    receipt = {'group': name, 'command': command, 'exit_code': completed.returncode,
               'seconds': time.monotonic() - started, 'source_manifest_sha256': digest(manifest_path),
               'source_inputs_sha256': source_inputs, 'files_sha256': files,
               'scope': manifest['scope'], 'complete': completed.returncode == 0}
    write_new(evidence / 'local-execution.json', receipt)
    assert completed.returncode == 0, 'Preserve the failed group; later groups were not executed'
    results.append({'group': name, 'receipt_sha256': digest(evidence / 'local-execution.json')})
    if name == 'json':
        headroom = folder / 'headroom/evidence'
        headroom.mkdir(parents=True)
        command = ['node', '--max-old-space-size=512', '--test', '--test-concurrency=1', '--experimental-test-coverage', '--test-coverage-lines=90', '--test-coverage-include=**/headroom-unit.mjs', '--test-reporter=spec', '--test-reporter-destination=stdout', '--test-reporter=lcov', '--test-reporter-destination=headroom/evidence/js-coverage.lcov', 'headroom-unit.mjs']
        with (headroom / 'execution.log').open('xb') as output:
            completed = subprocess.run(command, cwd=folder, stdout=output, stderr=subprocess.STDOUT)
        check_sources()
        write_new(headroom / 'local-execution.json', {
            'group': 'json-headroom', 'command': command, 'exit_code': completed.returncode,
            'source_manifest_sha256': digest(manifest_path), 'source_inputs_sha256': source_inputs,
            'files_sha256': {path.name: digest(path) for path in sorted(headroom.iterdir()) if path.is_file()},
            'scope': 'Six production-build size controls per fork; no additional source coverage',
            'complete': completed.returncode == 0})
        assert completed.returncode == 0, 'Preserve failed supplemental headroom evidence'
        results.append({'group': 'json-headroom', 'receipt_sha256': digest(headroom / 'local-execution.json')})
    print(json.dumps({'completed_group': name, 'scope': manifest['scope']}), flush=True)
print(json.dumps({'complete': True, 'groups': results, 'scope': manifest['scope']}), flush=True)
