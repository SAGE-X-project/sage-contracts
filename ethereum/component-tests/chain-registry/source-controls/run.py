"""Run one finite supplemental normal-test bundle and retain failures and raw evidence."""
import os, sys
if sys.flags.optimize != 0 or os.environ.get('PYTHONOPTIMIZE', '') not in ('', '0'):
    raise RuntimeError('Optimized Python is not permitted')
from pathlib import Path
import hashlib
import importlib
import json
import trace
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
OUT = HERE / 'evidence'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
record = {'scope': 'Supplemental normal source tests only; no live Source or operating qualification',
          'complete': False, 'stages': [], 'production_coverage_qualified': False, 'operating_ready': False}

def verify_sources():
    manifest = json.loads((HERE / 'source-identities.json').read_text())
    for name, digest in manifest['files_sha256'].items():
        rel = Path(name)
        assert not rel.is_absolute() and '..' not in rel.parts
        path = REPO / rel
        assert path.is_file() and not path.is_symlink() and sha(path) == digest, name
    actual = {str(path.relative_to(REPO)) for path in HERE.rglob('*') if path.is_file() and OUT not in path.parents and path.name != 'source-identities.json'}
    expected = {name for name in manifest['files_sha256'] if name.startswith(str(HERE.relative_to(REPO)) + '/')}
    assert actual == expected, 'Unexpected supplemental source file'
    return manifest

def check_files():
    if not OUT.exists(): return
    paths = list(OUT.iterdir())
    assert all(path.is_file() and not path.is_symlink() for path in paths)
    assert all(path.stat().st_size <= (4 if path.suffix == '.log' else 32) * 1024 ** 2 for path in paths)
    assert sum(path.stat().st_size for path in paths) <= 256 * 1024 ** 2

def stage(name, command, seconds):
    from owned_child import run_owned_child
    def on_spawn(value):
        record['active_stage'] = {'name': name, **value}
        (OUT / 'active-child.json').write_text(json.dumps(record['active_stage'], indent=2) + '\n')
    observed = run_owned_child(command, HERE, OUT / (name + '.log'), seconds, check_files, on_spawn)
    record['stages'].append({'name': name, **observed})
    record.pop('active_stage', None)
    assert observed['complete'] and observed['cleanup_confirmed'], 'Preserve first failed prefix; no automatic retry'

NORMAL_GROUPS = {
    'components': ('stateless-paris', 'stateless-shanghai', 'rules-paris', 'rules-shanghai', 'processor-shanghai'),
    'composition': ('core-shanghai', 'semantic-shanghai'),
}

def node_units(name, path, include, seconds=180, pattern=None, coverage_gate=True):
    selection = [] if pattern is None else ['--test-name-pattern=' + pattern]
    coverage = ['--test-coverage-lines=90'] if coverage_gate else []
    stage(name, ['node', '--max-old-space-size=512', '--test', '--test-isolation=none', '--test-concurrency=1', '--experimental-test-coverage',
        *coverage, '--test-coverage-include=' + include, '--test-reporter=spec', '--test-reporter-destination=stdout',
        '--test-reporter=lcov', '--test-reporter-destination=evidence/' + name + '-coverage.lcov', *selection, path], seconds)

def normal_units():
    for name, parts in NORMAL_GROUPS.items():
        pattern = '^normal source controls: (' + '|'.join(parts) + ')$'
        node_units('normal-controls-' + name, 'normal-unit.mjs', '**/source-controls/normal-unit.mjs', 300, pattern, coverage_gate=False)
    from normal_coverage import verify
    verify(HERE / 'normal-unit.mjs', OUT)

def main():
    assert os.environ.get('NODE_OPTIONS', '') == os.environ.get('DEBUG', '') == ''
    manifest = verify_sources()
    assert not OUT.exists(), 'Use a fresh checkout for a new attempt'
    prepare = importlib.import_module('prepare')
    builds = prepare.inputs()
    import contextlib
    with (OUT / 'python-units.log').open('x') as log, contextlib.redirect_stderr(log):
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.discover(str(HERE), pattern='test_*.py'))
    record['python_test_methods'] = result.testsRun
    assert result.wasSuccessful()
    node_units('observer-units', 'fixed-pc-observer-unit.mjs', '**/fixed-pc-observer*.mjs')
    try:
        for build in builds:
            os.environ['SAGE_CONTROL_BUILD'] = build['id']
            node_units('compile-' + build['id'], 'compile.mjs', '**/source-controls/compile.mjs', build['timeout'])
    finally:
        os.environ.pop('SAGE_CONTROL_BUILD', None)
    prepare.subjects()
    normal_units()
    observations = importlib.import_module('collect').collect()
    record['fresh_observed_count'] = observations['observed_count']
    record['fresh_whole_source_threshold_met'] = observations['whole_source_threshold_met']
    assert verify_sources() == manifest
    record['execution_complete'] = True

def python_coverage(path, counts):
    raw_executable = set(trace._find_executable_linenos(str(path)))
    source_lines = len(path.read_text().splitlines())
    executable = {line for line in raw_executable if 1 <= line <= source_lines}
    raw = sorted([line, count] for (filename, line), count in counts.items() if filename == str(path))
    hit = {line for line, count in raw if count > 0} & executable
    return {'file': path.name, 'sha256': sha(path), 'raw_line_counts': raw,
            'raw_executable_lines': sorted(raw_executable),
            'excluded_non_source_lines': sorted(raw_executable - executable),
            'executable_lines': sorted(executable), 'hit_lines': sorted(hit),
            'missing_lines': sorted(executable - hit),
            'percent': 100 * len(hit) / len(executable) if executable else 0}

if __name__ == '__main__':
    counter = trace.Trace(count=True, trace=False)
    failure = None
    try:
        counter.runfunc(main)
    except BaseException as error:
        failure = error
        record['failure_type'] = type(error).__name__
    finally:
        OUT.mkdir(exist_ok=True)
        coverage = []
        for path in sorted(HERE.glob('*.py')):
            if path.name.startswith('test_') or path.name == 'run.py': continue
            coverage.append(python_coverage(path, counter.results().counts))
        with (OUT / 'python-tool-coverage.json').open('x') as stream: json.dump(coverage, stream, indent=2); stream.write('\n')
        record['python_tool_coverage_met'] = bool(coverage) and all(row['percent'] >= 90 for row in coverage)
        from result_contract import finalize
        record.update(finalize(record, record['python_tool_coverage_met'], failure is not None))
        record['evidence_sha256'] = {p.name: sha(p) for p in sorted(OUT.iterdir()) if p.is_file()}
        with (OUT / 'run-result.json').open('x') as stream: json.dump(record, stream, indent=2); stream.write('\n')
        print(json.dumps({k: v for k, v in record.items() if k != 'evidence_sha256'}))
    if failure is not None: raise failure
    assert record['complete'] and record['python_tool_coverage_met']
