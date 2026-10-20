"""Check actual component artifacts; never infer complete Registry conformance."""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import sys
import trace
from expected_cases import expected_cases, check_rows

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parents[2]
EVIDENCE = ROOT / 'evidence'
REVISION = 'a22a275b4d88f1d415b53cdffc5bed41231b77a0'
FRAME = 'ethereum/contracts/chain-registry/RegistryFraming.sol'
INTERFACE = 'ethereum/contracts/chain-registry/IChainRegistry.sol'
HARNESS = 'ethereum/test/chain-registry/FramingHarness.sol'
COMPILER = '5c509f760dc110a695c8b39bbc21e08c17dee431aa14d606f59e623d7c3cc657'
SOURCES = [INTERFACE, FRAME, 'ethereum/contracts/chain-registry/README.md',
           '.github/workflows/registry-chain-framing.yml'] + [
    'ethereum/test/chain-registry/' + name for name in [
        '.gitignore', 'FramingHarness.sol', 'compile.mjs', 'normal-abi.mjs',
        'unit.mjs', 'prepare.py', 'python_units.py', 'test_prepare.py', 'verify.py',
        'package.json', 'package-lock.json', 'fixtures/binding.json',
        'fixtures/functions.json', 'fixtures/outcomes.json', 'fixtures/source.json',
        'fixtures/fixed-refusals.json', 'expected_cases.py', 'test_expected_cases.py',
        'fixtures/abi-selector-reference.json', 'fixtures/error-selector-reference.json',
        'fixtures/selector-source.json']]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path):
    def members(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate JSON member')
            result[key] = value
        return result
    data = Path(path).read_bytes()
    assert len(data) <= 8388608
    return json.loads(data, object_pairs_hook=members,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def normalized(value):
    if isinstance(value, list):
        return [normalized(item) for item in value]
    if isinstance(value, dict):
        return {key: normalized(item) for key, item in value.items() if key != 'internalType'}
    return value


def abi_set(entries):
    return sorted((normalized(item) for item in entries), key=lambda item: item['type'] + item['name'])


def source_coverage(output, visited):
    deployed = output['contracts'][HARNESS]['FramingHarness']['evm']['deployedBytecode']
    assert re.fullmatch(r'(?:[0-9a-f]{2})+', deployed['object'])
    code = bytes.fromhex(deployed['object'])
    previous = ['0', '0', '-1', '', '']
    hits = []
    pc = 0
    for fragment in deployed['sourceMap'].split(';'):
        fields = fragment.split(':')
        previous = [fields[index] if index < len(fields) and fields[index] else previous[index] for index in range(5)]
        if pc in visited:
            hits.append(tuple(map(int, previous[:3])))
        assert pc < len(code)
        opcode = code[pc]
        pc += 1 + (opcode - 0x5f if 0x60 <= opcode <= 0x7f else 0)
    source = output['sources'][FRAME]
    statements = []
    todo = [source['ast']]
    while todo:
        node = todo.pop()
        if isinstance(node, list):
            todo.extend(node)
        elif isinstance(node, dict):
            if node.get('nodeType') in ['ExpressionStatement', 'VariableDeclarationStatement', 'IfStatement', 'ForStatement', 'Return', 'RevertStatement', 'InlineAssembly']:
                start, length, file_id = map(int, node['src'].split(':'))
                statements.append({'id': node['id'], 'type': node['nodeType'], 'start': start, 'length': length, 'file': file_id})
            todo.extend(value for value in node.values() if isinstance(value, (dict, list)))
    covered = sorted(row['id'] for row in statements if any(
        file_id == source['id'] and size > 0 and start >= row['start'] and start + size <= row['start'] + row['length']
        for start, size, file_id in hits))
    return statements, covered


def main():
    normative = Path(sys.argv[1]).resolve()
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=normative, text=True).strip() == REVISION
    source = load(ROOT / 'fixtures/source.json')
    assert source['repository'] == 'SAGE-X-project/sage-spec' and source['revision'] == REVISION
    paths = {'functions.json': 'proposals/management-security-binding/contract-abi.json',
             'outcomes.json': 'proposals/management-security-binding/outcomes/abi.json',
             'binding.json': 'profiles/sage-0.11.0/registry-management.json'}
    assert set(source['files']) == set(paths)
    for name, path in paths.items():
        assert source['files'][name]['path'] == path
        assert source['files'][name]['sha256'] == sha(ROOT / 'fixtures' / name) == sha(normative / path)
    functions = load(ROOT / 'fixtures/functions.json')
    outcomes = load(ROOT / 'fixtures/outcomes.json')
    binding = load(ROOT / 'fixtures/binding.json')
    assert binding['status'] == 'ADOPTED_CHAIN_MANAGEMENT_BINDING'
    provenance = load(ROOT / 'fixtures/selector-source.json')
    assert provenance['repository'] == source['repository'] and provenance['revision'] == REVISION
    assert (provenance['run_id'], provenance['run_attempt'], provenance['artifact_id']) == (39393138454, 1, 12250601396)
    assert provenance['artifact_zip_sha256'] == '3956d3b46d8d1b8e2f7bf2524a818c6827f6811575e929ff02039750f4b32c1c'
    pinned = {'abi-selector-reference.json': ('candidate-abi-result.json', '14a125e9e6e66222c877fc3905edc671dd8f11a5f33c9bd4de0c9e37fe22bb22'),
              'error-selector-reference.json': ('candidate-outcomes-result.json', 'c61175afcc8f5557915964d48d516aeb23cddcf76b90a4cee16cd881374e21c9')}
    assert set(provenance['files']) == set(pinned)
    for name, (path, digest) in pinned.items():
        assert provenance['files'][name] == {'artifact_path': path, 'sha256': digest}
        assert sha(ROOT / 'fixtures' / name) == digest
    reference = load(ROOT / 'fixtures/abi-selector-reference.json')
    errors = load(ROOT / 'fixtures/error-selector-reference.json')
    assert reference['abi_sha256'] == sha(ROOT / 'fixtures/functions.json')
    assert errors['abi_sha256'] == sha(ROOT / 'fixtures/outcomes.json')
    assert errors['error_selectors']['MalformedCall'] == '0x2d98cd51' and errors['error_selectors']['BoundsExceeded'] == '0x8b54271a'
    expected = expected_cases(functions, reference, load(ROOT / 'fixtures/fixed-refusals.json'))
    assert expected['maximum lengths: framing only']['input_bytes'] == binding['limits']['whole_calldata_bytes'] == 148804
    assert sha(EVIDENCE / 'soljson.cjs') == COMPILER
    expected_sources = {name: (PROJECT / name).read_text() for name in [INTERFACE, FRAME, HARNESS]}
    evidence_names = []
    summary = {}
    for target in ['paris', 'shanghai']:
        builds = {}
        for suffix in ['', '-coverage-control']:
            label = target + suffix
            source_input = load(EVIDENCE / (label + '-input.json'))
            output = load(EVIDENCE / (label + '-output.json'))
            compiler = load(EVIDENCE / (label + '-compiler.json'))
            assert set(source_input) == {'language', 'sources', 'settings'} and source_input['language'] == 'Solidity'
            assert source_input['sources'] == {name: {'content': content} for name, content in expected_sources.items()}
            assert set(source_input['settings']) == {'optimizer', 'viaIR', 'evmVersion', 'metadata', 'outputSelection'}
            assert source_input['settings']['viaIR'] is True and source_input['settings']['evmVersion'] == target
            assert source_input['settings']['metadata'] == {'bytecodeHash': 'ipfs', 'appendCBOR': True}
            assert source_input['settings']['outputSelection'] == {'*': {'*': ['abi', 'evm.bytecode', 'evm.deployedBytecode', 'evm.methodIdentifiers'], '': ['ast']}}
            optimizer = source_input['settings']['optimizer']
            if suffix:
                assert optimizer == {'enabled': True, 'runs': 200, 'details': {'peephole': False, 'inliner': False, 'jumpdestRemover': False, 'orderLiterals': False, 'deduplicate': False, 'cse': False, 'constantOptimizer': False, 'yul': True, 'yulDetails': {'stackAllocation': True, 'optimizerSteps': 'u:'}}}
            else:
                assert optimizer == {'enabled': True, 'runs': 200}
            assert not [entry for entry in output.get('errors', []) if entry['severity'] == 'error']
            assert compiler['compiler'] == '0.8.20+commit.a1b79de6.Emscripten.clang' and compiler['compiler_sha256'] == COMPILER
            assert compiler['source_sha256'] == {name: hashlib.sha256(content.encode()).hexdigest() for name, content in expected_sources.items()}
            assert compiler['optimizer_settings'] == optimizer and compiler['coverage_control'] is bool(suffix)
            assert compiler['input_sha256'] == hashlib.sha256(json.dumps(source_input, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
            assert compiler['output_sha256'] == hashlib.sha256(json.dumps(output, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
            assert abi_set(output['contracts'][INTERFACE]['IChainRegistry']['abi']) == abi_set(functions + outcomes)
            runtime = output['contracts'][HARNESS]['FramingHarness']['evm']['deployedBytecode']['object']
            assert re.fullmatch(r'(?:[0-9a-f]{2})+', runtime)
            if not suffix:
                assert len(bytes.fromhex(runtime)) <= 24576
            builds[suffix] = output
            evidence_names.extend(label + ending for ending in ['-input.json', '-output.json', '-compiler.json'])
        rows = load(EVIDENCE / (target + '-calls.json'))
        check_rows(rows, expected)
        coverage = load(EVIDENCE / (target + '-coverage.json'))
        pcs = coverage['visited_pcs']
        assert all(type(pc) is int and pc >= 0 for pc in pcs) and pcs == sorted(set(pcs))
        statements, covered = source_coverage(builds['-coverage-control'], set(pcs))
        assert sorted(statements, key=lambda row: row['id']) == sorted(coverage['statements'], key=lambda row: row['id'])
        assert coverage['covered_statement_ids'] == covered
        assert coverage['total'] == len(statements) and coverage['covered'] == len(covered)
        assert abs(coverage['percent'] - len(covered) * 100 / len(statements)) < 1e-10 and coverage['percent'] >= 90
        result = load(EVIDENCE / (target + '-result.json'))
        assert result['methods'] == 13 and result['errors'] == 22 and result['events'] == 2 and result['calls'] == 40
        assert result['source_map_coverage_percent'] == coverage['percent'] and result['new_runtime_conformance_verdicts'] == 0 and result['deployment'] == 'NOT_RUN'
        evidence_names.extend(target + ending for ending in ['-calls.json', '-coverage.json', '-result.json'])
        summary[target] = {'calls': 40, 'statements': len(statements), 'covered': len(covered), 'percent': coverage['percent']}
    python = load(EVIDENCE / 'python-coverage.json')
    executable = set(trace._find_executable_linenos(str(ROOT / 'prepare.py')))
    assert python['source_sha256'] == sha(ROOT / 'prepare.py') and set(python['executable_lines']) == executable
    covered = python['covered_lines']
    assert all(type(line) is int for line in covered) and covered == sorted(set(covered)) and set(covered) <= executable
    assert python['total'] == len(executable) and python['covered'] == len(covered)
    assert abs(python['percent'] - 100 * len(covered) / len(executable)) < 1e-10 and python['percent'] >= 90
    assert python['tests_run'] == 5 and python['unit_success'] is True
    oracle_log = (EVIDENCE / 'oracle-unit.log').read_text()
    assert 'Ran 4 tests' in oracle_log and oracle_log.rstrip().endswith('OK')
    evidence_names += ['python-coverage.json', 'python-unit.log', 'oracle-unit.log', 'execution.log', 'js-coverage.lcov', 'npm-ci.log', 'npm-tree.json']
    if '--local' in sys.argv[2:]:
        print(json.dumps({'scope': 'Local uncommitted component checks only; no CI receipt', 'summary': summary}))
        return
    assert os.environ['GITHUB_ACTIONS'] == 'true' and os.environ['GITHUB_RUN_ID'].isdigit() and int(os.environ['GITHUB_RUN_ATTEMPT']) > 0
    for name in SOURCES:
        assert hashlib.sha256(subprocess.check_output(['git', 'show', 'HEAD:' + name], cwd=PROJECT)).hexdigest() == sha(PROJECT / name)
    receipt = {'scope': 'Interface and bounded framing component only; no complete Registry, deployment or runtime conformance',
               'checkout': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=PROJECT, text=True).strip(),
               'tree': subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=PROJECT, text=True).strip(),
               'run_id': os.environ['GITHUB_RUN_ID'], 'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'],
               'normative_revision': REVISION, 'compiler_sha256': COMPILER, 'summary': summary,
               'new_runtime_conformance_verdicts': 0,
               'source_sha256': {name: sha(PROJECT / name) for name in SOURCES},
               'output_sha256': {name: sha(EVIDENCE / name) for name in evidence_names}}
    (EVIDENCE / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))

if __name__ == '__main__':
    main()
