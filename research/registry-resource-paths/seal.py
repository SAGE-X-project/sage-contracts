"""Check and bind actual owned-VM research evidence; never a conformance verdict."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / 'evidence'
digest = lambda value: hashlib.sha256(value).hexdigest()
read = lambda name: json.loads((EVIDENCE / name).read_text())


def main():
    results = read('results.json')
    assert results['target'] == os.environ['SAGE_EVM_FORK']
    assert results['experimental_block_and_transaction_cap'] == '5000000000'
    assert results['verifier_call_cap'] == '15000000'
    expected = {'bounded-1', 'bounded-2', 'bounded-4', 'bounded-8', 'full-128',
                'late-first-insertion', 'owned-wallet', 'last-signer', 'max-grants'}
    assert {v['label'] for v in results['scenarios']} == expected
    assert len(results['scenarios']) == len(expected)
    calls = 0
    for scenario in results['scenarios']:
        label = scenario['label']
        assert read('scenario-' + label + '.json') == scenario
        rows = scenario['rows']
        assert rows and all(r['exception'] is None and r['transaction_type'] == 2 for r in rows)
        assert [r['index'] for r in rows] == list(range(len(rows)))
        for row in rows:
            before = int(row['execution_gas']) + int(row['intrinsic_gas'])
            refund = min(int(row['gas_refund_raw']), before // 5)
            assert int(row['refund_applied']) == refund
            assert int(row['total_gas']) == before - refund < 5_000_000_000
            raw = bytes.fromhex((EVIDENCE / (label + '-call-' + str(row['index']) + '.hex')).read_text().strip())
            assert digest(raw) == row['calldata_sha256'] and len(raw) == row['calldata_bytes']
        fixture = read(label + '-fixture.json')
        assert 'sage-pop-0.11.0'.encode().hex() in fixture['keys'][0]['challenge']
        witness = read(label + '-witness.json')
        assert len(witness) == scenario['transitions']
        for version, w in enumerate(witness, 1):
            assert w['version'] == version and w['record']['version'] == str(version)
            assert rows[w['mutation_row']]['category'] == 'normal'
            assert len(w['read_rows']) == 3 and all(rows[i]['category'] == 'read' for i in w['read_rows'])
        assert rows == read(label + '-partial.json')
        if label == 'full-128':
            assert witness[0]['record_bytes'] == 65513
            assert len(witness[0]['record']['keys']) == 128
        if label == 'owned-wallet':
            assert all(r['wallet'] and r['caller'].endswith('2000') for r in rows if r['category'] == 'normal')
        if label == 'max-grants':
            assert max(len(w['grants']) for w in witness) == 128
            assert witness[-1]['record']['state'] == 'deactivated' and not witness[-1]['grants']
        if label == 'last-signer':
            assert witness[-1]['record']['state'] == 'deactivated'
            assert any(k.get('expires') == 0 and k['state'] == 'accepted' for k in witness[-1]['record']['keys'])
        calls += len(rows)
    for kind in ['strict', 'paths']:
        for suffix in ['input', 'output']:
            assert read(kind + '-' + suffix + '.json') == read('unit-' + kind + '-' + suffix + '.json')
        assert read(kind + '-input.json')['settings']['evmVersion'] == results['target']
    assert (EVIDENCE / 'PathProbe.compiled.sol').read_bytes() == (EVIDENCE / 'unit-PathProbe.compiled.sol').read_bytes()
    for name, code in results['code'].items():
        if name.endswith((':PathProbe', ':OrdinaryWallet', ':CodecControls')):
            assert 0 < code['bytes'] <= 24576
    coverage = read('solidity-coverage.json')
    assert set(coverage) == {'Codec.sol', 'PathProbe.sol'}
    assert all(v['executable'] > 0 and v['percent'] >= 90 for v in coverage.values())
    files = {}
    for block in (EVIDENCE / 'js-coverage.lcov').read_text().split('end_of_record'):
        lines = block.strip().splitlines()
        if not lines:
            continue
        name = Path(next(v[3:] for v in lines if v.startswith('SF:'))).name
        total = int(next(v[3:] for v in lines if v.startswith('LF:')))
        hit = int(next(v[3:] for v in lines if v.startswith('LH:')))
        assert name not in files and total > 0 and 100 * hit / total >= 90
        files[name] = {'total': total, 'hit': hit}
    assert set(files) == {'abi.mjs', 'compile.mjs', 'coverage.mjs', 'evaluate.mjs', 'fixture.mjs', 'run.mjs'}
    (EVIDENCE / 'js-coverage-summary.json').write_text(json.dumps(files, indent=2) + '\n')
    research = ROOT.parent
    paths = [p for p in ROOT.rglob('*') if p.is_file() and not {'node_modules', '__pycache__'}.intersection(p.parts) and p.name != 'receipt.json']
    old = research / 'registry-ed25519'
    paths += [old / n for n in ['StrictEd25519.sol', 'prepare.py', 'SOURCE-NOTICES.md',
                               'LICENSES/speccheck-Apache-2.0.txt', 'evidence/soljson.cjs',
                               'evidence/source-receipt.json']]
    paths += [p for p in (old / 'upstream').rglob('*') if p.is_file()]
    paths.append(research / 'registry-bulk-workload/Storage.sol')
    workflow = ROOT.parent.parent / '.github/workflows/registry-resource-paths.yml'
    receipt = {
        'scope': results['scope'], 'calls': calls,
        'checkout': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        'tree': subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip(),
        'run_id': os.environ['GITHUB_RUN_ID'], 'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'],
        'fork': results['target'], 'node': subprocess.check_output(['node', '--version'], text=True).strip(),
        'npm': subprocess.check_output(['npm', '--version'], text=True).strip(),
        'workflow_sha256': digest(workflow.read_bytes()),
        'sha256': {str(p.relative_to(research)): digest(p.read_bytes()) for p in paths},
    }
    (EVIDENCE / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'scope': 'normal-state resource evidence only', 'fork': results['target'], 'calls': calls, 'files': len(paths)}))


if __name__ == '__main__':
    main()
