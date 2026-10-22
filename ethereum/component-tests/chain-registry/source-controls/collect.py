"""Map fresh normal runtime observations; keep historical and product scopes separate."""
import os, sys
if sys.flags.optimize != 0 or os.environ.get('PYTHONOPTIMIZE', '') not in ('', '0'):
    raise RuntimeError('Optimized Python is not permitted')

from pathlib import Path
import collections
import hashlib
import json
from core_identity import contained_hits, visited_pcs
import pilot_source_ranges as ranges
from historical import check_historical

HERE = Path(__file__).resolve().parent
OUT = HERE / 'evidence'
read = lambda path: json.loads(path.read_text())
sha = lambda value: hashlib.sha256(value).hexdigest()
KEYS = ['source', 'source_sha256', 'type', 'start', 'length']

def collect():
    original = read(HERE.parent / 'runtime/evidence/compiler/shanghai-input.json')
    catalogue = read(OUT / 'catalogue.json')
    key = lambda row: tuple(row[k] for k in KEYS)
    indices = {key(row): i for i, row in enumerate(catalogue)}
    assert len(indices) == 1642 and len(original['sources']) == 29
    by_name = collections.defaultdict(list)
    for row in catalogue:
        assert sha(original['sources'][row['source']]['content'].encode()) == row['source_sha256']
        by_name[row['source']].append(row)
    subjects = read(OUT / 'subjects.json')
    assert {part['id'] for part in subjects['parts']} == {'stateless-paris', 'stateless-shanghai', 'rules-paris', 'rules-shanghai', 'processor-shanghai', 'core-shanghai', 'semantic-shanghai'}
    assert len(subjects['parts']) == 7
    source_sha = sha((OUT / 'subjects.json').read_bytes())
    transform = read(OUT / 'whole-source-transformation.json')['sources']
    records = []
    for part in subjects['parts']:
        raw = read(OUT / (part['id'] + '-result.json'))
        assert raw['id'] == part['id'] and raw['profile'] == part['profile'] and raw['complete']
        assert raw['subject_sha256'] == source_sha and len(raw['calls']) == part['expected_calls']
        assert len(raw['deployments']) == len(part['deployments']) and len(raw['setup']) == len(part['setup'])
        modules = {m['id']: m for m in part['modules']}
        actual = {m['id']: m for m in raw['modules']}
        assert set(modules) == set(actual)
        for name, module in modules.items():
            assert actual[name]['code_sha256'] == module['images']['runtime']['sha256']
            assert actual[name]['code_bytes'] == module['images']['runtime']['bytes']
            if 'address' in module: assert actual[name]['address'] == module['address']
        expected = part['calls']
        for call, fixture in zip(raw['calls'], expected):
            assert call['fixture'] == fixture
        for name, module in modules.items():
            if part['id'].startswith('core-'):
                selected = name == 'ChainRegistry'
            else:
                selected = module.get('build') == 'control' or name in ['ProcessorPureControls', 'SemanticHelperControls']
            if not selected: continue
            observations = set()
            for call in raw['calls']:
                fixture = call['fixture']
                assert call['raw']['exception'] == fixture['expected_exception'] is None
                assert call['raw']['return_hex'] == fixture['expected_return_hex'] and call['raw']['logs'] == fixture['expected_logs']
                if fixture['module_id'] != name: continue
                pc = call['pc']
                assert pc['complete'] and pc['failure'] is None and pc['root_messages'] == 1 and not pc['open_frames']
                assert all(frame['completed'] and not frame['reverted'] and frame['is_static'] and not frame['delegatecall'] for frame in pc['frames'])
                assert {image['id'] for image in pc['images']} == set(modules)
                for image in pc['images']:
                    identity = actual[image['id']]
                    assert image['address'] == identity['address'] and image['code_sha256'] == identity['code_sha256']
                    assert image['code_bytes'] == identity['code_bytes']
                    pcs = ranges.bitmap_pcs(image['visited_bits_base64'], modules[image['id']]['images']['runtime']['hex'])
                    if image['id'] == name: observations.update(pcs)
            compiled = read(OUT / (module['compiler'] + '-output.json'))
            inp = read(OUT / (module['compiler'] + '-input.json'))
            if part['id'].startswith('core-'):
                assert set(inp['sources']) == set(original['sources'])
                assert all(inp['sources'][n]['content'] == t['content'] and t['source_sha256'] == sha(original['sources'][n]['content'].encode()) for n, t in transform.items())
            else:
                assert all(inp['sources'][n] == v for n, v in original['sources'].items())
                extras = set(inp['sources']) - set(original['sources'])
                assert extras <= {'ethereum/component-tests/chain-registry/ProcessorPureControls.sol', 'ethereum/component-tests/chain-registry/SemanticHelperControls.sol'}
            wrapper = name in ['ProcessorPureControls', 'SemanticHelperControls']
            path = ('ethereum/component-tests/chain-registry/' if wrapper else 'ethereum/contracts/chain-registry/') + module['contract'] + '.sol'
            art = compiled['contracts'][path][module['contract']]['evm']['deployedBytecode']
            local = {value['id']: n for n, value in compiled['sources'].items()}
            witnesses = {}
            if part['id'].startswith('core-'):
                rows = [{'source': n, **row} for n, item in transform.items() for row in item['statements']]
                spans = ranges.instruction_maps(art['object'], art['sourceMap'], 'runtime')
                hits = contained_hits(module['images']['runtime']['hex'], spans, {n: i for i, n in local.items()}, rows, observations)
                for hit in hits:
                    row = next(row for row in rows if row['marker_hex'] == hit['marker_hex'])
                    witnesses[indices[key(row['original'])]] = hit
            else:
                spans, _ = ranges.mapped_spans(module['images']['runtime']['hex'], art['sourceMap'], sorted(observations))
                grouped = collections.defaultdict(list)
                for span in spans:
                    n = local.get(span['file'])
                    if n in original['sources']: grouped[span['file']].append(span)
                for source_id, values in grouped.items():
                    n = local[source_id]
                    found, _ = ranges.join_witnesses(by_name[n], values, {source_id: original['sources'][n]}, len(records))
                    for i, witness in found.items(): witnesses[indices[key(by_name[n][i])]] = witness
            records.append({'id': part['id'] + ':' + name, 'execution_profile': part['profile'],
                'kind': 'source-instrumented-pc' if part['id'].startswith('core-') else 'component-control-pc',
                'compiler_input_sha256': sha((OUT / (module['compiler'] + '-input.json')).read_bytes()),
                'compiler_output_sha256': sha((OUT / (module['compiler'] + '-output.json')).read_bytes()),
                'runtime_address': actual[name]['address'], 'runtime_sha256': actual[name]['code_sha256'],
                'observed_count': len(witnesses), 'indices': sorted(witnesses), 'witnesses': {str(i): w for i, w in sorted(witnesses.items())},
                'visited_pcs': sorted(observations)})
    observed = sorted({i for row in records for i in row['indices']})
    source_hashes = {n: sha(v['content'].encode()) for n, v in original['sources'].items()}
    historical = read(HERE / 'fixtures/historical-source-entries.json')
    historical_count = check_historical(historical, catalogue, source_hashes)
    result = {'scope': 'Fresh supplemental normal component/source tests only; not whole-product coverage or historical replay',
        'complete': True, 'source_count': 29, 'statement_count': 1642, 'required_percent': 90, 'required_count': 1478,
        'observed_count': len(observed), 'indices': observed, 'subjects': records, 'sources_sha256': source_hashes,
        'whole_source_threshold_met': len(observed) >= 1478,
        'historical_comparison_only': {'count': historical_count, 'source_snapshot_matches': True, 'current_ci_provenance_accepted': False}, 'production_coverage_qualified': False, 'operating_ready': False}
    with (OUT / 'source-observations.json').open('x') as stream: json.dump(result, stream, indent=2); stream.write('\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ['subjects', 'indices', 'sources_sha256']}))
    return result

if __name__ == '__main__': collect()
