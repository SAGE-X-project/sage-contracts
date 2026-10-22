"""Independent expected bytes for three fixed owned claim/clock traces.
Public fixture values and scheduled times only; no VM observations or signing.
"""
import copy
import hashlib
import json
import sys
from importlib.util import spec_from_file_location, module_from_spec
from pathlib import Path
spec = spec_from_file_location('entry_model', Path(__file__).with_name('expected-entry.py'))
shared = module_from_spec(spec)
spec.loader.exec_module(shared)
jcs, digest = shared.jcs, shared.digest


def expected(fixture):
    assert set(fixture) == {'registry', 'base_height', 'fixtures', 'collision'}
    base = fixture['base_height']
    assert type(base) is int and base > 0
    names = ['owned-claim-upper', 'owned-claim-retry', 'owned-claim-collision']
    offsets = [[256], [258, 258], [262]]
    assert len(fixture['fixtures']) == 3
    bad = fixture['collision']
    assert set(bad) == {'claim', 'commitment_hex'}
    corrected = fixture['fixtures'][2]['claim']
    expected_bad = copy.deepcopy(corrected)
    expected_bad['services'] = [{'name':'z-sign', 'type':'fixture', 'uri':'https://example.invalid/collision/'}]
    assert bad['claim'] == expected_bad
    assert hashlib.sha256(b'sage-claim-0.11.0\0' + jcs(bad['claim'])).hexdigest() == bad['commitment_hex']
    assert bad['commitment_hex'] != fixture['fixtures'][2]['commitment_hex']
    traces = []
    for value, name, steps in zip(fixture['fixtures'], names, offsets):
        assert set(value) == {'record', 'claim', 'commitment_hex'}
        record, claim = copy.deepcopy(value['record']), value['claim']
        assert record['id'] == 'did:sage:' + fixture['registry'] + ':' + name
        assert record['version'] == '1' and record['state'] == 'created'
        assert [key['name'] for key in record['keys']] == ['a-kem', 'z-sign']
        assert [key['alg'] for key in record['keys']] == ['x25519', 'ed25519']
        assert claim == {'registryId':fixture['registry'], 'agentId':name,
                         'controller':record['controller'], 'keys':record['keys'],
                         'services':record['services'], 'salt':claim['salt']}
        commitment = hashlib.sha256(b'sage-claim-0.11.0\0' + jcs(claim)).hexdigest()
        assert commitment == value['commitment_hex']
        result = []
        for version, offset in enumerate(steps, 1):
            operation = 'create' if version == 1 else 'activate'
            arguments = {'controller':record['controller'], 'keys':copy.deepcopy(record['keys']),
                         'services':copy.deepcopy(record['services']), 'salt':claim['salt']} if version == 1 else {}
            if version == 2:
                record['state'] = 'active'
            record['version'] = str(version)
            previous = '' if version == 1 else str(version - 1)
            command = {'actor':record['controller'], 'arguments':arguments,
                       'binding':'sage-registry-chain-0.11.0', 'did':record['id'],
                       'expectedVersion':previous, 'operation':operation, 'registry':fixture['registry']}
            rb, gb, cb = jcs(record), jcs([]), jcs(command)
            history = {'actor':record['controller'], 'admitted':10000 + base + offset,
                       'automaticRemovals':[], 'commandDigest':digest(cb), 'grantsDigest':digest(gb),
                       'operation':operation, 'previousVersion':previous, 'recordDigest':digest(rb),
                       'target':None, 'version':str(version)}
            result.append({'version':version, 'operation':operation, 'actor':record['controller'],
                           'record_hex':rb.hex(), 'grants_hex':gb.hex(), 'command_hex':cb.hex(),
                           'history_hex':jcs(history).hex(), 'command_digest_hex':hashlib.sha256(cb).hexdigest(),
                           'record_digest_hex':hashlib.sha256(rb).hexdigest(),
                           'grants_digest_hex':hashlib.sha256(gb).hexdigest(),
                           'did_hash_hex':hashlib.sha256(record['id'].encode()).hexdigest()})
        traces.append(result)
    assert json.loads(bytes.fromhex(traces[1][0]['history_hex']))['admitted'] == json.loads(bytes.fromhex(traces[1][1]['history_hex']))['admitted']
    return traces


if __name__ == '__main__':
    print(json.dumps({'traces':expected(json.load(sys.stdin))}, separators=(',', ':')))
