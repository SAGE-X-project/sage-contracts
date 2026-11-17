"""Independent expected JSON for one fixed owned entry/service unit schedule.

Consumes public fixture values and planned times, never VM observations.
No signing, compiler, VM, network or arbitrary request production.
"""
import base64
import copy
import hashlib
import json
import sys


def jcs(value):
    def check(item):
        if isinstance(item, str):
            assert item.isascii()
        elif type(item) is int:
            assert 0 <= item <= 9007199254740991
        elif isinstance(item, list):
            for child in item:
                check(child)
        elif isinstance(item, dict):
            for key, child in item.items():
                assert isinstance(key, str)
                check(key)
                check(child)
        else:
            assert item is None or type(item) is bool
    check(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def digest(value):
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).decode().rstrip('=')


def expected_trace(fixture):
    assert set(fixture) == {'registry', 'initial', 'keys', 'services', 'admitted', 'salt'}
    record = copy.deepcopy(fixture['initial'])
    assert record['id'].endswith(':owned-entry-targets')
    assert record['state'] == 'created' and record['version'] == '1'
    assert [key['name'] for key in record['keys']] == ['a-kem', 'z-sign']
    assert [key['name'] for key in fixture['keys']] == ['e-expired', 'm-add', 'n-kem', 'svc']
    assert fixture['keys'][0]['expires'] == 0
    assert all(key['state'] == 'accepted' for key in fixture['keys'])
    controller = record['controller']
    expired, added, kem, service = fixture['keys']
    operations = [
        ('create', {'controller': controller, 'keys': copy.deepcopy(record['keys']),
                    'salt': fixture['salt'], 'services': copy.deepcopy(record['services'])}),
        ('activate', {}),
        ('add-key', {'key': expired}),
        ('add-key', {'key': added}),
        ('add-key', {'key': kem}),
        ('revoke-key', {'name': 'm-add'}),
        ('update-services', {'services': []}),
        ('add-key', {'key': service}),
        ('revoke-key', {'name': 'z-sign'}),
        ('update-services', {'services': fixture['services']}),
        ('revoke-key', {'name': 'svc'})
    ]
    assert len(fixture['admitted']) == len(operations) == 11
    assert all(type(value) is int and 0 <= value <= 9007199254740991 for value in fixture['admitted'])
    assert all(a < b for a, b in zip(fixture['admitted'], fixture['admitted'][1:]))
    result = []
    for version, (operation, arguments) in enumerate(operations, 1):
        arguments = copy.deepcopy(arguments)
        if operation == 'activate':
            assert record['state'] == 'created'
            record['state'] = 'active'
        elif operation == 'add-key':
            assert record['state'] == 'active'
            record['keys'].append(copy.deepcopy(arguments['key']))
            record['keys'].sort(key=lambda value: value['name'])
        elif operation == 'revoke-key':
            key = next(value for value in record['keys'] if value['name'] == arguments['name'])
            assert key['state'] == 'accepted'
            key['state'] = 'revoked'
            usable = any(value['alg'] == 'ed25519' and value['state'] == 'accepted'
                         and ('expires' not in value or fixture['admitted'][version-1] < value['expires'])
                         for value in record['keys'])
            if not usable:
                record['state'] = 'deactivated'
        elif operation == 'update-services':
            record['services'] = copy.deepcopy(arguments['services'])
        record['version'] = str(version)
        previous = str(version-1) if version > 1 else ''
        command = {'actor': controller, 'arguments': arguments, 'binding': 'sage-registry-chain-0.11.0',
                   'did': record['id'], 'expectedVersion': previous, 'operation': operation,
                   'registry': fixture['registry']}
        record_bytes, grants_bytes, command_bytes = jcs(record), jcs([]), jcs(command)
        history = {'actor': controller, 'admitted': fixture['admitted'][version-1], 'automaticRemovals': [],
                   'commandDigest': digest(command_bytes), 'grantsDigest': digest(grants_bytes),
                   'operation': operation, 'previousVersion': previous, 'recordDigest': digest(record_bytes),
                   'target': None, 'version': str(version)}
        result.append({'version': version, 'operation': operation, 'actor': controller,
                       'record_hex': record_bytes.hex(), 'grants_hex': grants_bytes.hex(),
                       'command_hex': command_bytes.hex(), 'history_hex': jcs(history).hex(),
                       'command_digest_hex': hashlib.sha256(command_bytes).hexdigest(),
                       'record_digest_hex': hashlib.sha256(record_bytes).hexdigest(),
                       'grants_digest_hex': hashlib.sha256(grants_bytes).hexdigest(),
                       'did_hash_hex': hashlib.sha256(record['id'].encode()).hexdigest()})
    assert record['state'] == 'deactivated' and record['version'] == '11'
    assert [key['name'] for key in record['keys']] == ['a-kem', 'e-expired', 'm-add', 'n-kem', 'svc', 'z-sign']
    assert next(key for key in record['keys'] if key['name'] == 'e-expired')['state'] == 'accepted'
    return result


if __name__ == '__main__':
    print(json.dumps({'scope': 'Expected bytes for one fixed owned entry/service schedule',
                      'steps': expected_trace(json.load(sys.stdin))}, separators=(',', ':')))
