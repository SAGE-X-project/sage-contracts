"""Expected canonical bytes for four fixed owned lifecycle unit schedules.

Input contains owned fixture values and preplanned times, never observed results.
This program emits expected JSON only; it has no signing, VM or network surface.
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
    assert set(fixture) == {'mode', 'registry', 'initial', 'added', 'operator', 'wallet', 'admitted', 'salt'}
    record = copy.deepcopy(fixture['initial'])
    controller = record['controller']
    operator, wallet = fixture['operator'], fixture['wallet']
    zero = '0x' + '0' * 40
    assert record['state'] == 'created' and record['version'] == '1'
    assert [key['name'] for key in record['keys']] == ['a-kem', 'z-sign']
    assert fixture['added']['name'] == 'm-add' and fixture['added']['alg'] == 'ed25519'
    assert fixture['added']['state'] == 'accepted'
    create = ('create', controller, {'controller': controller, 'keys': copy.deepcopy(record['keys']), 'salt': fixture['salt'], 'services': copy.deepcopy(record['services'])})
    def grant(actor, scope):
        return {'operator': actor, 'scope': scope}
    if fixture['mode'] == 'created':
        operations = [create, ('revoke-key', controller, {'name': 'a-kem'}), ('deactivate', controller, {})]
    elif fixture['mode'] == 'active':
        operations = [create,
            ('authorize-operator', controller, grant(operator, 'activate')),
            ('authorize-operator', controller, grant(zero, 'deactivate')),
            ('authorize-operator', controller, grant(wallet, 'activate')),
            ('authorize-operator', controller, grant(operator, 'deactivate')),
            ('activate', operator, {}),
            ('authorize-operator', controller, grant(operator, 'add-key')),
            ('authorize-operator', controller, grant(operator, 'revoke-key')),
            ('add-key', operator, {'key': fixture['added']}),
            ('revoke-key', operator, {'name': 'm-add'}),
            ('update-services', controller, {'services': []}),
            ('revoke-operator', controller, grant(operator, 'add-key')),
            ('revoke-operator', controller, grant(zero, 'deactivate')),
            ('revoke-operator', controller, grant(operator, 'revoke-key')),
            ('deactivate', operator, {})]
    elif fixture['mode'] == 'expiry-recovery':
        operations = [create,
            ('authorize-operator', controller, grant(operator, 'activate')),
            ('activate', operator, {}),
            ('authorize-operator', controller, grant(operator, 'update-services')),
            ('update-services', operator, {'services': []}),
            ('add-key', controller, {'key': fixture['added']}),
            ('revoke-key', controller, {'name': 'z-sign'}),
            ('authorize-operator', controller, grant(operator, 'deactivate')),
            ('deactivate', operator, {})]
    else:
        assert fixture['mode'] == 'expiry-created'
        operations = [create,
            ('authorize-operator', controller, grant(operator, 'activate')),
            ('deactivate', controller, {})]
    assert len(operations) == len(fixture['admitted'])
    assert all(type(time) is int and 0 <= time <= 9007199254740991 for time in fixture['admitted'])
    assert fixture['admitted'] == sorted(fixture['admitted'])
    grants, result = [], []
    for index, (operation, actor, arguments) in enumerate(operations, 1):
        automatic, target = [], None
        if operation == 'authorize-operator':
            assert arguments not in grants
            grants.append(copy.deepcopy(arguments))
            grants.sort(key=lambda value: (value['operator'], value['scope']))
            target = arguments
        elif operation == 'revoke-operator':
            assert arguments in grants
            grants.remove(arguments)
            target = arguments
        elif operation == 'activate':
            assert record['state'] == 'created'
            record['state'] = 'active'
            automatic = [value for value in grants if value['scope'] == 'activate']
            grants = [value for value in grants if value['scope'] != 'activate']
        elif operation == 'deactivate':
            record['state'] = 'deactivated'
            automatic, grants = copy.deepcopy(grants), []
        elif operation == 'update-services':
            record['services'] = []
        elif operation == 'add-key':
            record['keys'].append(copy.deepcopy(arguments['key']))
            record['keys'].sort(key=lambda value: value['name'])
        elif operation == 'revoke-key':
            key = next(value for value in record['keys'] if value['name'] == arguments['name'])
            assert key['state'] == 'accepted'
            key['state'] = 'revoked'
            usable = any(value['alg'] == 'ed25519' and value['state'] == 'accepted' and ('expires' not in value or fixture['admitted'][index-1] < value['expires']) for value in record['keys'])
            if not usable:
                record['state'] = 'deactivated'
                automatic, grants = copy.deepcopy(grants), []
        record['version'] = str(index)
        previous = str(index-1) if index > 1 else ''
        command = {'actor': actor, 'arguments': arguments, 'binding': 'sage-registry-chain-0.11.0', 'did': record['id'], 'expectedVersion': previous, 'operation': operation, 'registry': fixture['registry']}
        encoded_record, encoded_grants, encoded_command = jcs(record), jcs(grants), jcs(command)
        history = {'actor': actor, 'admitted': fixture['admitted'][index-1], 'automaticRemovals': automatic, 'commandDigest': digest(encoded_command), 'grantsDigest': digest(encoded_grants), 'operation': operation, 'previousVersion': previous, 'recordDigest': digest(encoded_record), 'target': target, 'version': str(index)}
        result.append({'version': index, 'operation': operation, 'actor': actor, 'record_hex': encoded_record.hex(), 'grants_hex': encoded_grants.hex(), 'command_hex': encoded_command.hex(), 'history_hex': jcs(history).hex(), 'command_digest_hex': hashlib.sha256(encoded_command).hexdigest(), 'record_digest_hex': hashlib.sha256(encoded_record).hexdigest(), 'grants_digest_hex': hashlib.sha256(encoded_grants).hexdigest(), 'did_hash_hex': hashlib.sha256(record['id'].encode()).hexdigest()})
    assert record['state'] == 'deactivated' and not grants
    return result


if __name__ == '__main__':
    print(json.dumps({'scope': 'Expected bytes only for four fixed owned lifecycle schedules', 'steps': expected_trace(json.load(sys.stdin))}, separators=(',', ':')))
