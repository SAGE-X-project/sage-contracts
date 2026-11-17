"""Independent finite unit oracle; no VM, signatures, transport or call producer API.

Only the forty fixed framing controls are reconstructed here. Selectors come
from a separately executed public Go ABI artifact, not observed VM output or
the JavaScript encoder under test. These opaque values are not valid records.
"""
import hashlib
import re


def _word(value):
    assert type(value) is int and 0 <= value < 2 ** 256
    return value.to_bytes(32, 'big')


def _is_dynamic(field):
    kind = field['type']
    if kind in ('string', 'bytes') or kind.endswith('[]'):
        return True
    return kind == 'tuple' and any(_is_dynamic(part) for part in field['components'])


def _static_size(field):
    assert not _is_dynamic(field)
    return sum(_static_size(part) for part in field['components']) if field['type'] == 'tuple' else 32


def _sequence(fields, values):
    assert len(fields) == len(values)
    cursor = sum(32 if _is_dynamic(field) else _static_size(field) for field in fields)
    head, tail = bytearray(), bytearray()
    for field, value in zip(fields, values):
        encoded = _value(field, value)
        if _is_dynamic(field):
            head.extend(_word(cursor))
            tail.extend(encoded)
            cursor += len(encoded)
        else:
            head.extend(encoded)
    return bytes(head + tail)


def _value(field, value):
    kind = field['type']
    if kind.endswith('[]'):
        part = dict(field, type=kind[:-2])
        return _word(len(value)) + _sequence([part] * len(value), value)
    if kind == 'tuple':
        return _sequence(field['components'], [value[part['name']] for part in field['components']])
    if kind in ('string', 'bytes'):
        raw = value.encode('utf-8') if kind == 'string' else value
        return _word(len(raw)) + raw + bytes((-len(raw)) % 32)
    if kind == 'address':
        assert re.fullmatch('0x[0-9a-f]{40}', value)
        return _word(int(value, 16))
    if kind == 'bool':
        assert type(value) is bool
        return _word(int(value))
    if re.fullmatch(r'uint\d+', kind):
        assert 0 <= value < 2 ** int(kind[4:])
        return _word(value)
    assert re.fullmatch(r'bytes\d+', kind) and len(value) == int(kind[5:])
    return value + bytes(32 - len(value))


def expected_cases(functions, reference, fixed):
    """Return the complete finite name/input/outcome contract, without results."""
    assert reference['methods'] == 13 and len(functions) == 13
    assert len({method['name'] for method in functions}) == 13
    methods = {method['name']: method for method in functions}
    assert set(methods) == set(reference['selectors'])
    selectors = {name: bytes.fromhex(value.removeprefix('0x')) for name, value in reference['selectors'].items()}
    assert all(len(value) == 4 for value in selectors.values())

    def call(name, *values):
        return selectors[name] + _sequence(methods[name]['inputs'], values)

    controller = '0x0000000000000000000000000000000000000001'
    key = dict(name='signing', alg='ed25519', key=bytes([1]) * 32,
               signer='did:sage:unit#signing', proof=bytes([2]) * 64,
               hasExpiry=False, expires=0)
    service = dict(name='rpc', serviceType='A2A', uri='https://example.invalid/agent')
    data = [
        ('commitClaim', call('commitClaim', bytes([3]) * 32), None),
        ('revealClaim', call('revealClaim', 'unit', controller, [key], [service], bytes([4]) * 32), None),
        ('activate', call('activate', 'unit', 1), None),
        ('deactivate', call('deactivate', 'unit', 1), None),
        ('addKey', call('addKey', 'unit', 1, key), None),
        ('revokeKey', call('revokeKey', 'unit', 1, 'signing'), None),
        ('updateServices', call('updateServices', 'unit', 1, [service]), None),
        ('authorizeOperator', call('authorizeOperator', 'unit', 1, controller, 'update-services'), None),
        ('revokeOperator', call('revokeOperator', 'unit', 1, controller, 'update-services'), None),
        ('record', call('record', 'unit'), None),
        ('registryId', call('registryId'), None),
        ('activeGrants', call('activeGrants', 'unit'), None),
        ('historyItem', call('historyItem', 'unit', 1), None),
    ]
    maximum_key = dict(name='k' * 32, alg='a' * 24, key=bytes([1]) * 65,
                       signer='s' * 189, proof=bytes([2]) * 65,
                       hasExpiry=True, expires=2 ** 64 - 1)
    maximum_service = dict(name='s' * 32, serviceType='t' * 64, uri='u' * 2048)
    data += [('maximum lengths: framing only', call('revealClaim', 'a' * 64, controller,
               [maximum_key] * 128, [maximum_service] * 16, bytes(32)), None),
             ('empty arrays: framing only', call('revealClaim', '', controller, [], [], bytes(32)), None)]
    for literal in ('', '00', 'ffffffff', 'ffffffff00'):
        data.append(('fixed incomplete or unknown call:' + literal, bytes.fromhex(literal), 'MalformedCall'))
    data += [
        ('whole input bound', bytes(148805), 'BoundsExceeded'),
        ('fixed method trailing byte', call('registryId') + bytes(1), 'BoundsExceeded'),
        ('truncated fixed argument', call('commitClaim', bytes(32))[:35], 'MalformedCall'),
        ('field bound', call('addKey', 'unit', 1, dict(key, alg='a' * 25)), 'BoundsExceeded'),
        ('missing bounded tail', call('record', 'a')[:68], 'MalformedCall'),
        ('dynamic trailing byte', call('record', 'a') + bytes(1), 'MalformedCall'),
    ]
    assert len(fixed['cases']) == 9
    for fixture in fixed['cases']:
        assert fixture['diagnostic'] == 'MalformedCall'
        data.append((fixture['name'], bytes.fromhex(fixture['input_hex']), 'MalformedCall'))
    empty_key = dict(name='', alg='', key=b'', signer='', proof=b'', hasExpiry=False, expires=0)
    empty_service = dict(name='', serviceType='', uri='')
    data += [
        ('key count bound', call('revealClaim', '', controller, [empty_key] * 129, [], bytes(32)), 'BoundsExceeded'),
        ('service count bound', call('updateServices', '', 1, [empty_service] * 17), 'BoundsExceeded'),
        ('URI field bound', call('updateServices', 'unit', 1, [dict(service, uri='u' * 2049)]), 'BoundsExceeded'),
        ('key name field bound', call('addKey', 'unit', 1, dict(key, name='n' * 33)), 'BoundsExceeded'),
        ('proof field bound', call('addKey', 'unit', 1, dict(key, proof=bytes(66))), 'BoundsExceeded'),
        ('agent field bound', call('addKey', 'a' * 65, 1, key), 'BoundsExceeded'),
    ]
    # Keccak selectors independently fixed in the public outcomes ABI tests.
    errors = {'MalformedCall': '2d98cd51', 'BoundsExceeded': '8b54271a'}
    expected = {name: dict(input_hex=raw.hex(), input_bytes=len(raw),
                          input_sha256=hashlib.sha256(raw).hexdigest(),
                          exception='revert' if diagnostic else None,
                          return_hex=errors[diagnostic] if diagnostic else raw[:4].hex() + '00' * 28)
                for name, raw, diagnostic in data}
    assert len(data) == len(expected) == 40
    return expected


def check_rows(rows, expected):
    """Bind every observed input and both build outcomes to the fixed oracle."""
    assert len(rows) == len(expected) == 40
    assert len({row['name'] for row in rows}) == 40
    assert {row['name'] for row in rows} == set(expected)
    for row in rows:
        gold = expected[row['name']]
        assert {key: row[key] for key in gold} == gold, row['name']
        assert row['control_exception'] == gold['exception'], row['name']
        assert row['control_return_hex'] == gold['return_hex'], row['name']
