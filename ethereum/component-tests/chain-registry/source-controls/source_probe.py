"""Test-copy statement-entry probes; no compiler, VM or coverage verdict.

Original byte ranges remain authoritative. For-loop initializers enter with the
loop; updates use a tuple expression at the original update position. Singleton
control bodies gain braces so their probes stay conditional. Every original
canonical statement remains in the returned catalogue, with no implicit hits.
"""
import os
import sys

if sys.flags.optimize != 0 or os.environ.get('PYTHONOPTIMIZE', '') not in ('', '0'):
    raise RuntimeError('Optimized Python is not permitted')

import hashlib
import json

STATEMENTS = frozenset({
    'ExpressionStatement', 'VariableDeclarationStatement', 'IfStatement',
    'ForStatement', 'WhileStatement', 'DoWhileStatement', 'Return', 'EmitStatement',
    'RevertStatement', 'TryStatement', 'Break', 'Continue', 'InlineAssembly',
})


def source_range(value, size, file_id):
    assert isinstance(value, str)
    fields = value.split(':')
    assert len(fields) == 3 and all(v.isascii() and v.isdecimal() for v in fields)
    start, length, actual_file = map(int, fields)
    assert actual_file == file_id and length > 0
    assert 0 <= start < start + length <= size
    return start, length



def statement_end(node, raw, file_id):
    start, length = source_range(node['src'], len(raw), file_id)
    end = start + length
    kind = node['nodeType']
    if kind == 'IfStatement':
        child = node.get('falseBody') or node['trueBody']
        return max(end, statement_end(child, raw, file_id))
    if kind in {'ForStatement', 'WhileStatement'}:
        return max(end, statement_end(node['body'], raw, file_id))
    terminated = {'ExpressionStatement', 'VariableDeclarationStatement', 'Return',
                  'EmitStatement', 'RevertStatement', 'Break', 'Continue', 'DoWhileStatement'}
    if kind not in terminated or raw[end - 1:end] == b';':
        return end
    # Solidity AST src commonly excludes the terminating semicolon. Skip only
    # lexical whitespace/comments after the compiler-delimited statement.
    cursor = end
    while cursor < len(raw):
        if raw[cursor] in b' \t\r\n\v\f':
            cursor += 1
        elif raw[cursor:cursor + 2] == b'/*':
            close = raw.find(b'*/', cursor + 2)
            assert close >= 0, 'Unterminated comment after statement'
            cursor = close + 2
        elif raw[cursor:cursor + 2] == b'//':
            newline = raw.find(b'\n', cursor + 2)
            assert newline >= 0, 'Missing terminator after line comment'
            cursor = newline + 1
        else:
            break
    assert raw[cursor:cursor + 1] == b';', 'Missing statement terminator'
    return cursor + 1

def instrument_source(content, ast, canonical, file_id):
    assert isinstance(content, str) and isinstance(ast, dict)
    assert type(file_id) is int and file_id >= 0 and isinstance(canonical, list)
    raw = content.encode('utf-8')
    identity = hashlib.sha256(raw).hexdigest()
    entries = {}
    for row in canonical:
        assert row['source_sha256'] == identity and row['type'] in STATEMENTS
        start, length = row['start'], row['length']
        assert type(start) is int and type(length) is int
        assert length > 0 and 0 <= start < start + length <= len(raw)
        key = (row['type'], start, length)
        assert key not in entries
        entries[key] = row

    nodes = []
    singleton_bodies = set()

    def walk(value, parent=None, field=None):
        if isinstance(value, list):
            for child in value:
                walk(child, parent, field)
        elif isinstance(value, dict):
            kind = value.get('nodeType')
            if kind in STATEMENTS:
                start, length = source_range(value['src'], len(raw), file_id)
                nodes.append(((kind, start, length), parent, field))
            if kind in {'IfStatement', 'ForStatement', 'WhileStatement', 'DoWhileStatement'}:
                fields = ('trueBody', 'falseBody') if kind == 'IfStatement' else ('body',)
                for name in fields:
                    body = value.get(name)
                    if body and body.get('nodeType') not in {'Block', 'UncheckedBlock'}:
                        start, length = source_range(body['src'], len(raw), file_id)
                        singleton_bodies.add((start, statement_end(body, raw, file_id) - start))
            for name, child in value.items():
                walk(child, value, name)

    walk(ast)
    keys = [key for key, _, _ in nodes]
    assert len(keys) == len(set(keys)) and set(keys) == set(entries)
    events = []
    for start, length in singleton_bodies:
        events.append((start, 2, b'{', None))
        events.append((start + length, 1, b'}', None))
    records = {}
    markers = set()
    for key, parent, field in nodes:
        kind, start, length = key
        seed = json.dumps([identity, kind, start, length], separators=(',', ':')).encode()
        marker = '7f' + hashlib.sha256(seed).hexdigest()[:62]
        assert marker not in markers and marker.encode() not in raw.lower()
        markers.add(marker)
        expression = ('abi.encode(uint256(0x' + marker + '))').encode()
        mode = 'statement-entry'
        offset = start
        if parent and parent.get('nodeType') == 'ForStatement':
            if field == 'initializationExpression':
                offset, _ = source_range(parent['src'], len(raw), file_id)
                mode = 'for-initialization-entry'
            elif field == 'loopExpression':
                assert kind == 'ExpressionStatement'
                mode = 'for-update-entry'
        if mode == 'for-update-entry':
            events.append((start, 3, b'(' + expression + b', ', key))
            events.append((start + length, 0, b')', None))
        else:
            # Parent loop probe precedes its initializer probe at the same offset.
            phase = 5 if mode == 'for-initialization-entry' else 4
            events.append((offset, phase, expression + b';', key))
        records[key] = {
            'original': {k: v for k, v in entries[key].items() if k not in {'observed', 'witnesses'}}, 'marker_hex': marker,
            'mode': mode, 'observed': False, 'probe_start': None,
            'probe_length': len(expression),
        }
    result = bytearray()
    inserted = []
    cursor = 0
    for position, phase, text, key in sorted(events, key=lambda x: (x[0], x[1])):
        assert position >= cursor
        result.extend(raw[cursor:position])
        if key is not None:
            records[key]['probe_start'] = len(result) + (1 if phase == 3 else 0)
        inserted.append({'start': len(result), 'length': len(text)})
        result.extend(text)
        cursor = position
    result.extend(raw[cursor:])
    rendered = bytes(result)
    restored = rendered
    for span in reversed(inserted):
        restored = restored[:span['start']] + restored[span['start'] + span['length']:]
    assert restored == raw
    rows = [records[key] for key in sorted(records, key=lambda x: (x[1], x[2], x[0]))]
    for row in rows:
        assert row['probe_start'] is not None
        probe = rendered[row['probe_start']:row['probe_start'] + row['probe_length']]
        assert probe == ('abi.encode(uint256(0x' + row['marker_hex'] + '))').encode()
    return {
        'scope': 'Source-test instrumentation only; no executed hit or production qualification',
        'source_sha256': identity, 'instrumented_sha256': hashlib.sha256(rendered).hexdigest(),
        'content': rendered.decode('utf-8'), 'statements': rows, 'inserted_spans': inserted,
        'coverage_qualified': False, 'production_coverage_qualified': False,
    }
