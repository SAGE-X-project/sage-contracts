"""Pure expected-code and source-entry attribution data checks, no execution."""
import base64
import hashlib
import re


def code_bytes(value):
    assert isinstance(value, str) and re.fullmatch(r'(?:[0-9a-f]{2})+', value)
    raw = bytes.fromhex(value)
    assert len(raw) <= 24576
    return raw


def immutable_names(sources):
    names = {}
    def walk(value):
        if isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, dict):
            if value.get('nodeType') == 'VariableDeclaration' and value.get('mutability') == 'immutable':
                ident = value['id']
                assert type(ident) is int and ident >= 0 and str(ident) not in names
                assert isinstance(value['name'], str) and value['name']
                names[str(ident)] = value['name']
            for child in value.values():
                if isinstance(child, (list, dict)):
                    walk(child)
    assert isinstance(sources, dict) and sources
    for source in sources.values():
        walk(source['ast'])
    return names


def expected_runtime(image, names, words):
    base = code_bytes(image['object'])
    assert image.get('linkReferences', {}) == {}
    refs = image.get('immutableReferences', {})
    assert isinstance(refs, dict) and isinstance(words, dict)
    assert all(isinstance(key, str) and key in names for key in refs)
    bound_names = [names[key] for key in refs]
    assert len(bound_names) == len(set(bound_names)) and set(bound_names) == set(words)
    assert all(isinstance(word, str) and re.fullmatch(r'[0-9a-f]{64}', word) for word in words.values())
    result = bytearray(base)
    occupied = set()
    bindings = []
    for ident, positions in refs.items():
        assert isinstance(positions, list) and positions
        for position in positions:
            assert set(position) == {'start', 'length'}
            start, length = position['start'], position['length']
            assert type(start) is int and type(length) is int and start >= 0 and length == 32
            assert start + length <= len(base)
            interval = set(range(start, start + length))
            assert interval.isdisjoint(occupied) and base[start:start + length] == bytes(32)
            occupied.update(interval)
            result[start:start + length] = bytes.fromhex(words[names[ident]])
        bindings.append({'id': ident, 'name': names[ident], 'word': words[names[ident]], 'positions': positions})
    raw = bytes(result)
    return {'hex': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
            'immutable_bindings': bindings, 'immutable_ids': len(refs)}


def opcode_positions(raw):
    flags = set()
    pc = 0
    while pc < len(raw):
        flags.add(pc)
        op = raw[pc]
        pc += 1 + (op - 0x5f if 0x60 <= op <= 0x7f else 0)
    return flags


def visited_pcs(code_hex, encoded):
    raw = code_bytes(code_hex)
    assert isinstance(encoded, str)
    bitmap = base64.b64decode(encoded, validate=True)
    assert base64.b64encode(bitmap).decode() == encoded and len(bitmap) == (len(raw) + 7) // 8
    flags = opcode_positions(raw)
    visited = {i for i in range(len(bitmap) * 8) if bitmap[i >> 3] & (1 << (i & 7))}
    assert visited <= flags
    return visited


def contained_hits(code_hex, spans, source_ids, rows, pcs):
    code = code_bytes(code_hex)
    assert isinstance(pcs, set) and all(type(pc) is int and 0 <= pc < len(code) and pc in spans for pc in pcs)
    assert pcs <= opcode_positions(code), 'Operand bytes are never instructions'
    assert len(set(source_ids.values())) == len(source_ids) and all(type(x) is int and x >= 0 for x in source_ids.values())
    assert len(rows) == len({row['marker_hex'] for row in rows})
    by_marker = {}
    for row in rows:
        marker = row['marker_hex']
        assert re.fullmatch(r'7f[0-9a-f]{62}', marker) and row['source'] in source_ids
        assert type(row['probe_start']) is int and type(row['probe_length']) is int and row['probe_start'] >= 0 and row['probe_length'] > 0
        by_marker[marker] = row
    hits = []
    for pc in sorted(pcs):
        if code[pc] != 0x7f:
            continue
        marker = code[pc + 1:pc + 33].hex()
        if marker not in by_marker:
            continue
        row, span = by_marker[marker], spans[pc]
        if (span is None or span[1] <= 0 or span[2] != source_ids[row['source']]
                or span[0] < row['probe_start'] or span[0] + span[1] > row['probe_start'] + row['probe_length']):
            continue
        hits.append({'marker_hex': marker, 'pc': pc, 'span': span})
    return hits
