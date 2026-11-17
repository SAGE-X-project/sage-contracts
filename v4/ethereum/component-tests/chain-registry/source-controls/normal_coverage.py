"""Join two complete native LCOV line maps for the same normal-test source."""
import hashlib
import json

GROUPS = ('components', 'composition')
sha = lambda data: hashlib.sha256(data).hexdigest()

def line_map(data, count):
    rows = data.decode('utf-8').splitlines()
    assert rows[:2] == ['TN:', 'SF:normal-unit.mjs'] and rows[-1:] == ['end_of_record']
    assert sum(row.startswith('SF:') for row in rows) == 1
    assert rows.count('TN:') == rows.count('end_of_record') == 1
    allowed = ('TN:', 'SF:', 'FN:', 'FNDA:', 'FNF:', 'FNH:', 'BRDA:', 'BRF:', 'BRH:', 'DA:', 'LH:', 'LF:')
    assert all(row == 'end_of_record' or row.startswith(allowed) for row in rows)
    values = {}
    for row in rows:
        if not row.startswith('DA:'): continue
        fields = row[3:].split(',')
        assert len(fields) == 2 and all(value and set(value) <= set('0123456789') for value in fields)
        line, hits = map(int, fields)
        assert line not in values and 1 <= line <= count
        values[line] = hits
    assert set(values) == set(range(1, count + 1))
    hit = {line for line, hits in values.items() if hits > 0}
    assert [row for row in rows if row.startswith('LF:')] == ['LF:' + str(count)]
    assert [row for row in rows if row.startswith('LH:')] == ['LH:' + str(len(hit))]
    return hit

def verify(source, evidence):
    assert source.name == 'normal-unit.mjs' and source.is_file() and not source.is_symlink()
    original = source.read_bytes()
    count = len(original.decode('utf-8').splitlines())
    assert count > 0
    hit, groups = set(), []
    for name in GROUPS:
        path = evidence / ('normal-controls-' + name + '-coverage.lcov')
        assert path.is_file() and not path.is_symlink() and path.stat().st_size <= 2 * 1024 ** 2
        data = path.read_bytes()
        observed = line_map(data, count)
        groups.append({'name': name, 'lcov_sha256': sha(data), 'hit_lines': sorted(observed),
                       'line_percent': 100 * len(observed) / count})
        hit.update(observed)
    assert source.read_bytes() == original
    value = {'scope': 'Combined native line coverage of the unchanged normal VM test source only',
             'source': source.name, 'source_sha256': sha(original), 'line_count': count,
             'groups': groups, 'hit_lines': sorted(hit), 'missing_lines': sorted(set(range(1, count + 1)) - hit),
             'required_percent': 90, 'percent': 100 * len(hit) / count, 'complete': 100 * len(hit) >= 90 * count,
             'production_coverage_qualified': False, 'operating_ready': False}
    with (evidence / 'normal-controls-coverage.json').open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
    assert value['complete'], 'Combined normal-test line coverage is below 90%'
    return value
