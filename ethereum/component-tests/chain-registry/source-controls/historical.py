"""Check historical-vector arithmetic only; this does not authenticate provenance."""
KEYS = ['source', 'source_sha256', 'type', 'start', 'length']

def check_historical(value, catalogue, sources):
    key = lambda row: tuple(row[k] for k in KEYS)
    assert value['historical_only'] is True and value['current_ci_provenance_accepted'] is False
    assert value['sources_sha256'] == sources and len(sources) == value['source_count'] == 29
    assert len(catalogue) == len(value['catalogue']) == value['statement_count'] == 1642
    assert len({key(row) for row in catalogue}) == 1642
    assert {key(row) for row in value['catalogue']} == {key(row) for row in catalogue}
    subjects = value['subjects']
    assert len(subjects) == len({row['id'] for row in subjects}) == 39
    assert all(row['profile'] in ['paris', 'shanghai'] for row in subjects)
    assert all(row['kind'] in ['production-pc', 'component-control-pc', 'source-instrumented-pc'] for row in subjects)
    assert all(type(i) is int and 0 <= i < 1642 for row in subjects for i in row['indices'])
    count = len({i for row in subjects for i in row['indices']})
    assert count == value['observed_count'] == 1482 and value['required_count'] == 1478
    assert value['historical_product_pc_count'] == 1160 and value['historical_product_pc_threshold_met'] is False
    assert value['historical_product_map_static_upper_bound'] == 1328 and value['operating_ready'] is False
    assert set(value['profiles']) == {'paris', 'shanghai'}
    for fork, reported in value['profiles'].items():
        assert len({i for row in subjects if row['profile'] == fork for i in row['indices']}) == reported
    return count
