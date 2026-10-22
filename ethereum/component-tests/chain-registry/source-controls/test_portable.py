"""Inert source/receipt regressions; no compiler, EVM, RPC or protocol requests."""
from pathlib import Path
import copy
import json
import tempfile
import unittest
from unittest.mock import patch
import prepare
from historical import check_historical

class PortableDataTests(unittest.TestCase):
    def setUp(self):
        self.vector = json.loads((Path(__file__).parent / 'fixtures/historical-source-entries.json').read_text())
        self.catalogue = copy.deepcopy(self.vector['catalogue'])
        self.sources = copy.deepcopy(self.vector['sources_sha256'])

    def test_historical_arithmetic_does_not_promote_scope(self):
        before = copy.deepcopy(self.vector)
        self.assertEqual(check_historical(self.vector, self.catalogue, self.sources), 1482)
        self.assertEqual(self.vector, before)
        self.assertFalse(self.vector['current_ci_provenance_accepted'])
        self.assertFalse(self.vector['historical_product_pc_threshold_met'])

    def test_changed_original_or_dropped_empty_interface_is_rejected(self):
        for mode in ['change-source', 'drop-empty', 'drop-entry', 'duplicate-entry']:
            sources, rows = copy.deepcopy(self.sources), copy.deepcopy(self.catalogue)
            if mode == 'change-source': sources[next(iter(sources))] = '0' * 64
            if mode == 'drop-empty': del sources[next(n for n in sources if n.endswith('/IChainRegistry.sol'))]
            if mode == 'drop-entry': rows.pop()
            if mode == 'duplicate-entry': rows[0] = copy.deepcopy(rows[1])
            with self.assertRaises(AssertionError): check_historical(self.vector, rows, sources)

    def test_historical_indices_profiles_and_product_scope_are_strict(self):
        for field, replacement in [('indices', [True]), ('indices', [-1]), ('indices', [1642]),
                                   ('profile', 'future-fork'), ('kind', 'unverified')]:
            vector = copy.deepcopy(self.vector)
            vector['subjects'][0][field] = replacement
            with self.assertRaises(AssertionError): check_historical(vector, self.catalogue, self.sources)
        for field, replacement in [('current_ci_provenance_accepted', True), ('historical_only', False),
                                   ('historical_product_pc_threshold_met', True), ('operating_ready', True),
                                   ('observed_count', 1642), ('required_count', 1),
                                   ('historical_product_map_static_upper_bound', 1642), ('profiles', {'paris': 1482})]:
            vector = copy.deepcopy(self.vector); vector[field] = replacement
            with self.assertRaises(AssertionError): check_historical(vector, self.catalogue, self.sources)

    def test_original_source_bytes_and_profile_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); base = root / 'tests'; compiled = base / 'runtime/evidence/compiler'; compiled.mkdir(parents=True)
            sources = {f'source-{i}.sol': {'content': '' if i == 0 else f'// inert {i}\n'} for i in range(29)}
            for name, item in sources.items(): (root / name).write_text(item['content'])
            inp = {'settings': {'evmVersion': 'shanghai'}, 'sources': sources}
            output = {'sources': {name: {} for name in sources}}
            for suffix, value in [('input', inp), ('output', output)]: (compiled / ('shanghai-' + suffix + '.json')).write_text(json.dumps(value))
            with patch.object(prepare, 'BASE', base), patch.object(prepare, 'REPO', root):
                self.assertEqual(prepare.original('shanghai'), (inp, output))
                (root / 'source-1.sol').write_text('changed')
                with self.assertRaises(AssertionError): prepare.original('shanghai')
                (root / 'source-1.sol').write_text(sources['source-1.sol']['content'])
                inp['settings']['evmVersion'] = 'paris'; (compiled / 'shanghai-input.json').write_text(json.dumps(inp))
                with self.assertRaises(AssertionError): prepare.original('shanghai')

    def test_image_limits_and_unbound_immutable_are_rejected(self):
        art = {'evm': {'bytecode': {'object': '00'}, 'deployedBytecode': {'object': '00'}}}
        self.assertEqual(prepare.images(art)['runtime']['bytes'], 1)
        for field, oversized in [('bytecode', 49153), ('deployedBytecode', 24577)]:
            changed = copy.deepcopy(art); changed['evm'][field]['object'] = '00' * oversized
            with self.assertRaises(AssertionError): prepare.images(changed)
        changed = copy.deepcopy(art); changed['evm']['deployedBytecode']['immutableReferences'] = {'1': [{'start': 0, 'length': 32}]}
        with self.assertRaises(AssertionError): prepare.images(changed)

    def test_collector_rejects_incomplete_bundle_and_changed_canonical_data(self):
        import collect as collector
        original = {'sources': {name: {'content': (prepare.REPO / name).read_text()} for name in self.sources}}
        for mode in ['missing-parts', 'dropped-entry', 'duplicate-entry', 'changed-source']:
            rows, inp = copy.deepcopy(self.catalogue), copy.deepcopy(original)
            if mode == 'dropped-entry': rows.pop()
            if mode == 'duplicate-entry': rows[0] = copy.deepcopy(rows[1])
            if mode == 'changed-source': inp['sources'][rows[0]['source']]['content'] += ' changed'
            values = {'shanghai-input.json': inp, 'catalogue.json': rows, 'subjects.json': {'parts': []}}
            with patch.object(collector, 'read', side_effect=lambda path: values[path.name]):
                with self.assertRaises(AssertionError): collector.collect()
