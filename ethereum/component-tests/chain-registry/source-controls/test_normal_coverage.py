"""Fixed LCOV data only; no Node, compiler or VM execution."""
from pathlib import Path
import json
import tempfile
import unittest
from normal_coverage import GROUPS, line_map, verify

def lcov(count, hit):
    rows = ['TN:', 'SF:normal-unit.mjs'] + [f'DA:{line},{int(line in hit)}' for line in range(1, count + 1)]
    return ('\n'.join(rows + ['LH:' + str(len(hit)), 'LF:' + str(count), 'end_of_record']) + '\n').encode()

class NormalCoverageTests(unittest.TestCase):
    def prepare(self, directory, left, right):
        root = Path(directory)
        source = root / 'normal-unit.mjs'; source.write_text('// inert source line\n' * 10)
        for name, hit in zip(GROUPS, [left, right]):
            (root / ('normal-controls-' + name + '-coverage.lcov')).write_bytes(lcov(10, hit))
        return source, root

    def test_disjoint_low_slices_join_without_raising_each_slice_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            source, root = self.prepare(directory, set(range(1, 6)), set(range(6, 11)))
            value = verify(source, root)
            self.assertEqual([g['line_percent'] for g in value['groups']], [50, 50])
            self.assertEqual((value['line_count'], value['percent'], value['complete']), (10, 100, True))
            self.assertFalse(value['production_coverage_qualified'] or value['operating_ready'])
            self.assertEqual(json.loads((root / 'normal-controls-coverage.json').read_text()), value)
            with self.assertRaises(FileExistsError): verify(source, root)

    def test_overlapping_hits_cannot_be_added_to_reach_threshold(self):
        with tempfile.TemporaryDirectory() as directory:
            source, root = self.prepare(directory, set(range(1, 9)), set(range(1, 9)))
            with self.assertRaisesRegex(AssertionError, 'below 90%'): verify(source, root)
            value = json.loads((root / 'normal-controls-coverage.json').read_text())
            self.assertEqual((value['percent'], value['complete'], value['missing_lines']), (80, False, [9, 10]))

    def test_exact_threshold_is_accepted_and_source_not_changed(self):
        with tempfile.TemporaryDirectory() as directory:
            source, root = self.prepare(directory, set(range(1, 6)), set(range(5, 10)))
            before = source.read_bytes()
            self.assertEqual(verify(source, root)['percent'], 90)
            self.assertEqual(source.read_bytes(), before)

    def test_missing_or_symlink_slice_cannot_complete(self):
        for mode in ['missing', 'symlink']:
            with tempfile.TemporaryDirectory() as directory:
                source, root = self.prepare(directory, set(range(1, 11)), set(range(1, 11)))
                path = root / 'normal-controls-composition-coverage.lcov'; data = path.read_bytes(); path.unlink()
                if mode == 'symlink':
                    target = root / 'inert.lcov'; target.write_bytes(data); path.symlink_to(target)
                with self.assertRaises(AssertionError): verify(source, root)
                self.assertFalse((root / 'normal-controls-coverage.json').exists())

    def test_empty_or_wrong_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source, root = self.prepare(directory, set(range(1, 11)), set(range(1, 11)))
            source.write_text('')
            with self.assertRaises(AssertionError): verify(source, root)
            with self.assertRaises(AssertionError): verify(root / 'other.mjs', root)

    def test_duplicate_omitted_or_outside_line_ids_are_rejected(self):
        original = lcov(10, set(range(1, 11)))
        for changed in [original.replace(b'DA:2,1', b'DA:1,1'), original.replace(b'DA:2,1\n', b''),
                        original.replace(b'DA:2,1', b'DA:11,1'), original.replace(b'DA:2,1', b'DA:0,1')]:
            with self.assertRaises(AssertionError): line_map(changed, 10)

    def test_changed_file_or_record_and_summary_are_rejected(self):
        original = lcov(10, set(range(1, 11)))
        for changed in [original.replace(b'SF:normal-unit.mjs', b'SF:another.mjs'),
                        original + original, original.replace(b'LF:10', b'LF:9'),
                        original.replace(b'LH:10', b'LH:9'), original.replace(b'TN:', b'TN:other'),
                        original.replace(b'DA:2,1', b'UNKNOWN:2,1')]:
            with self.assertRaises(AssertionError): line_map(changed, 10)

    def test_malformed_negative_or_extra_counts_are_rejected(self):
        original = lcov(10, set(range(1, 11)))
        for changed in [original.replace(b'DA:2,1', value) for value in [b'DA:2,-1', b'DA:2,1,1', b'DA:2,', b'DA:x,1']]:
            with self.assertRaises(AssertionError): line_map(changed, 10)
