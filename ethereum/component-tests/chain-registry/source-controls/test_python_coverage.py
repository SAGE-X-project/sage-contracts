"""Inert line-count regressions; no compiler, child process or VM execution."""
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch
import run as runner

class PythonCoverageTests(unittest.TestCase):
    def coverage(self, source, executable, hits):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'inert.py'
            path.write_text(source)
            counts = {(str(path), line): count for line, count in hits}
            counts[('another.py', 1)] = 999
            with patch.object(runner.trace, '_find_executable_linenos', return_value=executable):
                result = runner.python_coverage(path, counts)
            self.assertEqual(result['sha256'], runner.sha(path))
            self.assertEqual(result['raw_line_counts'], sorted(hits))
            return result

    def test_synthetic_zero_and_outside_source_remain_visible(self):
        value = self.coverage('a = 1\nb = 2\n', [0, 1, 2, 3], [[0, 1], [1, 3], [2, 2]])
        self.assertEqual(value['raw_executable_lines'], [0, 1, 2, 3])
        self.assertEqual(value['excluded_non_source_lines'], [0, 3])
        self.assertEqual(value['executable_lines'], [1, 2])
        self.assertEqual((value['percent'], value['missing_lines']), (100, []))

    def test_real_uncovered_lines_still_fail_the_same_threshold(self):
        value = self.coverage('a = 1\nb = 2\n', [0, 1, 2], [[1, 1], [2, 0]])
        self.assertEqual(value['missing_lines'], [2])
        self.assertEqual((value['hit_lines'], value['percent']), ([1], 50))
        self.assertLess(value['percent'], 90)

    def test_no_synthetic_lines_preserves_existing_measurement(self):
        value = self.coverage('a = 1\nb = 2\n', [1, 2], [[1, 1], [2, 1]])
        self.assertEqual((value['excluded_non_source_lines'], value['percent']), ([], 100))

    def test_no_executable_source_is_not_a_passing_receipt(self):
        value = self.coverage('', [0], [[0, 1]])
        self.assertEqual((value['executable_lines'], value['percent']), ([], 0))

    def test_actual_python312_data_keeps_every_real_missing_line(self):
        fixture = json.loads((runner.HERE / 'fixtures/python-trace-312.json').read_text())
        self.assertEqual(len(fixture['rows']), 9)
        for old in fixture['rows']:
            with self.subTest(file=old['file']):
                path = runner.HERE / old['file']
                self.assertEqual(runner.sha(path), old['sha256'])
                counts = {(str(path), line): count for line, count in old['raw_line_counts']}
                with patch.object(runner.trace, '_find_executable_linenos', return_value=old['executable_lines']):
                    value = runner.python_coverage(path, counts)
                self.assertEqual(value['raw_executable_lines'], old['executable_lines'])
                self.assertEqual(value['raw_line_counts'], old['raw_line_counts'])
                self.assertEqual(value['excluded_non_source_lines'], [0])
                self.assertEqual(value['missing_lines'], [line for line in old['missing_lines'] if line != 0])
                self.assertEqual(value['hit_lines'], old['hit_lines'])
                self.assertGreaterEqual(value['percent'], 90)
                if old['file'] == 'result_contract.py':
                    self.assertEqual((len(value['executable_lines']), len(value['hit_lines']), value['percent']), (5, 5, 100))
                    self.assertLess(old['percent'], 90)
