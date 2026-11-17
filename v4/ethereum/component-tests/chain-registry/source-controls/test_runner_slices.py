"""Inert scheduling regressions; never start a child or a VM."""
import re
import unittest
from unittest.mock import patch
import run as runner

class RunnerSlicesTests(unittest.TestCase):
    def test_groups_partition_every_fixed_normal_case_once(self):
        names = ['stateless-paris', 'stateless-shanghai', 'rules-paris', 'rules-shanghai',
                 'processor-shanghai', 'core-shanghai', 'semantic-shanghai']
        with patch.object(runner, 'stage') as stage, patch('normal_coverage.verify') as coverage:
            runner.normal_units()
        commands = [call.args[1] for call in stage.call_args_list]
        patterns = [next(value.split('=', 1)[1] for value in cmd if value.startswith('--test-name-pattern=')) for cmd in commands]
        self.assertEqual([sum(bool(re.fullmatch(pattern, 'normal source controls: ' + name)) for pattern in patterns) for name in names], [1] * 7)
        self.assertFalse(any(re.fullmatch(pattern, 'normal source controls: extra-group') for pattern in patterns))
        self.assertEqual([sum(bool(re.fullmatch(pattern, 'normal source controls: ' + name)) for name in names) for pattern in patterns], [5, 2])

    def test_slices_keep_limits_and_separate_evidence(self):
        with patch.object(runner, 'stage') as stage, patch('normal_coverage.verify') as coverage:
            runner.normal_units()
        self.assertEqual(stage.call_count, 2)
        coverage.assert_called_once_with(runner.HERE / 'normal-unit.mjs', runner.OUT)
        names, coverage = [], []
        for call in stage.call_args_list:
            name, cmd, seconds = call.args
            names.append(name)
            self.assertEqual(seconds, 300)
            self.assertEqual(cmd[0], 'node')
            self.assertEqual(cmd[-1], 'normal-unit.mjs')
            for flag in ['--max-old-space-size=512', '--test-isolation=none', '--test-concurrency=1',
                         '--experimental-test-coverage',
                         '--test-coverage-include=**/source-controls/normal-unit.mjs']:
                self.assertIn(flag, cmd)
            self.assertFalse(any(value.startswith('--test-coverage-lines=') for value in cmd))
            coverage.append(next(value for value in cmd if value.startswith('--test-reporter-destination=evidence/')))
        self.assertEqual(len(set(names)), 2)
        self.assertEqual(len(set(coverage)), 2)

    def test_failed_first_slice_does_not_start_next_slice(self):
        with patch.object(runner, 'stage', side_effect=AssertionError('retained failed prefix')) as stage, patch('normal_coverage.verify') as coverage:
            with self.assertRaisesRegex(AssertionError, 'retained failed prefix'):
                runner.normal_units()
        self.assertEqual(stage.call_count, 1)
        coverage.assert_not_called()

    def test_non_normal_units_keep_their_original_selection(self):
        with patch.object(runner, 'stage') as stage, patch('normal_coverage.verify') as coverage:
            runner.node_units('compile-fixed', 'compile.mjs', '**/source-controls/compile.mjs')
        name, cmd, seconds = stage.call_args.args
        self.assertEqual((name, cmd[-1], seconds), ('compile-fixed', 'compile.mjs', 180))
        self.assertIn('--test-coverage-lines=90', cmd)
        self.assertFalse(any(value.startswith('--test-name-pattern=') for value in cmd))
