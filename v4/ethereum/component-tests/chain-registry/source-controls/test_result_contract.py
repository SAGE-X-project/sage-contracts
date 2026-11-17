"""Inert receipt regressions: failed coverage or cleanup must never report completion."""
import copy
import unittest
from result_contract import finalize

class ResultContractTests(unittest.TestCase):
    def test_success_has_no_operating_or_product_qualification(self):
        record = {'execution_complete': True, 'stages': [{'complete': True, 'cleanup_confirmed': True}]}
        before = copy.deepcopy(record)
        self.assertEqual(finalize(record, True, False), {'complete': True, 'production_coverage_qualified': False, 'operating_ready': False})
        self.assertEqual(record, before)

    def test_coverage_failure_or_error_never_completes(self):
        record = {'execution_complete': True, 'stages': [{'complete': True, 'cleanup_confirmed': True}]}
        for coverage, failed in [(False, False), (True, True), (False, True), (1, False)]:
            self.assertFalse(finalize(record, coverage, failed)['complete'])

    def test_partial_or_unconfirmed_execution_never_completes(self):
        for record in [{}, {'execution_complete': True}, {'execution_complete': False, 'stages': [{'complete': True, 'cleanup_confirmed': True}]},
                       {'execution_complete': True, 'stages': [{'complete': True, 'cleanup_confirmed': False}]},
                       {'execution_complete': True, 'stages': [{'complete': False, 'cleanup_confirmed': True}]}]:
            self.assertFalse(finalize(record, True, False)['complete'])
