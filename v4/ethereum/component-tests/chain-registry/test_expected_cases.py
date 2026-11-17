"""Fixed evidence-contract unit controls; never execute or submit calldata."""
import copy
import json
from pathlib import Path
import unittest
from expected_cases import expected_cases, check_rows

ROOT = Path(__file__).resolve().parent


class ExpectedCasesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        def read(name):
            return json.loads((ROOT / 'fixtures' / name).read_text())
        cls.expected = expected_cases(read('functions.json'), read('abi-selector-reference.json'), read('fixed-refusals.json'))
        cls.rows = [dict(name=name, **gold, control_exception=gold['exception'], control_return_hex=gold['return_hex'])
                    for name, gold in cls.expected.items()]

    def test_complete_fixed_contract(self):
        check_rows(self.rows, self.expected)
        self.assertEqual(self.expected['registryId']['input_hex'], '04ef898d')
        self.assertEqual(self.expected['commitClaim']['input_hex'], 'efc38947' + '03' * 32)
        self.assertEqual(self.expected['maximum lengths: framing only']['input_bytes'], 148804)

    def test_every_input_and_outcome_member_is_bound(self):
        # Change evidence metadata only: no modified calls are executed.
        for index in range(len(self.rows)):
            for field, replacement in [('input_hex', 'unobserved'), ('input_bytes', -1), ('input_sha256', ''),
                                       ('exception', 'unobserved'), ('return_hex', ''),
                                       ('control_exception', 'unobserved'), ('control_return_hex', '')]:
                with self.subTest(index=index, field=field):
                    rows = copy.deepcopy(self.rows)
                    rows[index][field] = replacement
                    with self.assertRaises(AssertionError):
                        check_rows(rows, self.expected)

    def test_missing_extra_and_duplicate_names_are_refused(self):
        duplicate = copy.deepcopy(self.rows)
        duplicate[1] = duplicate[0]
        renamed = copy.deepcopy(self.rows)
        renamed[0]['name'] = 'unlisted evidence row'
        for rows in [self.rows[:-1], self.rows + [self.rows[0]], duplicate, renamed]:
            with self.assertRaises(AssertionError):
                check_rows(rows, self.expected)

    def test_wrong_framing_diagnostic_is_refused(self):
        rows = copy.deepcopy(self.rows)
        row = next(row for row in rows if row['name'] == 'field bound')
        row['return_hex'] = row['control_return_hex'] = '2d98cd51'
        with self.assertRaises(AssertionError):
            check_rows(rows, self.expected)


if __name__ == '__main__':
    unittest.main(verbosity=2)
