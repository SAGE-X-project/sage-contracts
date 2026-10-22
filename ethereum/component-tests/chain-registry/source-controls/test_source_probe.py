"""Inert AST/UTF-8 coordinate units; no compilation, EVM or runtime claims."""
import copy
import hashlib
import json
import unittest
import subprocess
import sys
from pathlib import Path

from source_probe import STATEMENTS, instrument_source, source_range


def fixture(content='x();', kind='ExpressionStatement', file_id=0):
    raw = content.encode()
    row = {'source_sha256': hashlib.sha256(raw).hexdigest(), 'type': kind,
           'start': 0, 'length': len(raw), 'observed': True, 'witnesses': ['old-PC-only']}
    node = {'nodeType': kind, 'src': f'0:{len(raw)}:{file_id}'}
    return {'nodeType': 'SourceUnit', 'nodes': [node]}, [row]


def row_for(content, kind, start, length):
    return {'source_sha256': hashlib.sha256(content.encode()).hexdigest(),
            'type': kind, 'start': start, 'length': length}


class ProbeUnits(unittest.TestCase):
    def test_each_eligible_statement_keeps_identity_and_starts_unobserved(self):
        for kind in sorted(STATEMENTS):
            with self.subTest(kind=kind):
                ast, rows = fixture(kind=kind)
                out = instrument_source('x();', ast, rows, 0)
                self.assertEqual(len(out['statements']), 1)
                row = out['statements'][0]
                self.assertEqual(row['original']['type'], kind)
                self.assertNotIn('observed', row['original'])
                self.assertNotIn('witnesses', row['original'])
                self.assertFalse(row['observed'])
                self.assertFalse(out['coverage_qualified'])
                self.assertFalse(out['production_coverage_qualified'])

    def test_utf8_offsets_are_bytes_and_original_is_recoverable(self):
        content = '// 한글\nx();'
        start = len('// 한글\n'.encode())
        ast = {'nodeType': 'SourceUnit', 'nodes': [{'nodeType': 'ExpressionStatement', 'src': f'{start}:4:0'}]}
        out = instrument_source(content, ast, [row_for(content, 'ExpressionStatement', start, 4)], 0)
        self.assertTrue(out['content'].startswith('// 한글\nabi.encode'))
        raw = out['content'].encode()
        for span in reversed(out['inserted_spans']):
            raw = raw[:span['start']] + raw[span['start'] + span['length']:]
        self.assertEqual(raw, content.encode())

    def test_for_header_initialization_and_update_have_distinct_entry_sites(self):
        content = 'for(uint i=0;i<1;i++)x();'
        i, u, body = content.index('uint'), content.index('i++'), content.index('x();')
        node = {'nodeType': 'ForStatement', 'src': f'0:{len(content)}:0',
                'initializationExpression': {'nodeType': 'VariableDeclarationStatement', 'src': f'{i}:8:0'},
                'loopExpression': {'nodeType': 'ExpressionStatement', 'src': f'{u}:3:0'},
                'body': {'nodeType': 'ExpressionStatement', 'src': f'{body}:4:0'}}
        rows = [row_for(content, 'ForStatement', 0, len(content)),
                row_for(content, 'VariableDeclarationStatement', i, 8),
                row_for(content, 'ExpressionStatement', u, 3), row_for(content, 'ExpressionStatement', body, 4)]
        out = instrument_source(content, {'nodeType': 'SourceUnit', 'nodes': [node]}, rows, 0)
        self.assertEqual([x['mode'] for x in out['statements']],
                         ['statement-entry', 'for-initialization-entry', 'for-update-entry', 'statement-entry'])
        self.assertIn(', i++))', out['content'])
        self.assertIn('){abi.encode', out['content'])
        self.assertTrue(out['content'].endswith('x();}'))
        self.assertLess(out['statements'][0]['probe_start'], out['statements'][1]['probe_start'])

    def test_singleton_if_and_else_probes_remain_inside_braces(self):
        content = 'if(a)x();else y();'
        x, y = content.index('x();'), content.index('y();')
        node = {'nodeType': 'IfStatement', 'src': f'0:{len(content)}:0',
                'trueBody': {'nodeType': 'ExpressionStatement', 'src': f'{x}:4:0'},
                'falseBody': {'nodeType': 'ExpressionStatement', 'src': f'{y}:4:0'}}
        rows = [row_for(content, 'IfStatement', 0, len(content)), row_for(content, 'ExpressionStatement', x, 4), row_for(content, 'ExpressionStatement', y, 4)]
        out = instrument_source(content, {'nodeType': 'SourceUnit', 'nodes': [node]}, rows, 0)
        self.assertIn('if(a){abi.encode', out['content'])
        self.assertIn('x();}else {abi.encode', out['content'])
        self.assertTrue(out['content'].endswith('y();}'))

    def test_while_and_do_while_singleton_bodies(self):
        for kind in ['WhileStatement', 'DoWhileStatement']:
            content = 'while(a)x();'
            node = {'nodeType': kind, 'src': f'0:{len(content)}:0', 'body': {'nodeType': 'ExpressionStatement', 'src': '8:4:0'}}
            rows = [row_for(content, kind, 0, len(content)), row_for(content, 'ExpressionStatement', 8, 4)]
            out = instrument_source(content, {'nodeType': 'SourceUnit', 'nodes': [node]}, rows, 0)
            self.assertIn('while(a){abi.encode', out['content'])

    def test_existing_blocks_do_not_receive_redundant_body_braces(self):
        content = 'if(a){x();}'
        node = {'nodeType': 'IfStatement', 'src': f'0:{len(content)}:0', 'trueBody': {'nodeType': 'Block', 'statements': [{'nodeType': 'ExpressionStatement', 'src': '6:4:0'}]}}
        rows = [row_for(content, 'IfStatement', 0, len(content)), row_for(content, 'ExpressionStatement', 6, 4)]
        out = instrument_source(content, {'nodeType': 'SourceUnit', 'nodes': [node]}, rows, 0)
        self.assertEqual(out['content'].count('{'), 1)

    def test_rejects_wrong_source_identity(self):
        ast, rows = fixture()
        rows[0]['source_sha256'] = '0' * 64
        with self.assertRaises(AssertionError): instrument_source('x();', ast, rows, 0)

    def test_rejects_duplicate_canonical_identity(self):
        ast, rows = fixture()
        with self.assertRaises(AssertionError): instrument_source('x();', ast, rows + rows, 0)

    def test_rejects_missing_canonical_and_extra_ast_statement(self):
        ast, rows = fixture()
        with self.assertRaises(AssertionError): instrument_source('x();', ast, [], 0)
        with self.assertRaises(AssertionError): instrument_source('x();', {'nodeType': 'SourceUnit'}, rows, 0)

    def test_rejects_duplicate_ast_statement(self):
        ast, rows = fixture()
        ast['nodes'].append(copy.deepcopy(ast['nodes'][0]))
        with self.assertRaises(AssertionError): instrument_source('x();', ast, rows, 0)

    def test_rejects_unsupported_canonical_type(self):
        ast, rows = fixture()
        rows[0]['type'] = 'Identifier'
        with self.assertRaises(AssertionError): instrument_source('x();', ast, rows, 0)

    def test_rejects_invalid_canonical_ranges(self):
        for start, length in [(-1, 1), (0, 0), (0, 5), (False, 4), (0, True)]:
            ast, rows = fixture()
            rows[0].update(start=start, length=length)
            with self.assertRaises(AssertionError): instrument_source('x();', ast, rows, 0)

    def test_rejects_wrong_ast_file_and_bad_range_encoding(self):
        for src in ['0:4:1', '0:0:0', '-1:4:0', '0:5:0', '0:4', '٠:4:0', None]:
            ast, rows = fixture()
            ast['nodes'][0]['src'] = src
            with self.assertRaises(AssertionError): instrument_source('x();', ast, rows, 0)

    def test_rejects_invalid_top_level_inputs(self):
        ast, rows = fixture()
        for args in [(b'x();', ast, rows, 0), ('x();', [], rows, 0), ('x();', ast, rows, True), ('x();', ast, rows, -1), ('x();', ast, (), 0)]:
            with self.assertRaises(AssertionError): instrument_source(*args)

    def test_deterministic_and_does_not_mutate_ast_or_canonical(self):
        ast, rows = fixture()
        original = copy.deepcopy((ast, rows))
        first = instrument_source('x();', ast, rows, 0)
        self.assertEqual(first, instrument_source('x();', ast, rows, 0))
        self.assertEqual((ast, rows), original)

    def test_empty_file_has_no_invented_statement(self):
        out = instrument_source('', {'nodeType': 'SourceUnit'}, [], 0)
        self.assertEqual(out['content'], '')
        self.assertEqual(out['statements'], [])

    def test_nested_nonstatement_dictionaries_and_lists_are_walked(self):
        ast, rows = fixture()
        ast = {'metadata': {'layers': [None, 3, ast]}}
        self.assertEqual(len(instrument_source('x();', ast, rows, 0)['statements']), 1)

    def test_optimized_python_rejected_before_any_target_work(self):
        root = Path(__file__).resolve().parent
        scripts = [root / name for name in ['source_probe.py', 'prepare.py', 'collect.py', 'run.py']]
        for script in scripts:
            result = subprocess.run([sys.executable, '-O', '-B', str(script)],
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Optimized Python is not permitted', result.stderr)

    def test_missing_src_semicolon_is_inside_singleton_body_after_comments(self):
        bodies = [('ExpressionStatement', 'x()'), ('Return', 'return 1'),
                  ('Break', 'break'), ('Continue', 'continue'), ('RevertStatement', 'revert E()'),
                  ('EmitStatement', 'emit Seen(1)'), ('DoWhileStatement', 'do {} while(a)')]
        for kind, body in bodies:
            content = 'if(a)' + body + ' /* note */ // tail\n ;'
            end = 5 + len(body)
            node = {'nodeType': 'IfStatement', 'src': f'0:{end}:0',
                    'trueBody': {'nodeType': kind, 'src': f'5:{len(body)}:0'}}
            rows = [row_for(content, 'IfStatement', 0, end), row_for(content, kind, 5, len(body))]
            out = instrument_source(content, {'nodeType': 'SourceUnit', 'nodes': [node]}, rows, 0)
            self.assertTrue(out['content'].endswith('; }') or out['content'].endswith(';}'))
            self.assertIn(body + ' /* note */ // tail\n ;}', out['content'])

    def test_nested_singleton_if_and_while_include_terminal_semicolon(self):
        content = 'if(a)while(b)x();'
        node = {'nodeType': 'IfStatement', 'src': f'0:{len(content)-1}:0',
                'trueBody': {'nodeType': 'WhileStatement', 'src': f'5:{len(content)-6}:0',
                             'body': {'nodeType': 'ExpressionStatement', 'src': '13:3:0'}}}
        rows = [row_for(content, 'IfStatement', 0, len(content)-1),
                row_for(content, 'WhileStatement', 5, len(content)-6),
                row_for(content, 'ExpressionStatement', 13, 3)]
        out = instrument_source(content, {'nodeType': 'SourceUnit', 'nodes': [node]}, rows, 0)
        self.assertTrue(out['content'].endswith('x();}}'))

    def test_missing_or_unterminated_statement_tail_is_rejected(self):
        for tail in ['', ' /* unterminated', ' // unterminated', ' /* closed */ next']:
            content = 'if(a)x()' + tail
            node = {'nodeType': 'IfStatement', 'src': '0:8:0',
                    'trueBody': {'nodeType': 'ExpressionStatement', 'src': '5:3:0'}}
            rows = [row_for(content, 'IfStatement', 0, 8), row_for(content, 'ExpressionStatement', 5, 3)]
            with self.assertRaises(AssertionError):
                instrument_source(content, {'nodeType': 'SourceUnit', 'nodes': [node]}, rows, 0)

    def test_actual_solc_ast_singleton_terminators_regression(self):
        root = Path(__file__).resolve().parent
        content = (root / 'original-fixture.sol').read_text()
        output = json.loads((root / 'original-fixture-output.json').read_text())
        rows = []
        def walk(value):
            if isinstance(value, list):
                for child in value: walk(child)
            elif isinstance(value, dict):
                if value.get('nodeType') in STATEMENTS:
                    start, length, file_id = map(int, value['src'].split(':'))
                    rows.append(row_for(content, value['nodeType'], start, length))
                for child in value.values(): walk(child)
        walk(output['sources']['StatementFixture.sol']['ast'])
        self.assertEqual(len(rows), 21)
        self.assertEqual({x['type'] for x in rows}, STATEMENTS)
        out = instrument_source(content, output['sources']['StatementFixture.sol']['ast'], rows, 0)
        self.assertEqual(len(out['statements']), 21)
        for ending in ['continue;}', 'break;}', 'total++;}', 'revert NotReady();}']:
            self.assertIn(ending, out['content'])

    def test_nested_singleton_if_else_keeps_else_binding_and_final_semicolon(self):
        content = 'if(a)if(b)x();else y();'
        x, y = content.index('x()'), content.index('y()')
        inner = {'nodeType': 'IfStatement', 'src': f'5:{len(content)-6}:0',
                 'trueBody': {'nodeType': 'ExpressionStatement', 'src': f'{x}:3:0'},
                 'falseBody': {'nodeType': 'ExpressionStatement', 'src': f'{y}:3:0'}}
        outer = {'nodeType': 'IfStatement', 'src': f'0:{len(content)-1}:0', 'trueBody': inner}
        rows = [row_for(content, 'IfStatement', 0, len(content)-1),
                row_for(content, 'IfStatement', 5, len(content)-6),
                row_for(content, 'ExpressionStatement', x, 3), row_for(content, 'ExpressionStatement', y, 3)]
        out = instrument_source(content, {'nodeType': 'SourceUnit', 'nodes': [outer]}, rows, 0)
        self.assertIn('x();}else {', out['content'])
        self.assertTrue(out['content'].endswith('y();}}'))

    def test_source_range_accepts_exact_boundaries(self):
        self.assertEqual(source_range('0:4:2', 4, 2), (0, 4))


if __name__ == '__main__':
    unittest.main(verbosity=2)
