"""Fixed inert source-map and bitmap tests; no EVM, Solidity compiler or protocol input."""
import base64, hashlib, unittest
import pilot_source_ranges

class DataTests:
    api = vars(pilot_source_ranges)

    def f(self, name, *args):
        return self.api[name](*args)

    def statement(self, path='one.sol', content='abcdef', kind='Return', start=2, length=2):
        return self.f('canonical_statements', path, content,
            {'nodeType': kind, 'id': 1, 'src': f'{start}:{length}:0'})[0]

    def test_full_taxonomy_and_scope(self):
        kinds = sorted(self.api['STATEMENTS'])
        self.assertEqual(len(kinds), 13)
        ast = {'nodeType': 'ContractDefinition', 'name': 'Owned', 'nodes': [
            {'nodeType': 'FunctionDefinition', 'kind': 'constructor', 'name': '', 'body': [
                {'nodeType': k, 'id': i, 'src': f'{i}:1:0'} for i, k in enumerate(kinds)]}, 'inert', 17]}
        rows = self.f('canonical_statements', 'one.sol', 'abcdefghijklmnop', ast)
        self.assertEqual({x['type'] for x in rows}, set(kinds))
        self.assertTrue(all(x['contract'] == 'Owned' and x['function'] == '<constructor>' for x in rows))

    def test_named_function_and_utf8_offsets(self):
        ast = {'nodeType': 'FunctionDefinition', 'kind': 'function', 'name': 'read',
            'body': {'nodeType': 'Return', 'id': 1, 'src': '2:1:0'}}
        rows = self.f('canonical_statements', 'unicode.sol', 'éabc', ast)
        self.assertEqual(rows[0]['function'], 'read')
        self.assertEqual(rows[0]['source_sha256'], hashlib.sha256('éabc'.encode()).hexdigest())

    def test_reject_canonical_invalid_and_duplicate(self):
        for start, length in [(-1, 1), (0, 0), (5, 2)]:
            with self.assertRaises(ValueError):
                self.statement(start=start, length=length)
        node = {'nodeType': 'Return', 'id': 1, 'src': '2:2:0'}
        with self.assertRaises(ValueError):
            self.f('canonical_statements', 'one.sol', 'abcdef', [node, dict(node, id=2)])

    def test_push_operands_are_not_instruction_pcs(self):
        maps = self.f('instruction_maps', '61aabb00', '0:1:0;')
        self.assertEqual(set(maps), {0, 3})
        self.assertEqual(maps[3], (0, 1, 0))
        with self.assertRaises(ValueError):
            self.f('mapped_spans', '61aabb00', '0:1:0;', [1])

    def test_truncated_push_and_source_carry(self):
        self.assertEqual(self.f('instruction_maps', '60', '0:1:0'), {0: (0, 1, 0)})
        maps = self.f('instruction_maps', '00000000', '1:2:3;;;4:1:0')
        self.assertEqual(maps[2], (1, 2, 3))
        self.assertEqual(maps[3], (4, 1, 0))

    def test_unmapped_generated_zero_are_not_hits(self):
        spans, kinds = self.f('mapped_spans', '0000', '', [0, 1])
        self.assertFalse(spans)
        self.assertEqual(kinds['unmapped'], 1)
        self.assertEqual(kinds['generated_or_unknown'], 1)
        spans, kinds = self.f('mapped_spans', '0000', '0:0:0;0:1:-1', [0, 1])
        self.assertFalse(spans)
        self.assertEqual(kinds['zero_length'], 1)
        self.assertEqual(kinds['generated_or_unknown'], 1)

    def test_reject_bad_map_and_bytecode_bounds(self):
        for code, sm in [('', ''), ('00' * 24577, ''), ('00', '0:1:0;'),
                         ('00', '0:1:0:::1'), ('00', '-2:1:0'), ('zz', '')]:
            with self.assertRaises(ValueError):
                self.f('instruction_maps', code, sm)

    def test_reject_bad_visited_lists(self):
        for pcs in [None, (0,), [True], ['0'], [1, 0], [0, 0], list(range(24577))]:
            with self.assertRaises(ValueError):
                self.f('mapped_spans', '0000', '0:1:0;', pcs)

    def test_contained_ranges_not_ancestor_spans(self):
        statement = self.statement()
        sha = statement['source_sha256']
        self.assertFalse(self.f('contained', statement, {'start': 0, 'length': 6}, sha))
        self.assertFalse(self.f('contained', statement, {'start': 2, 'length': 0}, sha))
        self.assertFalse(self.f('contained', statement, {'start': 3, 'length': 2}, sha))
        self.assertTrue(self.f('contained', statement, {'start': 2, 'length': 1}, sha))

    def test_changed_source_and_same_basename_do_not_join(self):
        statement = self.statement()
        span = {'pc': 0, 'start': 2, 'length': 1, 'file': 10}
        found, foreign = self.f('join_witnesses', [statement], [span], {10: {'name': 'one.sol', 'content': 'ABCDEF'}}, 0)
        self.assertFalse(found)
        self.assertEqual(foreign, 1)

    def test_source_ids_are_local_and_ids_are_not_join_keys(self):
        statement = self.statement()
        span = {'pc': 0, 'start': 2, 'length': 1, 'file': 99}
        found, foreign = self.f('join_witnesses', [statement], [span], {99: {'name': 'alias.sol', 'content': 'abcdef'}}, 'control-A')
        self.assertEqual(set(found), {0})
        self.assertEqual(found[0]['build_local_source_id'], 99)
        self.assertEqual(foreign, 0)

    def test_ambiguous_hash_never_selects_first_source(self):
        statements = [self.statement('one.sol'), self.statement('two.sol')]
        span = {'pc': 0, 'start': 2, 'length': 1, 'file': 0}
        with self.assertRaises(ValueError):
            self.f('join_witnesses', statements, [span], {0: {'content': 'abcdef'}}, 0)

    def test_unknown_source_and_outside_range(self):
        statement = self.statement()
        span = {'pc': 0, 'start': 2, 'length': 1, 'file': 99}
        found, foreign = self.f('join_witnesses', [statement], [span], {}, 0)
        self.assertFalse(found)
        self.assertEqual(foreign, 1)
        with self.assertRaises(ValueError):
            self.f('join_witnesses', [statement], [dict(span, start=5, length=2)], {99: {'content': 'abcdef'}}, 0)

    def test_duplicate_witnesses_do_not_inflate_or_cross_forks(self):
        statements = [self.statement(), self.statement('missing.sol', '123456', start=0, length=1)]
        spans = [{'pc': 0, 'start': 2, 'length': 1, 'file': 0}, {'pc': 1, 'start': 2, 'length': 1, 'file': 0}]
        a, _ = self.f('join_witnesses', statements, spans, {0: {'content': 'abcdef'}}, 'paris:control-A')
        b, _ = self.f('join_witnesses', statements, spans, {0: {'content': 'abcdef'}}, 'shanghai:control-A')
        self.assertEqual(set(a), {0})
        self.assertEqual(set(b), {0})
        self.assertNotEqual(a[0]['context'], b[0]['context'])
        self.assertEqual(len(statements), 2)

    def test_inert_summary_cannot_override_reconstructed_map(self):
        spans, kinds = self.f('mapped_spans', '00', '0:1:0', [0])
        found, _ = self.f('join_witnesses', [self.statement()], spans, {0: {'content': 'abcdef'}}, 0)
        self.assertFalse(found)  # A hypothetical summary claiming coverage is irrelevant.
        self.assertEqual(kinds['mapped'], 1)

class PilotDataTests(DataTests, unittest.TestCase):
    def test_creation_and_runtime_have_distinct_size_bounds(self):
        self.assertEqual(len(self.f('instruction_maps', '00' * 24577, '0:1:0', 'creation')), 24577)
        self.assertEqual(len(self.f('instruction_maps', '00' * 49152, '0:1:0', 'creation')), 49152)
        for kind, length in [('runtime',24577),('creation',49153)]:
            with self.assertRaises(ValueError):
                self.f('instruction_maps', '00' * length, '', kind)
        with self.assertRaises(ValueError):
            self.f('instruction_maps', '00', '', 'unknown')

    def test_creation_source_map_retains_exact_local_source_id(self):
        spans, _ = self.f('mapped_spans','600000','2:1:99;',[0,2],'creation')
        self.assertEqual(spans,[{'pc':0,'start':2,'length':1,'file':99},{'pc':2,'start':2,'length':1,'file':99}])
        self.assertEqual(self.f('bitmap_pcs',base64.b64encode(bytes([5])).decode(),'600000','creation'),[0,2])

    def test_bitmap_instruction_positions_and_empty_hits(self):
        self.assertEqual(self.f('bitmap_pcs','CQ==','61aabb00'),[0,3])
        self.assertEqual(self.f('bitmap_pcs','AA==','61aabb00'),[])
        with self.assertRaises(ValueError):
            self.f('bitmap_pcs','Ag==','61aabb00')

    def test_bitmap_encoding_and_width_are_strict(self):
        for value in [None,'?','AA','AA==\n','AB==','AAA=']:
            with self.assertRaises(ValueError):
                self.f('bitmap_pcs',value,'00')
        with self.assertRaises(ValueError):
            self.f('bitmap_pcs','AA==','00'*9)
        with self.assertRaises(ValueError):
            self.f('bitmap_pcs','A'*(4*((24576+23)//24)+1),'00')

    def test_bitmap_rejects_tail_bits_and_namespace_confusion(self):
        with self.assertRaises(ValueError):
            self.f('bitmap_pcs','gA==','00')
        with self.assertRaises(ValueError):
            self.f('bitmap_pcs','AA==','00','unknown')
        with self.assertRaises(ValueError):
            self.f('bitmap_pcs','AA==','')

    def test_bitmap_rows_do_not_supply_their_own_statement_verdict(self):
        pcs = self.f('bitmap_pcs','AQ==','00')
        spans, _ = self.f('mapped_spans','00','0:1:0',pcs)
        found, _ = self.f('join_witnesses',[self.statement()],spans,{0:{'content':'abcdef'}},'paris:creation')
        self.assertFalse(found)
