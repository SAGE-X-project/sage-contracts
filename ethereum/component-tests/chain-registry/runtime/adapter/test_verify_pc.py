"""Synthetic, fixed-data checker units; no product execution or actual evidence.

Draft only. These deliberately constructed receipt files are temporary inputs to
the checker, never Registry/compiler/CI evidence. Do not run alongside the active
capacity process. Integration and source review must precede execution.
"""
from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest


SOURCE = Path(__file__).resolve().with_name('verify-pc.py')
POLICY = {'max_input_bytes': 1024, 'max_expected_output_bytes': 1024,
          'max_steps': 2048, 'max_memory_bytes': 4096}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + '\n')


class SyntheticInputs:
    """Make independently named, isolated data; never reuse real receipts."""

    def __init__(self, directory):
        self.repo = Path(directory) / 'synthetic-repository'
        self.runtime = self.repo / 'ethereum/component-tests/chain-registry/runtime'
        self.adapter = self.runtime / 'adapter'
        self.adapter.mkdir(parents=True)
        self.checker = self.adapter / 'verify-pc.py'
        self.checker.write_bytes(SOURCE.read_bytes())
        self.sources = ['ethereum/contracts/chain-registry/' + name + '.sol'
                        for name in ['RegistryRules', 'RegistryRenderer'] +
                        ['SyntheticSource%02d' % index for index in range(2, 29)]]
        for index, name in enumerate(self.sources):
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('// Synthetic checker unit data, source %d.\n' % index)
        self.goldens = {'cases': [], 'skipped': [{'name': 'synthetic-skip-%d' % n}
                                              for n in range(0)]}
        for index in range(407):
            self.goldens['cases'].append({
                'name': 'synthetic-case-%03d' % index,
                'contract': 'RegistryRules' if index % 2 == 0 else 'RegistryRenderer',
                'method': 'syntheticReadOnly', 'exception': None,
                'expected_return_hex': '00' * 1025 if index == 2 else ''})
        self.rows = {}
        self.prefixes = {}
        self.results = {}
        self.compiled = {}
        self.baseline = {'targets': {}}
        for target in ['paris', 'shanghai']:
            sources = {}
            for index, name in enumerate(self.sources):
                nodes = [] if index == 1 else [{
                    'nodeType': 'ExpressionStatement', 'id': 1000 + index,
                    'src': '0:5:%d' % index}]
                if index == 0:
                    nodes.append({'nodeType': 'Return', 'id': 2000, 'src': '0:5:0'})
                sources[name] = {'id': index, 'ast': {
                    'nodeType': 'SourceUnit', 'nodes': nodes,
                    'ignored': {'nodeType': 'Identifier', 'name': 'synthetic'}}}
            sources['synthetic-generated.sol'] = {'id': 99, 'ast': {}}
            contracts = {}
            runtime_hashes = {}
            self.baseline['targets'][target] = {}
            for contract, role, code in [('RegistryRules', 'RULES', '600150005b'),
                                         ('RegistryRenderer', 'RENDERER', '600250005b')]:
                runtime_hashes[contract] = hashlib.sha256(bytes.fromhex(code)).hexdigest()
                self.baseline['targets'][target][role] = {
                    'runtime_sha256': runtime_hashes[contract]}
                contracts['ethereum/contracts/chain-registry/' + contract + '.sol'] = {
                    contract: {'evm': {'deployedBytecode': {
                        'object': code, 'sourceMap': '0:1:0;:0;;-1:-1:-1',
                        'immutableReferences': {}}}}}
            self.compiled[target] = {'sources': sources, 'contracts': contracts}
            rows = []
            traced, untraced = [], []
            for index, golden in enumerate(self.goldens['cases']):
                input_hex = '00' * 1025 if index == 1 else '00'
                eligible = index not in (1, 2)
                trace = {'eligible': eligible, 'steps': 1 if eligible else 0,
                         'max_memory_bytes': 0, 'stop': 'complete' if eligible else 'size'}
                if index == 3:
                    trace.update(max_memory_bytes=4097, stop='memory')
                if index == 4:
                    trace.update(steps=2048, max_memory_bytes=32, stop='steps')
                row = dict(golden, index=index, input_hex=input_hex,
                           input_sha256=hashlib.sha256(bytes.fromhex(input_hex)).hexdigest(),
                           runtime_sha256=runtime_hashes[golden['contract']],
                           expected_exception=golden['exception'],
                           return_hex=golden['expected_return_hex'],
                           execution_gas='1', gas_limit='250000000', logs=[], pc_trace=trace)
                rows.append(row)
                (traced if eligible else untraced).append({'index': index, 'name': row['name']})
            self.rows[target] = rows
            self.prefixes[target] = {
                'cases_completed': 407, 'policy': deepcopy(POLICY),
                'visited': {'RegistryRules': [0, 2, 3, 4], 'RegistryRenderer': [0, 2, 3, 4]},
                'traced': traced, 'untraced': untraced}
            self.results[target] = {
                'complete': True, 'cases': 407, 'pc_policy': deepcopy(POLICY),
                'skipped_data_cases': 0, 'PC_observations_recorded': True,
                'coverage_percent': None, 'runtime_sha256': runtime_hashes}
        self.seal()

    def seal(self):
        """Bind the synthetic fixture after an intentional semantic change."""
        save(self.adapter / 'goldens.json', self.goldens)
        save(self.runtime / 'fixtures/expected-modules.json', self.baseline)
        manifest = {
            'source_files_sha256': {name: digest(self.repo / name) for name in self.sources},
            'tool_files_sha256': {str(path.relative_to(self.repo)): digest(path)
                                  for path in [self.checker, self.adapter / 'goldens.json',
                                               self.runtime / 'fixtures/expected-modules.json']}}
        save(self.runtime / 'source-identities.json', manifest)
        compiler = self.runtime / 'evidence/compiler'
        for target in ['paris', 'shanghai']:
            save(compiler / (target + '-output.json'), self.compiled[target])
        check = {'verified': True,
                 'source_manifest_sha256': digest(self.runtime / 'source-identities.json'),
                 'evidence_files_sha256': {target + '-output.json':
                                          digest(compiler / (target + '-output.json'))
                                          for target in ['paris', 'shanghai']}}
        save(self.runtime / 'evidence/compiler-check.json', check)
        evidence = self.runtime / 'evidence/adapter'
        evidence.mkdir(exist_ok=True)
        for target in ['paris', 'shanghai']:
            rows_path = evidence / (target + '-rows.jsonl')
            rows_path.write_text(''.join(json.dumps(row, sort_keys=True) + '\n'
                                         for row in self.rows[target]))
            prefix_path = evidence / (target + '-pc-prefix.json')
            save(prefix_path, self.prefixes[target])
            self.results[target].update(
                source_manifest_sha256=digest(self.runtime / 'source-identities.json'),
                compiler_check_sha256=digest(self.runtime / 'evidence/compiler-check.json'),
                goldens_sha256=digest(self.adapter / 'goldens.json'),
                rows_sha256=digest(rows_path), pc_prefix_sha256=digest(prefix_path))
            save(evidence / (target + '-result.json'), self.results[target])

    def run(self):
        capture = io.StringIO()
        with redirect_stdout(capture):
            # Use the immutable canonical source name for trace aggregation.
            # __file__ still selects this isolated synthetic fixture and its
            # manifest; compiled bytes equal the canonical checker exactly.
            code = compile(self.checker.read_bytes(), str(SOURCE), 'exec')
            exec(code, {'__file__': str(self.checker), '__name__': '__main__'})
        return json.loads(capture.getvalue())


class CheckerDataTests(unittest.TestCase):
    completed_invalid_data = []
    def test_complete_synthetic_fixture_retains_full_denominator(self):
        with tempfile.TemporaryDirectory(prefix='sage-synthetic-pc-checker-') as directory:
            fixture = SyntheticInputs(directory)
            result = fixture.run()
            self.assertFalse(result['fixed5_complete'])
            self.assertFalse(result['operating_ready'])
            self.assertEqual(result['skipped_data_cases'], 0)
            for target in ['paris', 'shanghai']:
                observed = result['targets'][target]
                self.assertEqual(len(observed['sources']), 29)
                self.assertEqual(observed['total'], 29)
                self.assertEqual(observed['covered'], 2)
                self.assertFalse(observed['whole_registry_coverage_qualified'])
                for contract in ['RegistryRules', 'RegistryRenderer']:
                    self.assertEqual(observed['subjects'][contract]['visited_pcs'], [0, 2, 3, 4])

    def test_fixed_inconsistent_data_are_rejected(self):
        # These are local malformed receipt data only, not protocol messages,
        # forged signatures, executable payloads, or an attack/replay producer.
        self.__class__.completed_invalid_data = []
        mutations = {
            'missing_row': lambda f: f.rows['paris'].pop(),
            'unfinished_prefix': lambda f: f.prefixes['paris'].update(cases_completed=406),
            'unfinished_result': lambda f: f.results['paris'].update(complete=False),
            'wrong_case_count': lambda f: f.results['paris'].update(cases=406),
            'wrong_skip_count': lambda f: f.results['paris'].update(skipped_data_cases=1),
            'unexpected_claim': lambda f: f.results['paris'].update(coverage_percent=90),
            'missing_pc_flag': lambda f: f.results['paris'].update(PC_observations_recorded=False),
            'policy_changed': lambda f: f.prefixes['paris']['policy'].update(max_steps=2049),
            'result_policy_changed': lambda f: f.results['paris']['pc_policy'].update(max_steps=2049),
            'wrong_row_index': lambda f: f.rows['paris'][0].update(index=1),
            'wrong_case_name': lambda f: f.rows['paris'][0].update(name='other-synthetic-name'),
            'unexpected_exception': lambda f: f.rows['paris'][0].update(exception='synthetic-error'),
            'unexpected_return': lambda f: f.rows['paris'][0].update(return_hex='01'),
            'bad_input_digest': lambda f: f.rows['paris'][0].update(input_sha256='0' * 64),
            'gas_limit_changed': lambda f: f.rows['paris'][0].update(gas_limit='250000001'),
            'gas_exceeded': lambda f: f.rows['paris'][0].update(execution_gas='250000001'),
            'negative_gas': lambda f: f.rows['paris'][0].update(execution_gas='-1'),
            'unexpected_log': lambda f: f.rows['paris'][0].update(logs=[{'synthetic': True}]),
            'eligibility_changed': lambda f: f.rows['paris'][1]['pc_trace'].update(eligible=True),
            'eligibility_not_boolean': lambda f: f.rows['paris'][0]['pc_trace'].update(eligible=1),
            'steps_not_integer': lambda f: f.rows['paris'][0]['pc_trace'].update(steps=True),
            'negative_memory': lambda f: f.rows['paris'][0]['pc_trace'].update(max_memory_bytes=-1),
            'untraced_has_steps': lambda f: f.rows['paris'][1]['pc_trace'].update(steps=1),
            'zero_traced_steps': lambda f: f.rows['paris'][0]['pc_trace'].update(steps=0),
            'steps_budget_exceeded': lambda f: f.rows['paris'][0]['pc_trace'].update(steps=2049),
            'memory_stop_without_limit': lambda f: f.rows['paris'][3]['pc_trace'].update(max_memory_bytes=4096),
            'steps_stop_before_limit': lambda f: f.rows['paris'][4]['pc_trace'].update(steps=2047),
            'unknown_stop': lambda f: f.rows['paris'][0]['pc_trace'].update(stop='other'),
            'completed_at_step_limit': lambda f: f.rows['paris'][0]['pc_trace'].update(steps=2048),
            'traced_list_changed': lambda f: f.prefixes['paris']['traced'].pop(),
            'untraced_list_changed': lambda f: f.prefixes['paris']['untraced'].pop(),
            'runtime_digest_changed': lambda f: f.results['paris']['runtime_sha256'].update(RegistryRules='0' * 64),
            'row_runtime_digest_changed': lambda f: f.rows['paris'][0].update(runtime_sha256='0' * 64),
            'unsorted_pc_set': lambda f: f.prefixes['paris']['visited'].update(RegistryRules=[2, 0]),
            'duplicate_pc': lambda f: f.prefixes['paris']['visited'].update(RegistryRules=[0, 0]),
            'pc_inside_push_argument': lambda f: f.prefixes['paris']['visited'].update(RegistryRules=[1]),
            'negative_pc': lambda f: f.prefixes['paris']['visited'].update(RegistryRules=[-1]),
            'wrong_subject_set': lambda f: f.prefixes['paris']['visited'].update(OtherModule=[]),
            'too_many_map_entries': lambda f: f.compiled['paris']['contracts'][f.sources[0]]['RegistryRules']['evm']['deployedBytecode'].update(sourceMap=';'.join(['0:1:0'] * 6)),
            'invalid_source_position': lambda f: f.compiled['paris']['contracts'][f.sources[0]]['RegistryRules']['evm']['deployedBytecode'].update(sourceMap='-1:1:0'),
            'unexpected_immutables': lambda f: f.compiled['paris']['contracts'][f.sources[0]]['RegistryRules']['evm']['deployedBytecode'].update(immutableReferences={'1': []}),
            'statement_source_mismatch': lambda f: f.compiled['paris']['sources'][f.sources[0]]['ast']['nodes'][0].update(src='0:5:1'),
            'missing_source_denominator': lambda f: f.compiled['paris']['sources'].pop(f.sources[-1]),
        }
        for label, change in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory(prefix='sage-synthetic-pc-reject-') as directory:
                fixture = SyntheticInputs(directory)
                change(fixture)
                fixture.seal()
                with self.assertRaises(AssertionError):
                    fixture.run()
                self.__class__.completed_invalid_data.append(label)

    def test_changed_final_pc_file_digest_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='sage-synthetic-pc-digest-') as directory:
            fixture = SyntheticInputs(directory)
            # A harmless extra newline changes bytes without changing JSON.
            path = fixture.runtime / 'evidence/adapter/paris-pc-prefix.json'
            path.write_bytes(path.read_bytes() + b'\n')
            with self.assertRaises(AssertionError):
                fixture.run()

    def test_changed_manifest_bound_source_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='sage-synthetic-pc-source-') as directory:
            fixture = SyntheticInputs(directory)
            path = fixture.repo / fixture.sources[0]
            path.write_bytes(path.read_bytes() + b'// changed synthetic data\n')
            with self.assertRaises(AssertionError):
                fixture.run()


if __name__ == '__main__':
    unittest.main()
